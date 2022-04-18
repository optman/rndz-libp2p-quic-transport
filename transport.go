package quic

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"

	"golang.org/x/crypto/hkdf"

	"github.com/libp2p/go-libp2p-core/connmgr"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/libp2p/go-libp2p-core/network"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/pnet"
	tpt "github.com/libp2p/go-libp2p-core/transport"
	"github.com/optman/rndz-go/client/udp"
	ra "github.com/optman/rndz-multiaddr"

	p2ptls "github.com/libp2p/go-libp2p-tls"

	ma "github.com/multiformats/go-multiaddr"
	mafmt "github.com/multiformats/go-multiaddr-fmt"
	manet "github.com/multiformats/go-multiaddr/net"

	logging "github.com/ipfs/go-log/v2"
	"github.com/lucas-clemente/quic-go"
	"github.com/minio/sha256-simd"
)

var log = logging.Logger("rndz-quic-tpt")

var quicDialContext = quic.DialContext // so we can mock it in tests

var quicConfig = &quic.Config{
	MaxIncomingStreams:         256,
	MaxIncomingUniStreams:      -1,             // disable unidirectional streams
	MaxStreamReceiveWindow:     10 * (1 << 20), // 10 MB
	MaxConnectionReceiveWindow: 15 * (1 << 20), // 15 MB
	AcceptToken: func(clientAddr net.Addr, _ *quic.Token) bool {
		// TODO(#6): require source address validation when under load
		return true
	},
	KeepAlive: true,
	Versions:  []quic.VersionNumber{quic.VersionDraft29, quic.Version1},
}

var InvalidListenAddr = errors.New("invalid listen addr")

const statelessResetKeyInfo = "libp2p quic stateless reset key"
const errorCodeConnectionGating = 0x47415445 // GATE in ASCII

// The Transport implements the tpt.Transport interface for QUIC connections.
type transport struct {
	privKey      ic.PrivKey
	localPeer    peer.ID
	identity     *p2ptls.Identity
	serverConfig *quic.Config
	clientConfig *quic.Config
	gater        connmgr.ConnectionGater
	rcmgr        network.ResourceManager

	connMx sync.Mutex
	conns  map[quic.Connection]*conn
}

var _ tpt.Transport = &transport{}

// NewTransport creates a new QUIC transport
func NewTransport(key ic.PrivKey, psk pnet.PSK, gater connmgr.ConnectionGater, rcmgr network.ResourceManager) (tpt.Transport, error) {
	if len(psk) > 0 {
		log.Error("QUIC doesn't support private networks yet.")
		return nil, errors.New("QUIC doesn't support private networks yet")
	}
	localPeer, err := peer.IDFromPrivateKey(key)
	if err != nil {
		return nil, err
	}
	identity, err := p2ptls.NewIdentity(key)
	if err != nil {
		return nil, err
	}
	if rcmgr == nil {
		rcmgr = network.NullResourceManager
	}
	config := quicConfig.Clone()
	keyBytes, err := key.Raw()
	if err != nil {
		return nil, err
	}
	keyReader := hkdf.New(sha256.New, keyBytes, nil, []byte(statelessResetKeyInfo))
	config.StatelessResetKey = make([]byte, 32)
	if _, err := io.ReadFull(keyReader, config.StatelessResetKey); err != nil {
		return nil, err
	}

	tr := &transport{
		privKey:   key,
		localPeer: localPeer,
		identity:  identity,
		gater:     gater,
		rcmgr:     rcmgr,
		conns:     make(map[quic.Connection]*conn),
	}
	config.AllowConnectionWindowIncrease = tr.allowWindowIncrease
	tr.serverConfig = config
	tr.clientConfig = config.Clone()

	return tr, nil
}

// Dial dials a new QUIC connection
func (t *transport) Dial(ctx context.Context, raddr ma.Multiaddr, p peer.ID) (tpt.CapableConn, error) {

	log.Debugf("Dial %s %s", raddr, p)

	scope, err := t.rcmgr.OpenConnection(network.DirOutbound, false)
	if err != nil {
		log.Debugw("resource manager blocked outgoing connection", "peer", p, "addr", raddr, "error", err)
		return nil, err
	}
	if err := scope.SetPeer(p); err != nil {
		log.Debugw("resource manager blocked outgoing connection for peer", "peer", p, "addr", raddr, "error", err)
		scope.Done()
		return nil, err
	}

	rndzServerAddr, err := manet.ToNetAddr(raddr)
	if err != nil {
		return nil, err
	}
	rndz := udp.New(rndzServerAddr.String(), t.localPeer.String(), netip.AddrPort{})
	defer rndz.Close()

	tempConn, err := rndz.Connect(ctx, p.String())
	if err != nil {
		return nil, err
	}

	localAddr := tempConn.LocalAddr()
	remoteAddr := tempConn.RemoteAddr()
	remoteHost := remoteAddr.(*net.UDPAddr).IP.String()

	tempConn.Close()

	//quic-go not support connected udp
	pconn, err := udp.Bind(localAddr.String())
	if err != nil {
		return nil, err
	}

	tlsConf, keyCh := t.identity.ConfigForPeer(p)

	qconn, err := quicDialContext(ctx, pconn, remoteAddr, remoteHost, tlsConf, t.clientConfig)
	if err != nil {
		scope.Done()
		return nil, err
	}
	// Should be ready by this point, don't block.
	var remotePubKey ic.PubKey
	select {
	case remotePubKey = <-keyCh:
	default:
	}
	if remotePubKey == nil {
		scope.Done()
		return nil, errors.New("rndz-libp2p-quic-transport BUG: expected remote pub key to be set")
	}

	localMultiaddr, err := toQuicMultiaddr(pconn.LocalAddr())
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, err
	}

	remoteMultiaddr, err := toQuicMultiaddr(remoteAddr)
	if err != nil {
		qconn.CloseWithError(0, "")
		return nil, err
	}

	c := &conn{
		quicConn:        qconn,
		transport:       t,
		scope:           scope,
		privKey:         t.privKey,
		localPeer:       t.localPeer,
		localMultiaddr:  localMultiaddr,
		remotePubKey:    remotePubKey,
		remotePeerID:    p,
		remoteMultiaddr: remoteMultiaddr,
	}
	if t.gater != nil && !t.gater.InterceptSecured(network.DirOutbound, p, c) {
		qconn.CloseWithError(errorCodeConnectionGating, "connection gated")
		return nil, fmt.Errorf("secured connection gated")
	}
	t.addConn(qconn, c)
	return c, nil
}

func (t *transport) addConn(conn quic.Connection, c *conn) {
	t.connMx.Lock()
	t.conns[conn] = c
	t.connMx.Unlock()
}

func (t *transport) removeConn(conn quic.Connection) {
	t.connMx.Lock()
	delete(t.conns, conn)
	t.connMx.Unlock()
}

var dialMatcher = mafmt.UDP

// CanDial determines if we can dial to an address
func (t *transport) CanDial(addr ma.Multiaddr) bool {
	return dialMatcher.Matches(addr)
}

// Listen listens for new QUIC connections on the passed multiaddr.
func (t *transport) Listen(addr ma.Multiaddr) (tpt.Listener, error) {

	log.Debugf("Listen %s", addr)

	localAddr, rndzAddr := ra.SplitListenAddr(addr)
	if rndzAddr == nil {
		return nil, InvalidListenAddr
	}

	laddr, err := manet.ToNetAddr(localAddr)
	if err != nil {
		return nil, InvalidListenAddr
	}

	raddr, err := manet.ToNetAddr(rndzAddr)
	if err != nil {
		return nil, InvalidListenAddr
	}

	rndz := udp.New(raddr.String(), t.localPeer.String(), netip.MustParseAddrPort(laddr.String()))
	conn, err := rndz.Listen(context.Background())
	if err != nil {
		rndz.Close()
		return nil, err
	}
	ln, err := newListener(conn, t, t.localPeer, t.privKey, t.identity, t.rcmgr)
	if err != nil {
		rndz.Close()
		return nil, err
	}
	return ln, nil
}

func (t *transport) allowWindowIncrease(conn quic.Connection, size uint64) bool {
	// If the QUIC connection tries to increase the window before we've inserted it
	// into our connections map (which we do right after dialing / accepting it),
	// we have no way to account for that memory. This should be very rare.
	// Block this attempt. The connection can request more memory later.
	t.connMx.Lock()
	c, ok := t.conns[conn]
	t.connMx.Unlock()
	if !ok {
		return false
	}
	return c.allowWindowIncrease(size)
}

// Proxy returns true if this transport proxies.
func (t *transport) Proxy() bool {
	return false
}

// Protocols returns the set of protocols handled by this transport.
func (t *transport) Protocols() []int {
	return []int{ma.P_UDP}
}

func (t *transport) String() string {
	return "RNDZ-QUIC"
}

func (t *transport) Close() error {
	return nil
}
