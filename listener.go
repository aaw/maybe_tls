package maybe_tls

import (
	"crypto/tls"
	"net"
)

func isTLS(b []byte) bool {
	return len(b) >= 6 && b[0] == '\x16' && b[1] == '\x03' && (b[2] == '\x00' || b[2] == '\x01') && b[5] == '\x01'
}

type Listener struct {
	listener net.Listener
	config   *tls.Config
}

// Accept waits for and returns the next connection to the listener.
func (s *Listener) Accept() (c net.Conn, err error) {
	c, err = s.listener.Accept()
	if err != nil {
		return
	}
	b := make([]byte, 6)
	var n int
	n, err = c.Read(b)
	c = Conn{c, &StreamReplay{b[:n], err}}
	if err == nil && isTLS(b[:n]) {
		c = tls.Server(c, s.config)
	}
	return
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
func (s *Listener) Close() error {
	return s.listener.Close()
}

// Addr returns the listener's network address.
func (s *Listener) Addr() net.Addr {
	return s.listener.Addr()
}
