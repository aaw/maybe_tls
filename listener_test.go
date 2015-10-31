package maybe_tls

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// We'll listen on this port during tests.
const testPort = 62913

func TestIsTLS_Raw(t *testing.T) {
	s := "hello, world!"
	b, _ := hex.DecodeString(s)
	if isTLS(b) {
		t.Errorf("Expected isTLS to reject message '%s'", s)
	}
}

func TestIsTLS_SSLv3(t *testing.T) {
	s := "160300007b010000770300e24aee8803681e7bc941adc1e55c280ceaea199ca" +
		"2b17ae542122d71f9108e5a000050c014c00a0039003800880087c00fc00500" +
		"350084c012c00800160013c00dc003000ac013c00900330032009a009900450" +
		"044c00ec004002f00960041c011c007c00cc0020005000400150012000900ff" +
		"0100"
	b, _ := hex.DecodeString(s)
	if !isTLS(b) {
		t.Errorf("Expected isTLS to accept SSLv3 hello '%s'", s)
	}
}

func TestIsTLS_TLS1_0(t *testing.T) {
	s := "16030100c6010000c20301f24865db32c9ffaa1c0614c08dabcdadca98a8a01" +
		"879173635f4b921a97d83f6000050c014c00a0039003800880087c00fc00500" +
		"350084c012c00800160013c00dc003000ac013c00900330032009a009900450" +
		"044c00ec004002f00960041c011c007c00cc0020005000400150012000900ff" +
		"01000049000b000403000102000a00340032000e000d0019000b000c0018000" +
		"9000a0016001700080006000700140015000400050012001300010002000300" +
		"0f0010001100230000000f000101"
	b, _ := hex.DecodeString(s)
	if !isTLS(b) {
		t.Errorf("Expected isTLS to accept TLS 1.0 hello '%s'", s)
	}
}

func TestIsTLS_TLS1_1(t *testing.T) {
	s := "16030100c6010000c20302e19a230e244ca397cbe6704c851a686e56f4917aa" +
		"a899f83945fed52d62f444e000050c014c00a0039003800880087c00fc00500" +
		"350084c012c00800160013c00dc003000ac013c00900330032009a009900450" +
		"044c00ec004002f00960041c011c007c00cc0020005000400150012000900ff" +
		"01000049000b000403000102000a00340032000e000d0019000b000c0018000" +
		"9000a0016001700080006000700140015000400050012001300010002000300" +
		"0f0010001100230000000f000101"
	b, _ := hex.DecodeString(s)
	if !isTLS(b) {
		t.Errorf("Expected isTLS to accept TLS 1.1 hello '%s'", s)
	}
}

func TestIsTLS_TLS1_2(t *testing.T) {
	s := "16030101220100011e03031a1c6ec6b51f6cf642276821107f335d9941f55f6" +
		"a5f7cbd52f082454c160619000088c030c02cc028c024c014c00a00a3009f00" +
		"6b006a0039003800880087c032c02ec02ac026c00fc005009d003d00350084c" +
		"012c00800160013c00dc003000ac02fc02bc027c023c013c00900a2009e0067" +
		"004000330032009a009900450044c031c02dc029c025c00ec004009c003c002" +
		"f00960041c011c007c00cc0020005000400150012000900ff0100006d000b00" +
		"0403000102000a00340032000e000d0019000b000c00180009000a001600170" +
		"00800060007001400150004000500120013000100020003000f001000110023" +
		"0000000d0020001e06010602060305010502050304010402040303010302030" +
		"3020102020203000f000101"
	b, _ := hex.DecodeString(s)
	if !isTLS(b) {
		t.Errorf("Expected isTLS to accept TLS 1.2 hello '%s'", s)
	}
}

// Generates a self-signed RSA keypair for 127.0.0.1 and returns both key and
// certificate as byte arrays.
func generateRSAKeyPair() (pemCert []byte, pemKey []byte) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Error generating RSA key: %s", err))
	}
	key := x509.MarshalPKCS1PrivateKey(priv)
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, _ := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"Example.com"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:        true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	var cert []byte
	cert, err = x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		panic(fmt.Sprintf("Failed to create certificate: %s", err))
	}
	pemKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: key})
	pemCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	return
}

type result struct {
	data []byte
	err  error
}

// Listen for a connection, read anything written once the client is connected
// and then close.
func ListenOnce(port int) (chan result, []byte) {
	cert, key := generateRSAKeyPair()
	keypair, kerr := tls.X509KeyPair(cert, key)
	if kerr != nil {
		panic(fmt.Sprintf("Failed to create X509KeyPair: %s", kerr))
	}
	config := tls.Config{Certificates: []tls.Certificate{keypair}}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		panic(fmt.Sprintf("Error opening connection: %s", err))
	}
	sln := Listener{ln, &config}
	c := make(chan result)
	go func() {
		conn, err := sln.Accept()
		defer func() { sln.Close() }()
		if err != nil {
			c <- result{nil, err}
			return
		}
		b := make([]byte, 1024)
		var cnt int
		var x []byte
		cnt, err = conn.Read(b)
		for err == nil {
			x = append(x, b[:cnt]...)
			cnt, err = conn.Read(b)
		}
		if err == io.EOF {
			c <- result{x, nil}
		} else {
			c <- result{nil, err}
		}
	}()
	return c, cert
}

func TestListenerTCP(t *testing.T) {
	bc, _ := ListenOnce(testPort)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", testPort))
	if err != nil {
		t.Errorf("Couldn't connect to server: %s", err)
	}
	want := []byte{1, 2, 3, 5, 8, 13, 21, 34}
	conn.Write(want)
	conn.Close()
	got := <-bc
	if got.err != nil {
		t.Errorf("Unexpected error from listener: %s", got.err)
	}
	if bytes.Compare(got.data, want) != 0 {
		t.Errorf("Got %s, want %s", got.data, want)
	}
}

func TestListenerTLS(t *testing.T) {
	bc, serverCert := ListenOnce(testPort)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(serverCert)
	config := tls.Config{RootCAs: pool}
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", testPort), &config)
	if err != nil {
		t.Errorf("Couldn't connect to server: %s", err)
	}
	want := []byte{1, 2, 3, 5, 8, 13, 21, 34}
	conn.Write(want)
	conn.Close()
	got := <-bc
	if got.err != nil {
		t.Errorf("Unexpected error from listener: %s", got.err)
	}
	if bytes.Compare(got.data, want) != 0 {
		t.Errorf("Got %s, want %s", got.data, want)
	}
}

func TestListenerReadTimeout(t *testing.T) {
	bc, _ := ListenOnce(testPort)
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", testPort))
	if err != nil {
		t.Errorf("Couldn't connect to server: %s", err)
	}
	conn.Close()
	got := <-bc
	if got.err == nil {
		t.Error("Expected error from listener but got success")
	}
}
