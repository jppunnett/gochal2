package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"golang.org/x/crypto/nacl/box"
)

const (
	noncesz = 24
	keysz   = 32
)

// secureReader implements the io.Reader interface to read and decrypt messages.
type secureReader struct {
	r   io.Reader
	key *[keysz]byte
}

// Read reads encrypted bytes from the Reader, decrypts the bytes and copies
// decrypted bytes to p.
func (sr *secureReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	//	The first noncesz bytes should be the nonce
	var nonce [noncesz]byte
	n, err := io.ReadFull(sr.r, nonce[:])
	if err != nil {
		return n, err
	}
	if n != noncesz {
		return n, fmt.Errorf("secureReader.Read: Unexpected nonce length: %d", n)
	}

	// Buffer has to be at least len(p) + encryption overhead.
	encrptd := make([]byte, len(p)+box.Overhead)
	n, err = sr.r.Read(encrptd)
	if err != nil {
		return n, err
	}
	// TODO: Must handle scenario where n < len(encrptd)

	decrypted, ok := box.OpenAfterPrecomputation(nil, encrptd[:n], &nonce, sr.key)
	if !ok {
		return n, fmt.Errorf("secureReader.Read: Error decrypting data")
	}

	return copy(p, decrypted), nil
}

// NewSecureReader instantiates a new SecureReader
func NewSecureReader(r io.Reader, priv, pub *[keysz]byte) io.Reader {
	sr := &secureReader{r: r, key: &[keysz]byte{}}
	box.Precompute(sr.key, pub, priv)
	return sr
}

// secureWriter implements the io.Writer interface to write encrypted messages.
type secureWriter struct {
	w   io.Writer
	key *[keysz]byte
}

// Write encrypts the bytes in p then copies the encrytped bytes to the Writer.
func (sw *secureWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	
	// Generate the nonce
	var nonce [noncesz]byte
	n, err := rand.Read(nonce[:])
	if err != nil {
		return 0, fmt.Errorf("secureWriter.Write: %v", err)
	}
	if n != noncesz {
		return 0, fmt.Errorf("secureWriter.Write: only generated %d bytes for nouce", n)
	}

	//	Write the nonce. This is in the clear.
	n, err = sw.w.Write(nonce[:])
	if err != nil {
		return n, fmt.Errorf("secureWriter.Write: %v", err)
	}
	if n != noncesz {
		return 0, fmt.Errorf("secureWriter.Write: only wrote %d bytes for nouce", n)
	}

	encrptd := box.SealAfterPrecomputation(nil, p, &nonce, sw.key)
	n, err = sw.w.Write(encrptd)
	if n > box.Overhead {
		n -= box.Overhead
	}
	return n, err
}

// NewSecureWriter instantiates a new SecureWriter
func NewSecureWriter(w io.Writer, priv, pub *[keysz]byte) io.Writer {
	sw := &secureWriter{w: w, key: &[keysz]byte{}}
	box.Precompute(sw.key, pub, priv)
	return sw
}

// secureReadWriter implements the io.ReadWriteCloser interface to read and
// write secure messages.
type secureReadWriter struct {
	rwc io.ReadWriteCloser
	sw  io.Writer
	sr  io.Reader
}

// NewSecureReadWriter instantiates a new secureReadWriter
func NewSecureReadWriter(rwc io.ReadWriteCloser, priv, pub *[keysz]byte) io.ReadWriteCloser {
	return &secureReadWriter{
		rwc,
		NewSecureWriter(rwc, priv, pub),
		NewSecureReader(rwc, priv, pub),
	}
}

func (srw *secureReadWriter) Read(p []byte) (int, error) {
	return srw.sr.Read(p)
}

func (srw *secureReadWriter) Write(p []byte) (int, error) {
	return srw.sw.Write(p)
}

func (srw *secureReadWriter) Close() error {
	return srw.rwc.Close()
}

// Dial generates a private/public key pair, connects to the server, performs
// the handshake and return a reader/writer.
func Dial(addr string) (io.ReadWriteCloser, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer func(c net.Conn, e error) {
		if e != nil {
			fmt.Printf("Dial: Closing connection because: %v", err)
			c.Close()
		}
	}(conn, err)

	// Receive public key from server. The client uses the server's public key
	//	and its private key to encrypt/decrypt messages.
	var srvpub [keysz]byte
	n, err := conn.Read(srvpub[:])
	if err != nil {
		return nil, err
	}
	if n != keysz {
		return nil, fmt.Errorf("Dial: could only read <%d> bytes of server's public key.", n)
	}

	// Generate client's key-pair for public key exchange (handshake)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	// Send client's public key to server. The server uses the client's public key, along
	//	with the server's private key to encrypt/decrypt messages.
	n, err = conn.Write(pub[:])
	if err != nil {
		return nil, err
	}
	if n != keysz {
		return nil, fmt.Errorf("Dial: could only write <%d> bytes of client's public key.", n)
	}

	return NewSecureReadWriter(conn, priv, &srvpub), nil
}

// Serve starts a secure echo server on the given listener.
func Serve(l net.Listener) error {
	// Generate key-pair for public key exchange (handshake)
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	// Wait for and handle incoming connections.
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go handleConnection(conn, priv, pub)
	}
}

func handleConnection(conn net.Conn, pri, pub *[keysz]byte) {
	//	Send public key to client. The client will use the server's public key
	//	along with its own private key to encrypt/decrypt messages.

	// TODO Clean up. Don't like all the repetative error handling code for key
	// exchange.
	n, err := conn.Write(pub[:])
	if err != nil {
		conn.Close()
		fmt.Printf("handleConnection: %v\n", err)
		return
	}
	if n != keysz {
		conn.Close()
		fmt.Printf("handleConnection: could only write <%d> bytes of server's public key.\n", n)
		return
	}

	// First keysz bytes read should be the public key of the connecting client
	var clipub [keysz]byte
	n, err = conn.Read(clipub[:])
	if err != nil {
		conn.Close()
		fmt.Printf("handleConnection.io.conn.Read: %v\n", err)
		return
	}
	if n != keysz {
		conn.Close()
		fmt.Printf("handleConnection: could only read <%d> bytes of client's public key.\n", n)
		return
	}

	// Key exchange complete
	swr := NewSecureReadWriter(conn, pri, &clipub)
	defer swr.Close()

	//	Read message from client, echo it back to them, and exit.
	buf := make([]byte, 2048)
	n, err = swr.Read(buf)
	if err != nil && err != io.EOF {
		fmt.Printf("handleConnection.swr.Read: %v\n", err)
		return
	}

	// Echo
	n, err = swr.Write(buf[:n])
	if err != nil {
		fmt.Printf("handleConnection.swr.Write: %v\n", err)
		return
	}

	// TODO Extend to echo until client wants to stop or connection times out.
}

func main() {
	port := flag.Int("l", 0, "Listen mode. Specify port")
	flag.Parse()

	// Server mode
	if *port != 0 {
		l, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
		if err != nil {
			log.Fatal(err)
		}
		defer l.Close()
		log.Fatal(Serve(l))
	}

	// Client mode
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <port> <message>", os.Args[0])
	}
	conn, err := Dial("localhost:" + os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	if _, err := conn.Write([]byte(os.Args[2])); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, len(os.Args[2]))
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Fatal(err)
	}
	fmt.Printf("%s\n", buf[:n])
}
