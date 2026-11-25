package integration

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"socketproxy/internal/cipher"
	"socketproxy/internal/client"
	"socketproxy/internal/config"
	"socketproxy/internal/crypto"
	"socketproxy/internal/protocol"
	"socketproxy/internal/server"
	"socketproxy/internal/socks5"
)

func startUDPEcho(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn
}

func TestSocks5UDPAssociate(t *testing.T) {
	echo := startUDPEcho(t)
	defer echo.Close()
	echoAddr := echo.LocalAddr().(*net.UDPAddr)

	method, err := cipher.FromName(cipher.MethodAES128GCM)
	if err != nil {
		t.Fatal(err)
	}
	key := crypto.EVPBytesToKey("udp-e2e", method.KeySize())

	ssUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ssSrv := server.New("127.0.0.1:0", method, key, 5*time.Second)
	go ssSrv.ServeUDP(ssUDP)
	defer ssUDP.Close()

	dialer, err := client.New(config.Node{
		Name:     "udp",
		Server:   "127.0.0.1",
		Port:     ssUDP.LocalAddr().(*net.UDPAddr).Port,
		Password: "udp-e2e",
		Method:   cipher.MethodAES128GCM,
		UDP:      true,
		Timeout:  5,
	})
	if err != nil {
		t.Fatal(err)
	}

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	socksSrv := socks5.New(socksLn.Addr().String(), dialer.Dial)
	socksSrv.DialUDP = dialer.DialUDP
	go socksSrv.Serve(socksLn)
	defer socksLn.Close()

	ctrl, err := net.Dial("tcp", socksLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := ctrl.Write([]byte{socks5.Version, 1, 0x00}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ctrl, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}

	req := []byte{socks5.Version, socks5.CmdUDPAssociate, 0x00, protocol.AddrTypeIPv4, 0, 0, 0, 0, 0, 0}
	if _, err := ctrl.Write(req); err != nil {
		t.Fatal(err)
	}
	var head [3]byte
	if _, err := io.ReadFull(ctrl, head[:]); err != nil {
		t.Fatal(err)
	}
	if head[1] != socks5.RepSuccess {
		t.Fatalf("udp associate failed, rep=0x%02x", head[1])
	}
	bndHost, bndPort, err := protocol.ReadAddress(ctrl)
	if err != nil {
		t.Fatal(err)
	}
	bnd := net.JoinHostPort(bndHost, strconv.Itoa(bndPort))

	udpConn, err := net.Dial("udp", bnd)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConn.Close()
	udpConn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := []byte("udp-associate-ping")
	dstAddr, err := protocol.EncodeAddress("127.0.0.1", echoAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	packet := append([]byte{0, 0, 0}, dstAddr...)
	packet = append(packet, payload...)
	if _, err := udpConn.Write(packet); err != nil {
		t.Fatal(err)
	}

	resp := make([]byte, 2048)
	n, err := udpConn.Read(resp)
	if err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("short response (%d bytes)", n)
	}
	body := resp[3:n]
	br := bytes.NewReader(body)
	srcHost, srcPort, err := protocol.ReadAddress(br)
	if err != nil {
		t.Fatal(err)
	}
	gotPayload := body[len(body)-br.Len():]

	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch: got %q", gotPayload)
	}
	if srcHost != "127.0.0.1" || srcPort != echoAddr.Port {
		t.Fatalf("source = %s:%d, want 127.0.0.1:%d", srcHost, srcPort, echoAddr.Port)
	}
}
