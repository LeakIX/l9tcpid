package l9tcpid

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/LeakIX/l9format"
	"github.com/RumbleDiscovery/jarm-go"
	"gitlab.nobody.run/tbi/socksme"
	"log"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

var tlsSessionCache = tls.NewLRUClientSessionCache(4096*1024)

func GetNetworkConnection(event *l9format.L9Event) (conn net.Conn, err error) {
	taskContext, _ := context.WithDeadline(context.Background(), time.Now().Add(20*time.Second))
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(event.Ip, event.Port), 3*time.Second)
	if tcpConn, isTcp := conn.(*net.TCPConn); isTcp {
		// Will considerably lower TIME_WAIT connections and required fds,
		// since we don't plan to reconnect to the same host:port combo and need TIME_WAIT's window anyway
		// Will lead to out of sequence events if used on the same target host/port and source port starts to collide.
		// TLDR : DO NOT USE ON AN HOST THAT'S NOT DEDICATED TO SCANNING
		_ = tcpConn.SetLinger(0)

	}
	return conn, err
	// If you want to use a socks proxy ... Making network.go its own library soon.
	//TODO : implement socks proxy support
	return socksme.NewDialer("tcp", fmt.Sprintf("127.0.0.1:2250")).
		DialContext(taskContext, "tcp", net.JoinHostPort(event.Ip, event.Port))
}

func GetBanner(event *l9format.L9Event) (err error) {
	// Open connection
	connection, err := GetNetworkConnection(event)
	if err != nil {
		return err
	}
	event.Transports = append(event.Transports, "tcp")
	err = connection.SetDeadline(time.Now().Add(10 * time.Second))
	if err != nil {
		return err
	}
	if event.SSL.Detected && !event.SSL.Enabled {
		err := UpgradeConnection(event.Protocol, connection)
		if err != nil {
			return nil
		}
		err = connection.SetDeadline(time.Now().Add(10 * time.Second))
		if err != nil {
			return nil
		}
	}
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ClientSessionCache: tlsSessionCache,
	}
	if event.Host != "" {
		tlsConfig.ServerName = event.Host
	}
	connection = tls.Client(connection, tlsConfig)
	err = connection.(*tls.Conn).Handshake()
	if err != nil {
		err = connection.Close()
		if err != nil {
			return err
		}
		if event.SSL.Detected {
			return nil
		}
		connection, err = GetNetworkConnection(event)
		if err != nil {
			return err
		}
	} else {
		event.Transports = append(event.Transports, "tls")
		event.SSL.Enabled = true
		FillSSLDetails(connection.(*tls.Conn).ConnectionState(), event)
	}
	err = FuzzConnection(connection, event)
	if err != nil {
		return err
	}
	if event.SSL.Detected && !event.SSL.Enabled {
		return GetBanner(event)
	}
	if event.SSL.Enabled {
		_ = GetJARM(event)
	}
	return nil
}

func SendLine(line string, conn net.Conn) (err error) {
	log.Println("Sending " + line)
	err = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte(line + "\r\n"))
	if err != nil {
		return err
	}
	return nil
}

func SendLineAndWait(line string, conn net.Conn) (err error) {
	log.Println("Sending " + line)
	err = conn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err != nil {
		return err
	}
	_, err = conn.Write([]byte(line + "\r\n"))
	if err != nil {
		return err
	}
	err = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	for {
		recvBuf := make([]byte, 4096)
		_, err := conn.Read(recvBuf[:])
		log.Println("line-resp: " + string(recvBuf))
		if err != nil {
			break
		}
	}
	return nil
}

func UpgradeConnection(protocol string, connection net.Conn) (err error) {
	switch protocol {
	case "smtp":
		err = SendLineAndWait("EHLO leakix.net", connection)
		if err != nil {
			return err
		}
		err = SendLineAndWait("STARTTLS", connection)
		if err != nil {
			return err
		}
	case "ftp":
		err = SendLineAndWait("AUTH TLS", connection)
		if err != nil {
			return err
		}
	}
	return nil
}

// takes a connection and populates hostService with findings
func FuzzConnection(connection net.Conn, event *l9format.L9Event) (err error) {
	err = connection.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		return err
	}
	defer connection.Close()
	var buffer []byte
	// read input until deadline or error
	for {
		recvBuf := make([]byte, 16)
		n, err := connection.Read(recvBuf[:])
		if err != nil {
			break
		}
		if n > 0 && len(buffer) < 512 {
			buffer = append(buffer, recvBuf...)
		}
	}
	err = connection.SetWriteDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		return err
	}
	_, err = connection.Write(
		[]byte("GET / HTTP/1.1\r\nHost: " + event.Host + "\r\n\r\nHELP\r\nEHLO leakix.net\r\n?\r\n\r\n"))
	if err == nil {
		err = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			return err
		}
		for {
			recvBuf := make([]byte, 16)
			n, err := connection.Read(recvBuf[:])
			if err != nil {
				break
			}
			if n > 0 && len(buffer) < 512 {
				buffer = append(buffer, recvBuf...)
			}
		}
	}

	if len(buffer) < 1 {
		// So far we have written without issue (aka NO RST came back)
		return errors.New("empty")
	}
	printables := strings.FieldsFunc(string(buffer), func(r rune) bool {
		if r == '\n' || r == '\r' {
			return true
		}
		return !unicode.IsPrint(r)
	})

	for _, result := range printables {
		event.Summary += strings.TrimSpace(result) + "\n"
	}
	for _, matchFunc := range TCPIdentifiers {
		if matchFunc(event, buffer, printables) {
			break
		}
	}
	// We couldn't identify, add connection dump
	if event.Protocol == "tcp" {
		event.Summary += "\nRaw connection:\n"
		event.Summary += hex.Dump(buffer)
	}
	return nil
}

func FillSSLDetails(state tls.ConnectionState, event *l9format.L9Event) {
	if len(state.PeerCertificates) > 0 {
		err := state.PeerCertificates[0].VerifyHostname(event.Host)
		if err == nil {
			event.SSL.Certificate.Valid = true
		} else {
			log.Println(err.Error())
		}
		event.SSL.Certificate.CommonName = state.PeerCertificates[0].Subject.CommonName
		for _, domain := range state.PeerCertificates[0].DNSNames {
			event.SSL.Certificate.Domains = append(event.SSL.Certificate.Domains, domain)
		}
		event.SSL.Certificate.Fingerprint = fmt.Sprintf("%02x", sha256.Sum256(state.PeerCertificates[0].Raw))
		event.SSL.CypherSuite = tls.CipherSuiteName(state.CipherSuite)
		event.SSL.Version = GetTLSVersionName(state.Version)
		event.SSL.Certificate.KeyAlgo = state.PeerCertificates[0].PublicKeyAlgorithm.String()
		if publicKey, isECDSA := state.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey); isECDSA {
			event.SSL.Certificate.KeySize = publicKey.Params().BitSize
		} else if publicKey, isRSA := state.PeerCertificates[0].PublicKey.(*rsa.PublicKey); isRSA {
			event.SSL.Certificate.KeySize = publicKey.Size() * 8
		}
		event.SSL.Certificate.NotBefore = state.PeerCertificates[0].NotBefore
		event.SSL.Certificate.NotAfter = state.PeerCertificates[0].NotAfter
		event.SSL.Certificate.IssuerName = state.PeerCertificates[0].Issuer.CommonName
	}
}

var tlsVersionMap = map[uint16]string{
	0x0301: "TLSv1.0",
	0x0302: "TLSv1.1",
	0x0303: "TLSv1.2",
	0x0304: "TLSv1.3",
	0x0300: "SSLv3",
}

func GetJARM(event *l9format.L9Event) (err error) {
	results := []string{}
	port, _ := strconv.Atoi(event.Port)
	for _, probe := range jarm.GetProbes(event.Ip, port) {
		c, err := GetNetworkConnection(event)
		if err != nil {
			return err
		}
		err = UpgradeConnection(event.Protocol, c)
		if err != nil {
			return err
		}
		data := jarm.BuildProbe(probe)
		c.SetWriteDeadline(time.Now().Add(time.Second * 3))
		_, err = c.Write(data)
		if err != nil {
			results = append(results, "")
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 3))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		ans, err := jarm.ParseServerHello(buff, probe)
		if err != nil {
			results = append(results, "")
		}

		results = append(results, ans)
	}
	event.SSL.JARM = jarm.RawHashToFuzzyHash(strings.Join(results, ","))
	return nil
}

func GetTLSVersionName(version uint16) string {
	if name, found := tlsVersionMap[version]; found {
		return name
	}
	return ""
}
