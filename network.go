package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"gitlab.nobody.run/tbi/core"
	"gitlab.nobody.run/tbi/socksme"
	"log"
	"net"
	"strings"
	"time"
	"unicode"
)

func GetNetworkConnection(hostService *core.HostService) (conn net.Conn, err error) {
	taskContext, _ := context.WithDeadline(context.Background(), time.Now().Add(20*time.Second))
	conn, err = net.DialTimeout("tcp", net.JoinHostPort(hostService.Ip, hostService.Port), 3*time.Second)
	if tcpConn, isTcp := conn.(*net.TCPConn); isTcp {
		// Will considerably lower TIME_WAIT connections and required fds,
		// since we don't plan to reconnect to the same host:port combo and need TIME_WAIT's window anyway
		// Will lead to out of sequence events if used on the same target host/port and source port starts to collide.
		_ = tcpConn.SetLinger(0)

	}
	return conn, err
	// If you want to use a socks proxy ... Making network.go its own library soon.
	return socksme.NewDialer("tcp", fmt.Sprintf("127.0.0.1:2250")).
		DialContext(taskContext,  "tcp", net.JoinHostPort(hostService.Ip, hostService.Port))

}

// takes a connection and populates hostService with findings
func FuzzConnection(connection net.Conn, hostService *core.HostService) (err error) {
	// - wait 1 second and read data
	// - write fuzzing bytes
	//   - if ok read back for 3 sec
	// - if no input bytes yet, start sending fake SSL bytes,
	//   - if ok read back for 3 sec
	// - if still empty giveup
	// - detect protocol from bytes
	err = connection.SetReadDeadline(time.Now().Add(1*time.Second))
	if err != nil {
		return  err	}
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
	err = connection.SetWriteDeadline(time.Now().Add(3*time.Second))
	if err != nil {
		return  err
	}
	_, err = connection.Write(
		[]byte("GET / HTTP/1.1\r\nHost: " + hostService.Hostname + "\r\n\r\nHELP\r\nEHLO leakix.net\r\n?\r\n\r\n"))
	if err == nil {
		err = connection.SetReadDeadline(time.Now().Add(3*time.Second))
		if err != nil {
			return  err
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

	// Try an SSL payload
	if len(buffer) < 1 || hostService.Scheme != "ssl" {
		err = connection.SetWriteDeadline(time.Now().Add(3*time.Second))
		if err != nil {
			return err
		}
		_, err = connection.Write([]byte{0x16, 0x03, 0x01, 0xa5, 0x01, 0x00,0x00, 0xa1, 0x00, 0x00})
		if err == nil {
			err = connection.SetReadDeadline(time.Now().Add(3*time.Second))
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
	}
	if len(buffer) < 1 {
		return errors.New("empty")
	}
	printables := strings.FieldsFunc(string(buffer), func(r rune) bool {
		if r == '\n' || r == '\r' {
			return true
		}
		return !unicode.IsPrint(r)
	})
	if hostService.Scheme == "ssl" {
		hostService.Data = "SSL Connection:\n"
	}
	for _, result := range printables {
		hostService.Data += strings.TrimSpace(result) + "\n"
	}
	for _, matchFunc := range Matches {
		if matchFunc(hostService, buffer, printables) {
			return nil
		}
	}
	hostService.Data += "\nRaw connection:\n"
	hostService.Data += hex.Dump(buffer)
	return nil
}

func GetBanner(hostService *core.HostService) (err error) {
	// - connect
	// - Fuzz connection
	// - if SSL detected
	//   - upgrade connection
	//   - Fuzz connection
	//   - Fill certificate info
	hostService.Type = "tcp"
	// Open connection
	connection, err := GetNetworkConnection(hostService)
	if err != nil {
		return err
	}
	err = FuzzConnection(connection, hostService)
	if err != nil && err.Error() != "empty" {
		return err
	}
	// Found SSL, try if empty
	if hostService.Scheme == "ssl" || (hostService.Type == "tcp" && err != nil && err.Error() == "empty") {
		// reconnect
		log.Printf("Upgrading %s:%s", hostService.Ip, hostService.Port)
		newConnection, err := GetNetworkConnection(hostService)
		if err != nil {
			return errors.New("couldn't upgrade SSL connection")
		}
		defer newConnection.Close()
		if hostService.Type == "ftp" || hostService.Type == "smtp" {
			err = newConnection.SetReadDeadline(time.Now().Add(2*time.Second))
			for {
				recvBuf := make([]byte, 1024)
				_, err := newConnection.Read(recvBuf[:])
				log.Println("SSL-recv1: "+ string(recvBuf))
				if err != nil {
					break
				}
			}
			if hostService.Type == "smtp" {
				log.Println("Sending EHLO")
				err = newConnection.SetWriteDeadline(time.Now().Add(1*time.Second))
				if err != nil {
					return err
				}
				_, err = newConnection.Write([]byte("EHLO leakix.net\r\n"))
				if err != nil {
					return err
				}
			}
			err = newConnection.SetReadDeadline(time.Now().Add(2*time.Second))
			for {
				recvBuf := make([]byte, 1024)
				_, err := newConnection.Read(recvBuf[:])
				log.Println("SSL-recv2: "+ string(recvBuf))
				if err != nil {
					break
				}
			}
			err = newConnection.SetWriteDeadline(time.Now().Add(1*time.Second))
			log.Println("Sending STARTTLS")
			if hostService.Type == "smtp" {
				_, err = newConnection.Write([]byte("STARTTLS\r\n"))
				if err != nil {
					return err
				}
			} else if hostService.Type == "ftp" {
				_, err = newConnection.Write([]byte("AUTH TLS\r\n"))
				if err != nil {
					return err
				}
			}
			err = newConnection.SetReadDeadline(time.Now().Add(2*time.Second))
			for {
				recvBuf := make([]byte, 1024)
				_, err := newConnection.Read(recvBuf[:])
				log.Println("SSL-recv3: "+ string(recvBuf))
				if err != nil {
					break
				}
			}
		}
		newConnection.SetDeadline(time.Now().Add(5*time.Second))
		tlsConnection := tls.Client(newConnection, &tls.Config{
			InsecureSkipVerify: true,
		})
		err = tlsConnection.Handshake()
		if err != nil {
			return err
		}
		hostService.Scheme = "ssl"
		err = FuzzConnection(tlsConnection, hostService)
		if err != nil {
			return err
		}
		if len(tlsConnection.ConnectionState().PeerCertificates) > 0 {
			err := tlsConnection.ConnectionState().PeerCertificates[0].VerifyHostname(hostService.Hostname)
			if err == nil {
				hostService.Certificate.Valid = true
			} else {
				log.Println(err.Error())
			}
			hostService.Certificate.CommonName = tlsConnection.ConnectionState().PeerCertificates[0].Subject.CommonName
			for _, domain := range tlsConnection.ConnectionState().PeerCertificates[0].DNSNames {
				hostService.Certificate.Domains = append(hostService.Certificate.Domains, domain)
			}
			hostService.Certificate.Fingerprint = fmt.Sprintf("%02x", sha256.Sum256( tlsConnection.ConnectionState().PeerCertificates[0].Raw))
			hostService.Certificate.CypherSuite = tls.CipherSuiteName(tlsConnection.ConnectionState().CipherSuite)
			//hostService.Certificate.Version = plugin.GetTLSVersionName(tlsConnection.ConnectionState().Version)
			hostService.Certificate.KeyAlgo = tlsConnection.ConnectionState().PeerCertificates[0].PublicKeyAlgorithm.String()
			if publicKey, isECDSA :=  tlsConnection.ConnectionState().PeerCertificates[0].PublicKey.(*ecdsa.PublicKey); isECDSA {
				hostService.Certificate.KeySize = publicKey.Params().BitSize
			} else if publicKey, isRSA :=  tlsConnection.ConnectionState().PeerCertificates[0].PublicKey.(*rsa.PublicKey); isRSA {
				hostService.Certificate.KeySize = publicKey.Size()*8
			}
			hostService.Certificate.NotBefore = tlsConnection.ConnectionState().PeerCertificates[0].NotBefore
			hostService.Certificate.NotAfter = tlsConnection.ConnectionState().PeerCertificates[0].NotAfter
			hostService.Certificate.IssuerName = tlsConnection.ConnectionState().PeerCertificates[0].Issuer.CommonName
		}
	}
	return nil
}
