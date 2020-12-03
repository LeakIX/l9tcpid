package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"github.com/RumbleDiscovery/jarm-go"
	"gitlab.nobody.run/tbi/core"
	"gitlab.nobody.run/tbi/bannerid"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var ValidHeaders = []string{
	"Server",
	"Set-Cookie",
	"X-Powered-By",
	"X-Mod-Pagespeed",
	"X-Aspnet-Version",
	"Www-Authenticate",
	"Via",
	"Upgrade",
	"Status",
	"Pragma",
	"Location",
	"Keep-Alive",
	"Expires",
	"Content-Type",
	"Date",
	"Content-Length",
	"Content-Language",
	"Cache-Control",
	"Access-Control-Allow-Origin",
	"Access-Control-Expose-Headers",
	"Access-Control-Max-Age",
	"Access-Control-Allow-Credentials",
	"Accept-Ranges",
	"Strict-Transport-Security",
	"X-Debug-Token",
	"Link",
	"X-Debug",
	"Debug",
	"Kbn-Version",
	"Kbn-Name",
	"X-Couch-Request-Id",
}
var tlsVersionMap = map[uint16]string{
	0x0301 : "TLSv1.0",
	0x0302 : "TLSv1.1",
	0x0303 : "TLSv1.2",
	0x0304 : "TLSv1.3",
	0x0300 : "SSLv3",
}
var plugin = core.ProxiedPlugin{}

func GetTLSVersionName(version uint16) string {
	if name, found := tlsVersionMap[version]; found {
		return name
	}
	return ""
}
// Get info
func GetHttpBanner(service *core.HostService) error {
	log.Printf("Discovering http://%s:%s ...", service.Ip, service.Port)
	req, err := http.NewRequest("GET", fmt.Sprintf("%s://%s:%s/", service.Scheme, service.Ip, service.Port), nil)
	req.Header["User-Agent"] = []string{"l9serviceid/0.1.0 (+https://leakix.net/)"}
	if service.Hostname != service.Ip && len(service.Hostname) > 1 {
		req.Host = service.Hostname
		req.URL.Host = service.Hostname
	}
	if err != nil {
		return err
	}
	// use the http client to fetch the page
	resp, err := plugin.GetHttpClient(service.Ip, service.Port).Do(req)
	if err != nil {
		return err

	}
	defer resp.Body.Close()
	log.Printf("Found %d headers for http://%s:%s", len(resp.Header), service.Ip, service.Port)
	service.Headers = make(map[string][]string)
	// Sanity check to store only sanitized headers
	if resp.TLS != nil {
		if len(resp.TLS.PeerCertificates) > 0 {
			err := resp.TLS.PeerCertificates[0].VerifyHostname(service.Hostname)
			if err == nil {
				service.Certificate.Valid = true
			} else {
				log.Println(err.Error())
			}
			service.Certificate.CommonName = resp.TLS.PeerCertificates[0].Subject.CommonName
			for _, domain := range resp.TLS.PeerCertificates[0].DNSNames {
				service.Certificate.Domains = append(service.Certificate.Domains, domain)
			}

			service.Certificate.Fingerprint = fmt.Sprintf("%02x", sha256.Sum256( resp.TLS.PeerCertificates[0].Raw))
			service.Certificate.CypherSuite = tls.CipherSuiteName(resp.TLS.CipherSuite)
			service.Certificate.Version = GetTLSVersionName(resp.TLS.Version)
			service.Certificate.KeyAlgo = resp.TLS.PeerCertificates[0].PublicKeyAlgorithm.String()
			if publicKey, isECDSA :=  resp.TLS.PeerCertificates[0].PublicKey.(*ecdsa.PublicKey); isECDSA {
				service.Certificate.KeySize = publicKey.Params().BitSize
			} else if publicKey, isRSA :=  resp.TLS.PeerCertificates[0].PublicKey.(*rsa.PublicKey); isRSA {
				service.Certificate.KeySize = publicKey.Size()*8
			}
			service.Certificate.NotBefore = resp.TLS.PeerCertificates[0].NotBefore
			service.Certificate.NotAfter = resp.TLS.PeerCertificates[0].NotAfter
			service.Certificate.IssuerName = resp.TLS.PeerCertificates[0].Issuer.CommonName
			// Only do IPs
			if service.Ip == service.Hostname {
				service.Certificate.JARM, _ = GetJARM(service.Ip, service.Hostname, service.Port)
			}
		}
	}

	for header, values := range resp.Header {
		service.Data += fmt.Sprintf("\r\n%s : %s\n", header, strings.Join(values, ", "))
		for _, validHeader := range ValidHeaders {
			if strings.EqualFold(validHeader, header) && len(values) == 1 && len(values[0]) < 512 {
				service.Headers[validHeader] = values
				if validHeader == "Server" {
					software, err := bannerid.ParseWebServerBanner(values[0])
					if err == nil {
						service.Software.Name = software.Name
						service.Software.Version = software.Version
						service.Software.OperatingSystem = software.OS
						for _, module := range software.Modules {
							service.Software.Modules = append(service.Software.Modules, &core.SoftwareModule{
								Name:    module.Name,
								Version: module.Version,
							})
						}
					}
				}
				if validHeader == "X-Powered-By" {
					software, err := bannerid.ParseWebServerBanner(values[0])
					if err == nil {
						service.Software.Modules = append(service.Software.Modules, &core.SoftwareModule{
							Name:    software.Name,
							Version: software.Version,
						})
					}
				}
			}
		}
	}
	service.DeferSave()
	return nil
}


func GetJARM(ip, host, servicePort string) (string, error) {
	results := []string{}
	port, _ := strconv.Atoi(servicePort)
	for _, probe := range jarm.GetProbes(host, port) {
		c, err := plugin.GetProxiedDialer().Dial("tcp", net.JoinHostPort(ip, fmt.Sprintf("%d", port)))
		if err != nil {
			return "", err
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
	return jarm.RawHashToFuzzyHash(strings.Join(results, ",")), nil
}