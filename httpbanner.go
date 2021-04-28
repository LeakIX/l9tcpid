package l9tcpid

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"gitlab.nobody.run/tbi/bannerid"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func GetHttpClient(event *l9format.L9Event) *http.Client {
	ip := event.Ip
	if strings.Contains(ip, ":") {
		ip = fmt.Sprintf("[%s]", event.Ip)
	}
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _ string, _ string) (net.Conn, error) {
				return GetNetworkConnection(event)
			},
			ResponseHeaderTimeout: 2 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
			DisableKeepAlives:     true,
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

var HttpTestRequest = "GET %s HTTP/1.1\r\n" +
	"Host: %s\r\n" +
	"User-Agent: l9tcpid/v1.0.0\r\n" +
	"Connection: close\r\n"

func SendHttpTestRequest(hostname string, path string, connection net.Conn) (err error) {
	err = SendLine(fmt.Sprintf(HttpTestRequest, path, hostname), connection)
	if err != nil {
		return err
	}
	return nil
}

func GetHttpBanner(event *l9format.L9Event, path string) (err error) {
	hostname := event.Ip
	if len(event.Host) > 0 && event.Ip != event.Host {
		hostname = event.Host
	}
	connection, err := GetNetworkConnection(event)
	if err != nil {
		return err
	}
	err = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if err != nil {
		return err
	}
	if event.HasTransport("tls") {
		connection = tls.Client(connection, &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true,
		})
		err = connection.(*tls.Conn).Handshake()
		if err != nil {
			return err
		}
	}
	defer connection.Close()
	// We're connected run the request
	err = SendHttpTestRequest(hostname, path, connection)
	if err != nil {
		return err
	}

	err = connection.SetReadDeadline(time.Now().Add(3 * time.Second))
	scanner := bufio.NewScanner(connection)
	var response string
	var httpStatusLine string
	var body string
	headers := make(map[string]string)
	// Handle status line
	if scanner.Scan() {
		httpStatusLine = scanner.Text()
		httpStatusLineParts := strings.Fields(httpStatusLine)
		if len(httpStatusLineParts) > 2 {
			if statusCode, err := strconv.Atoi(httpStatusLineParts[1]); err == nil && statusCode > 0 && statusCode < 999 {
				event.Http.Status = statusCode
			}
		}
		response += httpStatusLine + "\r\n"
	}
	// Handle headers
	for scanner.Scan() {
		response += scanner.Text() + "\r\n"
		if scanner.Text() == "" {
			break
		}
		headerParts := strings.Split(scanner.Text(), ":")
		headers[strings.Trim(strings.ToLower(headerParts[0]), " ")] = strings.Trim(strings.TrimPrefix(scanner.Text(), headerParts[0]+":"), " ")
		if len(headers) > 128 {
			break
		}
	}
	if banner, found := headers["server"]; found {
		log.Println(banner)
		software, err := bannerid.ParseWebServerBanner(banner)
		if err == nil {
			event.Service.Software.Name = software.Name
			event.Service.Software.Version = software.Version
			event.Service.Software.OperatingSystem = software.OS
			for _, module := range software.Modules {
				event.Service.Software.Modules = append(event.Service.Software.Modules, l9format.SoftwareModule{
					Name:        module.Name,
					Version:     module.Version,
				})
			}
		}
	}
	event.Http.Headers = headers
	event.Summary = response

	// Handles body
	//String appending costs a lot, using a byte buffer saves 25% CPU :|
	bodyBuffer := bytes.NewBufferString("")
	for scanner.Scan() {
		bodyBuffer.Write(scanner.Bytes())
		if bodyBuffer.Len() > 64*1024 {
			break
		}
	}
	body = bodyBuffer.String()

	document, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err == nil {
		title := document.Find("title")
		if title.Length() > 0 && len(title.Text()) > 0 {
			event.Http.Title = title.Text()
			event.Summary = response + "Page title: " + title.Text()
		}
	}

	for _, matchFunc := range HttpIdentifiers {
		if matchFunc(event, body, document) {
			break
		}
	}
	if len(event.Http.Title) < 1 && len(body) < 16*1024 {
		event.Summary += body
	}
	return nil
}


