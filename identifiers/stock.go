package identifiers

import (
	"github.com/LeakIX/l9format"
	"strings"
)

func IdentifyHttp(event *l9format.L9Event, bannerBytes []byte, bannerPrintables []string) bool {
	if len(bannerPrintables) > 0 {
		if strings.Contains(bannerPrintables[0], "HTTP/") || strings.Contains(bannerPrintables[0], "501 ") ||
			strings.Contains(bannerPrintables[0], "500 ") || strings.Contains(bannerPrintables[0], "400 ") ||
			strings.Contains(bannerPrintables[0], "html") || strings.Contains(bannerPrintables[0], "HTML") {
			if event.SSL.Enabled {
				event.Protocol = "https"
			} else {
				event.Protocol = "http"
			}
			event.Transports = append(event.Transports, "http")
			// continue other matchers
			return false
		}
	}
	return false
}
func IdentifyMysql(event *l9format.L9Event, bannerBytes []byte, bannerPrintables []string) bool {
	if strings.Contains(event.Summary, "mysql_native_password") ||
		(len(bannerBytes) > 16 && bannerBytes[1] == 0x00 && bannerBytes[2] == 0x00 &&
			(strings.Contains(event.Summary, " is not allowed to connect to this ") ||
				strings.Contains(event.Summary, "Bad handshake") ||
				strings.Contains(event.Summary, "Got packets out of order"))) {
		event.Protocol = "mysql"
		return true
	}
	return false
}

func IdentifySSH(event *l9format.L9Event, bannerBytes []byte, bannerPrintables []string) bool {
	if len(bannerBytes) > 16 && bannerBytes[3] == 0x2d && bannerBytes[7] == 0x2d &&
		len(bannerPrintables) > 0 && strings.HasPrefix(bannerPrintables[0], "SSH-") {
		event.Protocol = "ssh"
		return true
	}
	return false
}

func IdentifySMTP(event *l9format.L9Event, bannerBytes []byte, bannerPrintables []string) bool {
	if len(bannerBytes) > 8 && bannerBytes[0] == 0x32 && bannerBytes[1] == 0x32 && bannerBytes[2] == 0x30 &&
		((len(bannerPrintables) > 0 && strings.Contains(strings.ToLower(bannerPrintables[0]), "smtp")) ||
			event.Port == "25" || event.Port == "587") {
		event.Protocol = "smtp"
		if strings.Contains(event.Summary,"STARTTLS") {
			event.SSL.Detected = true
		}
		return true
	}
	return false
}
func IdentifyFTP(event *l9format.L9Event, bannerBytes []byte, bannerPrintables []string) bool {
	if len(bannerBytes) > 8 && bannerBytes[0] == 0x32 && bannerBytes[1] == 0x32 && bannerBytes[2] == 0x30 &&
		(len(bannerPrintables) > 0 && strings.Contains(strings.ToLower(bannerPrintables[0]), "ftp") ||
			event.Port == "21") {
		event.Protocol = "ftp"
		if strings.Contains(bannerPrintables[0], "[TLS]") {
			event.SSL.Detected = true
		}
		return true
	}
	return false
}
func IdentifyRedis(event *l9format.L9Event, bytes []byte, i []string) bool {
	if len(i) > 0 && strings.HasPrefix(i[0], "-ERR wrong number of arguments for 'get' command") {
		event.Protocol = "redis"
		return true
	}
	return false
}

func IdentifyRTSP(event *l9format.L9Event, bytes []byte, i []string) bool {
	if len(i) > 0 && strings.HasPrefix(i[0], "RTSP/1.0") {
		event.Protocol = "rtsp"
		return true
	}
	return false
}

func IdentifyTelnet(event *l9format.L9Event, bannerBytes []byte, bannerPrintables []string) bool {
	if len(bannerBytes) > 8 && bannerBytes[0] == 0xff && bannerBytes[1] == 0xff && bannerBytes[2] == 0x01 {
		event.Protocol = "telnet"
		return true
	}
	if len(bannerBytes) > 8 && bannerBytes[0] == 0xff && bannerBytes[1] == 0xfd && bannerBytes[2] == 0x18 {
		event.Protocol = "telnet"
		return true
	}
	if len(bannerBytes) > 8 && bannerBytes[0] == 0xff && bannerBytes[1] == 0xfb && bannerBytes[2] == 0x01 {
		event.Protocol = "telnet"
		return true
	}
	if len(bannerBytes) > 8 && bannerBytes[0] == 0x0d && bannerBytes[1] == 0x0a {
		event.Protocol = "telnet"
		return true
	}
	return false
}

func IdentifyElasticSearch(event *l9format.L9Event, bytes []byte, i []string) bool {
	if event.HasTransport("http") &&
		(strings.Contains(event.Summary,"lucene") && strings.Contains(event.Summary,"cluster_uuid") ) {
		event.Protocol = "elasticsearch"
		return true
	}
	return false
}