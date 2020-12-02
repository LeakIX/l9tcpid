package main

import (
	"gitlab.nobody.run/tbi/core"
	"strings"
)

var Matches = []func(*core.HostService, []byte, []string) bool{
	// SSL
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if len(bannerBytes) > 3 && bannerBytes[0] == 0x15 && (bannerBytes[1] == 0x01 || bannerBytes[1] == 0x02 || bannerBytes[1] == 0x03) {
			hostService.Scheme = "ssl"
			return true
		}
		return false
	},
	//HTTP
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if len(bannerPrintables) > 0 {
			if strings.Contains(bannerPrintables[0], "HTTP/") || strings.Contains(bannerPrintables[0], "501 ") ||
				strings.Contains(bannerPrintables[0], "500 ") || strings.Contains(bannerPrintables[0], "400 ") ||
				strings.Contains(bannerPrintables[0], "html") || strings.Contains(bannerPrintables[0], "HTML") {
				if hostService.Scheme == "ssl" {
					hostService.Scheme = "https"
				} else {
					hostService.Scheme = "http"
				}
				hostService.Type = "http"
				return true
			}
		}
		return false
	},
	//Mysql
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if strings.Contains(hostService.Data, "mysql_native_password") ||
			(len(bannerBytes) > 16 && bannerBytes[1] == 0x00 && bannerBytes[2] == 0x00 &&
				(strings.Contains(hostService.Data, " is not allowed to connect to this ") ||
					strings.Contains(hostService.Data, "Bad handshake") ||
					strings.Contains(hostService.Data, "Got packets out of order"))) {
			hostService.Type = "mysql"
			return true
		}
		return false
	},
	//SSH
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if len(bannerBytes) > 16 && bannerBytes[3] == 0x2d && bannerBytes[7] == 0x2d &&
			len(bannerPrintables) > 0 && strings.HasPrefix(bannerPrintables[0], "SSH-") {
			hostService.Type = "ssh"
			return true
		}
		return false
	},
	//SMTP
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if len(bannerBytes) > 8 && bannerBytes[0] == 0x32 && bannerBytes[1] == 0x32 && bannerBytes[2] == 0x30 &&
			((len(bannerPrintables) > 0 && strings.Contains(strings.ToLower(bannerPrintables[0]), "smtp")) ||
				hostService.Port == "25" || hostService.Port == "587") {
			hostService.Type = "smtp"
			if strings.Contains(hostService.Data,"STARTTLS") {
				hostService.Scheme = "ssl"
			}
			return true
		}
		return false
	},
	//FTP
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if len(bannerBytes) > 8 && bannerBytes[0] == 0x32 && bannerBytes[1] == 0x32 && bannerBytes[2] == 0x30 &&
			(len(bannerPrintables) > 0 && strings.Contains(strings.ToLower(bannerPrintables[0]), "ftp") ||
				hostService.Port == "21") {
			hostService.Type = "ftp"
			if strings.Contains(bannerPrintables[0], "[TLS]") {
				hostService.Scheme = "ssl"
			}
			return true
		}
		return false
	},
	//redis
	func(hostService *core.HostService, bytes []byte, i []string) bool {
		if len(i) > 0 && strings.HasPrefix(i[0], "-ERR wrong number of arguments for 'get' command") {
			hostService.Type = "redis"
			return true
		}
		return false
	},
	//rtsp
	func(hostService *core.HostService, bytes []byte, i []string) bool {
		if len(i) > 0 && strings.HasPrefix(i[0], "RTSP/1.0") {
			hostService.Type = "rtsp"
			return true
		}
		return false
	},
	//telnet
	func(hostService *core.HostService, bannerBytes []byte, bannerPrintables []string) bool {
		if len(bannerBytes) > 8 && bannerBytes[0] == 0xff && bannerBytes[1] == 0xff && bannerBytes[2] == 0x01 {
			hostService.Type = "telnet"
			return true
		}
		if len(bannerBytes) > 8 && bannerBytes[0] == 0xff && bannerBytes[1] == 0xfd && bannerBytes[2] == 0x18 {
			hostService.Type = "telnet"
			return true
		}
		if len(bannerBytes) > 8 && bannerBytes[0] == 0xff && bannerBytes[1] == 0xfb && bannerBytes[2] == 0x01 {
			hostService.Type = "telnet"
			return true
		}
		if len(bannerBytes) > 8 && bannerBytes[0] == 0x0d && bannerBytes[1] == 0x0a {
			hostService.Type = "telnet"
			return true
		}
		return false
	},
}
