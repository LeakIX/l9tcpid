package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"strings"
)

func TagNginx(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if serverHeader, hasServerHeader := event.Http.Headers["server"]; hasServerHeader {
		if strings.Contains(serverHeader, "nginx") {
			event.AddTag("nginx")
			return true
		}
	}
	return false
}

func TagApache(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if serverHeader, hasServerHeader := event.Http.Headers["server"]; hasServerHeader && len(serverHeader) < 128 {
		if strings.Contains(serverHeader, "Apache") {
			event.AddTag("apache")
			if strings.Contains(serverHeader, "Coyote") {
				event.AddTag("tomcat")
			}
			return true
		}
	}
	return false
}

func TagPHP(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if serverHeader, hasServerHeader := event.Http.Headers["server"]; hasServerHeader && len(serverHeader) < 128 {
		if strings.Contains(serverHeader, "PHP/") {
			event.AddTag("php")
			return true
		}
	}
	if powerHeader, hasPowerHeader := event.Http.Headers["x-powered-by"]; hasPowerHeader && len(powerHeader) < 128 {
		if strings.HasPrefix(powerHeader, "PHP") {
			event.AddTag("php")
			return true
		}
	}
	return false
}
