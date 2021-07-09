package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"strings"
)

func TagPLC(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if serverHeader, hasServerHeader := event.Http.Headers["server"]; hasServerHeader && len(serverHeader) < 128 {
		if strings.Contains(serverHeader, "A-B WWW/") {
			event.AddTag("plc")
			return true
		}
	}
	return false
}
