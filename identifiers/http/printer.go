package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"strings"
)


func TagPrinter(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if serverHeader, hasServerHeader := event.Http.Headers["server"]; hasServerHeader {
		if strings.HasPrefix(serverHeader, "HP HTTP Server;") {
			event.AddTag("printer")
			return true
		}
	}
	return false
}
