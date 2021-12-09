package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"strings"
)

func IdentifyGrafana(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if strings.HasPrefix(event.Http.Title, "Grafana") {
		event.Service.Software.Name = "Grafana"
		return true
	}
	return false
}
