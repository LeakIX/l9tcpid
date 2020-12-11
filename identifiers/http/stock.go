package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"strings"
)

func IdentifyElasticSearch(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if event.Http.Status == 200 && strings.Contains(body,"lucene") && strings.Contains(body,"cluster_uuid")  {
		event.Protocol = "elasticsearch"
		return true
	}
	return false
}