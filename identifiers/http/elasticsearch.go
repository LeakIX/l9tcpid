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

func IdentifyKibana(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if kbnVersion, kbnFound := event.Http.Headers["kbn-version"]; kbnFound {
		event.Protocol = "kibana"
		event.Service.Software.Name = "Kibana"
		event.Service.Software.Fingerprint = "kibana"
		event.Service.Software.Version = kbnVersion
		return true
	}
	if _, kbnFound := event.Http.Headers["kbn-name"]; kbnFound {
		event.Protocol = "kibana"
		event.Service.Software.Name = "Kibana"
		event.Service.Software.Version = ""
		return true
	}
	return false
}