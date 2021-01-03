package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
)

func IdentifyCouchDb(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if _, couchDbHeaderFound := event.Http.Headers["x-couch-request-id"]; couchDbHeaderFound {
		event.Protocol = "couchdb"
		return true
	}
	return false
}