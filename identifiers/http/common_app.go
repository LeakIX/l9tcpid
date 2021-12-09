package http

import (
	"github.com/LeakIX/l9format"
	"github.com/PuerkitoBio/goquery"
	"strings"
)

// This stage is useful if a plugin relies on tags ( eg nuclei plugin )

func TagDrupal(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if strings.Contains(body, "Drupal.settings") || strings.Contains(body, "content=\"Drupal") {
		event.AddTag("drupal")
		event.AddTag("php")
		return true
	}
	return false
}

func TagWordpress(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if strings.Contains(body, "wp-content/") {
		event.AddTag("wordpress")
		event.AddTag("php")
		return true
	}
	return false
}

func TagJoomla(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if strings.Contains(body, "content=\"Joomla!") {
		event.AddTag("joomla")
		event.AddTag("php")
		return true
	}
	return false
}

func TagVMWare(event *l9format.L9Event, body string, document *goquery.Document) bool {
	if strings.Contains(body, "vmware.vsphere.client") {
		event.AddTag("vmware")
		return true
	}
	return false
}
