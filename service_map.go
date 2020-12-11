package l9tcpid

import (
	"github.com/LeakIX/l9format"
	"github.com/LeakIX/l9tcpid/identifiers/http"
	"github.com/LeakIX/l9tcpid/identifiers/tcp"
	"github.com/PuerkitoBio/goquery"
)

type TcpIdentifier func(event *l9format.L9Event, banner []byte, lines[]string) bool
type HttpIdentifier func(event *l9format.L9Event, body string, document *goquery.Document) bool


var TCPIdentifiers = []TcpIdentifier{
	tcp.IdentifySSH,
	tcp.IdentifyHttp,
	tcp.IdentifyMysql,
	tcp.IdentifySMTP,
	tcp.IdentifyFTP,
	tcp.IdentifyRedis,
	tcp.IdentifyRTSP,
	tcp.IdentifyTelnet,
}

var HttpIdentifiers = []HttpIdentifier{
	http.IdentifyElasticSearch,
}
