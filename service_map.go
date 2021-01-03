package l9tcpid

import (
	"github.com/LeakIX/l9format"
	"github.com/LeakIX/l9tcpid/identifiers/http"
	"github.com/LeakIX/l9tcpid/identifiers/tcp"
	"github.com/PuerkitoBio/goquery"
)

type TcpIdentifier func(event *l9format.L9Event, banner []byte, lines []string) bool
type HttpIdentifier func(event *l9format.L9Event, body string, document *goquery.Document) bool

var TCPIdentifiers = []TcpIdentifier{
	tcp.IdentifyHttp,
	tcp.IdentifyKibana,
	tcp.IdentifyMongoDb,
	tcp.IdentifySSH,
	tcp.IdentifyMysql,
	tcp.IdentifySMTP,
	tcp.IdentifyFTP,
	tcp.IdentifyRedis,
	tcp.IdentifyRTSP,
	tcp.IdentifyTelnet,
	tcp.IdentifyCassandra,
}
var HttpIdentifiers = []HttpIdentifier{
	http.IdentifyElasticSearch,
	http.IdentifyKibana,
	http.IdentifyCouchDb,
}
var serviceMap = map[string]string{
	"9092": "kafka",
	"2181": "zookeeper",
}

func ApplyDefaultProtocol(event *l9format.L9Event) (found bool) {
	event.Protocol, found = serviceMap[event.Port]
	return found
}
