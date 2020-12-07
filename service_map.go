package l9tcpid

import (
	"github.com/LeakIX/l9format"
	"github.com/LeakIX/l9tcpid/identifiers"
)

type BannerIdentifier func(*l9format.L9Event, []byte, []string) bool

var Matches = []BannerIdentifier{
	identifiers.IdentifySSH,
	identifiers.IdentifyElasticSearch,
	identifiers.IdentifyHttp,
	identifiers.IdentifyMysql,
	identifiers.IdentifySMTP,
	identifiers.IdentifyFTP,
	identifiers.IdentifyRedis,
	identifiers.IdentifyRTSP,
	identifiers.IdentifyTelnet,
}
