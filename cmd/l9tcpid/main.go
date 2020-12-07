package main

import (
	"github.com/LeakIX/l9tcpid"
	"github.com/alecthomas/kong"
)

var App struct {
	Service l9tcpid.TcpIdCommand `cmd`
}

func main() {
	ctx := kong.Parse(&App)
	// Call the Run() method of the selected parsed command.
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
