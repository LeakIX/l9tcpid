package l9tcpid

import (
	"bufio"
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/gboddin/goccm"
	"io/ioutil"
	"log"
	"os"
)

type TcpIdCommand struct {
	MaxThreads int  `default:"10"`
	ThreadManager *goccm.ConcurrencyManager `kong:"-"`
	DeepHttp bool
	Debug bool
}
func (cmd *TcpIdCommand) Run() error {
	cmd.ThreadManager = goccm.New(cmd.MaxThreads)
	defer cmd.ThreadManager.WaitAllDone()
	if !cmd.Debug {
		log.SetOutput(ioutil.Discard)
	}
	stdinReader := bufio.NewReaderSize(os.Stdin, 256*1024)
	stdoutEncoder := json.NewEncoder(os.Stdout)
	for {
		bytes, isPrefix, err := stdinReader.ReadLine()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			log.Fatal(err)
		}
		if isPrefix == true {
			log.Fatal("Event is too big")
		}
		event := &l9format.L9Event{}
		err = json.Unmarshal(bytes, event)
		event.AddSource("l9tcpid")
		event.EventType = "service"
		event.Protocol = "tcp"
		if err != nil {
			return err
		}
		cmd.ThreadManager.Wait()
		go func(event *l9format.L9Event) {
			err = GetBanner(event)
			if event.HasTransport("http") && cmd.DeepHttp {
				err = GetHttpBanner(event)
			}
			if len(event.Summary) > 0 {
				err = stdoutEncoder.Encode(event)
				if err != nil {
					log.Fatal(err)
				}
			}
			if err != nil {
				log.Println(err)
			}
			cmd.ThreadManager.Done()
		}(event)
	}
	return nil
}

