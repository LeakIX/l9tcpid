package l9tcpid

import (
	"bufio"
	"encoding/json"
	"github.com/LeakIX/l9format"
	"github.com/gboddin/goccm"
	"log"
	"os"
)

type TcpIdCommand struct {
	MaxThreads int  `default:"10"`
	ThreadManager *goccm.ConcurrencyManager `kong:"-"`
}
func (cmd *TcpIdCommand) Run() error {
	cmd.ThreadManager = goccm.New(cmd.MaxThreads)
	stdinScanner := bufio.NewScanner(os.Stdin)
	stdoutEncoder := json.NewEncoder(os.Stdout)
	for stdinScanner.Scan() {
		event := &l9format.L9Event{}
		err := json.Unmarshal(stdinScanner.Bytes(), event)
		event.AddSource("l9tcpid")
		event.Protocol = "tcp"
		if err != nil {
			return err
		}
		cmd.ThreadManager.Wait()
		go func(event *l9format.L9Event) {
			err = GetBanner(event)
			if len(event.Summary) > 0 {
				err = stdoutEncoder.Encode(event)
				if err != nil {
					panic(err)
				}
			}
			if err != nil {
				log.Println(err)
			}
			cmd.ThreadManager.Done()
		}(event)
	}
	cmd.ThreadManager.WaitAllDone()
	return nil
}

