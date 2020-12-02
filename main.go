package main

import (
	"bufio"
	"encoding/json"
	"github.com/zenthangplus/goccm"
	"gitlab.nobody.run/tbi/core"
	"log"
	"os"
)
var cm = goccm.New(512)

func main() {
	stdinScanner := bufio.NewScanner(os.Stdin)
	stdoutEncoder := json.NewEncoder(os.Stdout)
	for stdinScanner.Scan() {
		hostService := &core.HostService{}
		err := json.Unmarshal(stdinScanner.Bytes(), hostService)
		if err != nil {
			panic(err)
		}
		cm.Wait()
		go func(hostService *core.HostService) {
			err = GetBanner(hostService)
			if len(hostService.Data) > 0 {
				err = stdoutEncoder.Encode(hostService)
				if err != nil {
					panic(err)
				}
			}
			if err != nil {
				log.Println(err)
			}
			cm.Done()
		}(hostService)
	}
	cm.WaitAllDone()
}
