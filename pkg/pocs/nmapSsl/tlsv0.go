package nmapSsl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"log"
	"net/url"
	"sync"
	"time"

	"github.com/Ullaakut/nmap/v2"
	"github.com/thoas/go-funk"
)

var NmapMsg string

// var DefaultProxy = ""

// var cert string
// var mkey string
var mutex sync.Mutex

//var threadwg sync.WaitGroup //同步线程

type ExceptionStruct struct {
	Try     func()
	Catch   func(Exception)
	Finally func()
}
type Exception interface{}

func Throw(up Exception) {
	panic(up)
}
func (this ExceptionStruct) Do() {
	if this.Finally != nil {

		defer this.Finally()
	}
	if this.Catch != nil {
		defer func() {
			if e := recover(); e != nil {
				this.Catch(e)
			}
		}()
	}
	this.Try()
}

func TestNmapScan(Param layers.PluginParam) error {
	var err error
	if NmapMsg == "" {
		var scanner *nmap.Scanner
		var err error
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
		// with a 5 minute timeout.

		// re := regexp.MustCompile(`[http://|https://]`)

		u, err := url.Parse(Param.Url)
		if err != nil {
			logger.Error("%s", err.Error())
		}

		urlchunk := u.Hostname()
		scanner, err = nmap.NewScanner(
			nmap.WithTargets(urlchunk),
			nmap.WithPorts("443"),
			nmap.WithScripts("ssl-enum-ciphers"),
			nmap.WithContext(ctx),
		)

		if err != nil {
			logger.Error("%s", err.Error())
			return err
		}

		result, warnings, err := scanner.Run()
		if err != nil {
			logger.Error("unable to run nmap scan: %v", err)
			return err
		}

		if warnings != nil {
			log.Printf("Warnings: \n %v", warnings)
			return fmt.Errorf("warnings error:%v", warnings)
		}

		ExceptionStruct{
			Try: func() {
				var buf bytes.Buffer
				rawXml := result.ToReader()
				buf.ReadFrom(rawXml)
				mutex.Lock()
				defer mutex.Unlock()
				NmapMsg = buf.String()
			},
			Catch: func(e Exception) {
				fmt.Printf("exception %v\n", e)
				err = fmt.Errorf("exception%v", e)
			},
			Finally: func() {
				fmt.Println("Finally...")
			}}.Do()
	}
	return err
}

func TLSv0verify(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var Param layers.PluginParam
	ct := layers.CheckType{IsMultipleUrls: true, Urlindex: 0}
	gd := args
	// ct := layers.CheckType{}
	// ct.IsMultipleUrls = true
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}
	err := TestNmapScan(Param)
	if err != nil {
		return nil, false, errors.New("SSL test not found")
	}

	if funk.Contains(NmapMsg, "TLSv1.0") {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"TLSV0 has enable",
			[]string{string("")},
			[]string{string("")},
			"high",
			Param.Hostid, "rj-010-0001")
		// Result.Vulnid = "rj-010-0001"
		gd.Alert(Result)
		return Result, true, nil
	}

	return nil, false, errors.New("SSL test not found")
}
