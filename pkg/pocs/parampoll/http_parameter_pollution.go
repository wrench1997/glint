package parampoll

import (
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"regexp"
	"time"
)

type classParampoll struct {
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

var payload = `8634&n974065=v934137`

const pattern = `href=".*8634&n974065=v934137.*"`

func (c *classParampoll) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
}

func StartTesting(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	//var err error
	var variations *util.Variations

	var Parampoll classParampoll
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
	gd := args
	ct := layers.CheckType{IsMultipleUrls: false}
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       60 * time.Second,
			RetryTimes:    Param.MaxRedirectTimes,
			AllowRedirect: false,
			Proxy:         Param.UpProxy,
			Cert:          Param.Cert,
			PrivateKey:    Param.CertKey,
		})

	Parampoll.lastJob.Init(Param)

	variations, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		// logger.Error(err.Error())
		return nil, false, errors.New("not found")
	}
	//赋值
	Parampoll.variations = variations
	Parampoll.lastJob.Layer.Sess = sess
	Parampoll.TargetUrl = Param.Url
	Parampoll.lastJob.Layer.Method = Param.Method
	Parampoll.lastJob.Layer.ContentType = Param.ContentType
	Parampoll.lastJob.Layer.Headers = Param.Headers
	Parampoll.lastJob.Layer.Body = []byte(Param.Body)
	defer Parampoll.ClearFeature()

	timeout := make(map[string]string)
	timeout["timeout"] = "3"

	// for _, v := range passArray {
	for _, vp := range variations.Params {
		features, err := Parampoll.lastJob.RequestByIndex(vp.Index, Param.Url, []byte(payload), timeout)

		if err != nil {
			logger.Error(err.Error())
		}
		// 将模式编译成正则表达式对象
		re := regexp.MustCompile(pattern)

		// 匹配字符串
		matchstrs := re.FindAllString(features.Response.String(), 1)

		if len(matchstrs) != 0 {
			//都测试完成后，可以断定这个站点没有对密码长度进行限制。
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"ParamPoll",
				[]string{string(features.Request.String())},
				[]string{string(features.Response.String())},
				"high",
				Param.Hostid, string(plugin.ParamPoll))
			gd.Alert(Result)
			return Result, true, err
		}
	}
	return nil, false, errors.New("not found")
}
