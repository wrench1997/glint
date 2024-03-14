package bigpwdattack

import (
	"errors"
	"fmt"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"math"
	"strings"
	"time"
)

var passArray = []string{
	"pwd", "密码", "pass", "password", "user_password", "user_pass", "user_pwd",
}

type classBigPwdAttack struct {
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

func (c *classBigPwdAttack) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
	// if c.trueFeatures != nil {
	// 	c.trueFeatures.Clear()
	// }
}

func StartTesting(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	//var err error
	var variations *util.Variations

	var BigPwdAttack classBigPwdAttack
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

	BigPwdAttack.lastJob.Init(Param)
	// variations, err = util.ParseUri(url)
	// BlindSQL.variations =

	variations, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		// logger.Error(err.Error())
		return nil, false, errors.New("not found")
	}
	//赋值
	BigPwdAttack.variations = variations
	BigPwdAttack.lastJob.Layer.Sess = sess
	BigPwdAttack.TargetUrl = Param.Url
	BigPwdAttack.lastJob.Layer.Method = Param.Method
	BigPwdAttack.lastJob.Layer.ContentType = Param.ContentType
	BigPwdAttack.lastJob.Layer.Headers = Param.Headers
	BigPwdAttack.lastJob.Layer.Body = []byte(Param.Body)
	defer BigPwdAttack.ClearFeature()

	for _, v := range passArray {
		for _, vp := range variations.Params {
			if strings.EqualFold(vp.Name, v) {
				counts := int(math.Pow10(6))
				payload := strings.Repeat("A", int(counts))
				fmt.Printf("payload len:%d\r\n", len(payload))
				timeout := make(map[string]string)
				timeout["timeout"] = "15"
				//测试长密码
				t1pre := time.Now()
				_, err := BigPwdAttack.lastJob.RequestByIndex(vp.Index, Param.Url, []byte(payload), timeout)

				if err != nil {
					logger.Error(err.Error())
				}
				t1post := time.Since(t1pre)
				if !(t1post.Seconds() > 20) {
					break
				}
				//测试短密码
				counts = int(math.Pow10(2))
				payload = strings.Repeat("A", int(counts))
				t2pre := time.Now()
				BigPwdAttack.lastJob.RequestByIndex(vp.Index, Param.Url, []byte(payload), timeout)
				t2post := time.Since(t2pre)
				if !(t2post.Seconds() > 0.5) {
					break
				}
				//测试中位密码
				counts = int(math.Pow10(5))
				payload = strings.Repeat("A", int(counts))
				t3pre := time.Now()
				BigPwdAttack.lastJob.RequestByIndex(vp.Index, Param.Url, []byte(payload), timeout)
				t3post := time.Since(t3pre)
				if !(t3post.Seconds() > 3) {
					break
				}

				//再次测试长位密码
				counts = int(math.Pow10(6))
				payload = strings.Repeat("A", int(counts))
				t4pre := time.Now()
				Features, err := BigPwdAttack.lastJob.RequestByIndex(vp.Index, Param.Url, []byte(payload), timeout)
				t4post := time.Since(t4pre)
				if !(t4post.Seconds() > 20) {
					break
				}

				//再次测试短位密码
				counts = 5 * int(math.Pow10(2))
				payload = strings.Repeat("A", int(counts))
				t5pre := time.Now()
				BigPwdAttack.lastJob.RequestByIndex(vp.Index, Param.Url, []byte(payload), timeout)
				t5post := time.Since(t5pre)
				if !(t5post.Seconds() > 0.5) {
					break
				}
				//都测试完成后，可以断定这个站点没有对密码长度进行限制。
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"big passwd denial of service ",
					[]string{string(Features.Request.String())},
					[]string{string(Features.Response.String())},
					"high",
					Param.Hostid, string(plugin.BigPwdAttack))
				gd.Alert(Result)
				return Result, true, err
			}
		}
	}
	return nil, false, errors.New("not found")
}
