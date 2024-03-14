package directorytraversal

import (
	"errors"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"time"
)

// var DefaultProxy = ""
// var Cert string
// var Mkey string

func TraversalVaild(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations
	var DirectoryTraversal classDirectoryTraversal
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
	gd := args
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

	DirectoryTraversal.lastJob.Init(Param)
	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	// if value, ok := Param.Headers["Content-Type"]; ok {
	// 	ContentType = value
	// }

	if value, ok := Param.Headers["Content-Type"]; ok {
		Param.ContentType = value
	}

	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	//赋值
	DirectoryTraversal.variations = variations
	DirectoryTraversal.lastJob.Layer.Sess = sess
	DirectoryTraversal.TargetUrl = Param.Url
	DirectoryTraversal.lastJob.Layer.Method = Param.Method
	DirectoryTraversal.lastJob.Layer.ContentType = Param.ContentType
	DirectoryTraversal.lastJob.Layer.Headers = Param.Headers
	DirectoryTraversal.lastJob.Layer.Body = []byte(Param.Body)

	if DirectoryTraversal.startTesting() {
		// println(hostid)
		// println("发现sql漏洞")
		//....................
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"DirectoryTraversal Vulnerable",
			[]string{string(DirectoryTraversal.lastJob.Features.Request.String())},
			[]string{string(DirectoryTraversal.lastJob.Features.Response.String())},
			"high",
			Param.Hostid, string(plugin.DIR_COSS))
		gd.Alert(Result)
		return Result, true, err
	}
	return nil, false, err
}
