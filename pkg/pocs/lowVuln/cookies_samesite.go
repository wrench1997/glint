package lowsomething

import (
	"errors"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"strings"

	"github.com/thoas/go-funk"
)

func Cookies_not_set_SameSite_flag(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations

	var CclassSomething ClassSomething
	// var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
	// ct := layers.CheckType{}
	gd := args

	for i := 0; i < len(gd.GroupUrls); i++ {
		ct := layers.CheckType{IsMultipleUrls: true, Urlindex: i}
		ct.IsMultipleUrls = true
		Param.ParsePluginParams(args, ct)
		if Param.CheckForExitSignal() {
			return nil, false, errors.New("receive task exit signal")
		}
		sess, _ := Param.GenerateSession()
		if value, ok := Param.Headers["Content-Type"]; ok {
			Param.ContentType = value
		}
		//赋值
		CclassSomething.lastJob.Init(Param)
		variations, err = Param.GenerateVariable()
		CclassSomething.variations = variations
		CclassSomething.lastJob.Layer.Sess = sess
		CclassSomething.targetURL = Param.Url
		CclassSomething.lastJob.Layer.Method = Param.Method
		CclassSomething.lastJob.Layer.ContentType = Param.ContentType
		CclassSomething.lastJob.Layer.Headers = Param.Headers
		CclassSomething.lastJob.Layer.Body = []byte(Param.Body)
		CclassSomething.trueFeatures = &layers.MFeatures{}

		defer CclassSomething.ClearFeature()

		if CclassSomething.startTesting456() {
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"cookie not set samesite",
				[]string{string(CclassSomething.trueFeatures.Request.String())},
				[]string{string(CclassSomething.trueFeatures.Response.String())},
				"low",
				Param.Hostid, string("rj-022-0001"))
			gd.Alert(Result)
			return Result, true, err
		}
	}
	return nil, false, errors.New("not found")
}

func (c *ClassSomething) startTesting456() bool {
	///先请求一次
	req, resp, err := c.lastJob.Layer.Sess.Get(c.targetURL, c.lastJob.Layer.Headers)
	if err != nil {
		logger.Error("classSomething error %s", err.Error())
		return false
	}
	req.CopyTo(&c.trueFeatures.Request)
	resp.CopyTo(&c.trueFeatures.Response)
	cookies := resp.Header.Peek("Set-Cookie")
	if len(cookies) == 0 {
		return false
	} else if !funk.Contains(strings.ToLower(string(cookies)), strings.ToLower("SameSite")) {
		return true
	}
	return false
}
