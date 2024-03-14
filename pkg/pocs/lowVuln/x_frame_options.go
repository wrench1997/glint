package lowsomething

import (
	"errors"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"regexp"
	"strings"

	"github.com/thoas/go-funk"
)

type ClassSomething struct {
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
}

func (c *ClassSomething) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
	if c.trueFeatures != nil {
		c.trueFeatures.Clear()
	}
}

func validXFrameOptionsValue(value string) bool {
	value = strings.ToUpper(strings.TrimSpace(value))
	if strings.Contains(value, "ALLOW-FROM") {
		return true
	}
	return value == "DENY" || value == "SAMEORIGIN"
}

// 定义函数，用于从网页内容中查找 frame 和 iframe 标签
func findFrameTags(content string) bool {
	// 定义正则表达式，用于匹配 frame 和 iframe 标签
	re := regexp.MustCompile(`<(frame|iframe)`)

	// 使用正则表达式来查找网页内容中的 frame 和 iframe 标签
	if re.FindString(content) != "" {
		// 如果找到了，返回 true
		return true
	}

	// 如果没有找到，返回 false
	return false
}

func Jacking_X_Frame_Options_Valid(args *plugin.GroupData) (*util.ScanResult, bool, error) {

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

		if CclassSomething.startTesting() {
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"The Site has been jacking_X_Frame_Options vulnerability",
				[]string{string(CclassSomething.trueFeatures.Request.String())},
				[]string{string(CclassSomething.trueFeatures.Response.String())},
				"low",
				Param.Hostid, string(plugin.X_Frame_Options))
			gd.Alert(Result)
			return Result, true, err
		}
	}
	return nil, false, errors.New("not found")
}

func (c *ClassSomething) startTesting() bool {

	req, resp, err := c.lastJob.Layer.Sess.Get(c.targetURL, c.lastJob.Layer.Headers)
	if err != nil {
		logger.Error("classSomething error %s", err.Error())
		return false
	}
	req.CopyTo(&c.trueFeatures.Request)
	resp.CopyTo(&c.trueFeatures.Response)
	if funk.Contains(c.lastJob.Layer.ContentType, "text/html") {
		if findFrameTags(string(resp.String())) {
			// Check if lastJob.Layer.Headers contains the X-Frame-Options key
			if headers, ok := c.lastJob.Layer.Headers["X-Frame-Options"]; ok {
				// Call the validXFrameOptionsValue function and pass in the value of the X-Frame-Options key
				return validXFrameOptionsValue(headers)
			}
		}
	}

	// Return true if the X-Frame-Options key is  found
	return true
}
