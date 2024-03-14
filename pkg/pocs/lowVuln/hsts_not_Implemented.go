package lowsomething

import (
	"errors"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"strings"
)

/**
title: HSTS Not Implemented
tags: HSTS
author: Alex
issue: 207
description:
    Alerts if HTTP Strict Transport Security (HSTS) is not implemented.
**/

func Hsts__Valid(args *plugin.GroupData) (*util.ScanResult, bool, error) {

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

		if CclassSomething.startTesting2() {
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"HSTS Not Implemented",
				[]string{string(CclassSomething.trueFeatures.Request.String())},
				[]string{string(CclassSomething.trueFeatures.Response.String())},
				"low",
				Param.Hostid, string(plugin.HSTS_detection))
			gd.Alert(Result)
			return Result, true, err
		}
	}
	return nil, false, errors.New("not found")
}

func (c *ClassSomething) startTesting2() bool {
	req, resp, err := c.lastJob.Layer.Sess.Get(c.targetURL, c.lastJob.Layer.Headers)
	if err != nil {
		logger.Error("classSomething error %s", err.Error())
		return false
	}

	req.CopyTo(&c.trueFeatures.Request)
	resp.CopyTo(&c.trueFeatures.Response)

	// browser doesn't accept HSTS header via HTTP
	if strings.EqualFold(c.lastJob.Layer.ContentType, "text/html") {
		// HSTS headers are present?
		if value, ok := c.lastJob.Layer.Headers["Strict-Transport-Security"]; ok {
			hstsValue := value

			// __dbgout('hstsValue: ' + hstsValue);
			directives := strings.Split(hstsValue, ";")
			maxAge := false // greater or equal to 1 year
			//preload := false // not used
			iSD := false //include subdomains
			for _, d := range directives {
				// __dbgout('HSTS current directive: ' + d);
				curDir := strings.Split(d, "=")
				curName := strings.ToLower(strings.TrimSpace(curDir[0]))
				if curName == "includesubdomains" {
					iSD = true
				} else if curName == "preload" {
					//preload = true
				} else if curName == "max-age" {
					if curDir[1] != "" {
						maVal := strings.TrimSpace(curDir[1])
						maVal = strings.ReplaceAll(maVal, `"`, "")
						if len(maVal) >= 31536000 {
							maxAge = true
						}
					}
				}
			}

			if maxAge == false || iSD == false {
				//  __dbgout("alertImprovments maxAge=" + maxAge + ' iSD=' + iSD + ' at ' + scriptArg.http.request.uri);
				//alertImprovments(!maxAge, !iSD)
				return true
			}

		} else {
			// __dbgout("alertNoHSTS "+ scriptArg.http.request.uri);
			// alertNoHSTS()
			return false
		}
	}
	return false
}
