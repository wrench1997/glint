package nmapSsl

import (
	"errors"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"

	"github.com/thoas/go-funk"
)

func Sweet32verify(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var Param layers.PluginParam
	ct := layers.CheckType{IsMultipleUrls: true, Urlindex: 0}
	// ct := layers.CheckType{}
	// ct.IsMultipleUrls = true
	gd := args
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}
	err := TestNmapScan(Param)
	if err != nil {
		return nil, false, errors.New("SSL test not found")
	}
	if funk.Contains(NmapMsg, "TLS_RSA_WITH_IDEA_CBC_SHA") || funk.Contains(NmapMsg, "TLS_RSA_WITH_3DES_EDE_CBC_SHA") {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"TLS/SSL Sweet32 attack",
			[]string{string("")},
			[]string{string("")},
			"middle",
			Param.Hostid, "rj-010-0003")
		Result.Vulnid = "rj-010-0003"
		gd.Alert(Result)
		return Result, true, nil
	}

	return nil, false, errors.New("SSL test not found")
}
