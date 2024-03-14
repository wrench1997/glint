package nmapSsl

import (
	"errors"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"

	"github.com/thoas/go-funk"
)

// var cert string
// var mkey string

// var threadwg sync.WaitGroup //同步线程
func TLSv1verify(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var Param layers.PluginParam
	gd := args
	ct := layers.CheckType{IsMultipleUrls: true, Urlindex: 0}
	// ct := layers.CheckType{}
	// ct.IsMultipleUrls = true
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}
	err := TestNmapScan(Param)
	if err != nil {
		return nil, false, errors.New("SSL test not found")
	}

	if funk.Contains(NmapMsg, "TLSv1.1") {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"TLSV1 has enable",
			[]string{string("")},
			[]string{string("")},
			"middle",
			Param.Hostid, "rj-010-0002")
		// Result.Vulnid = "rj-010-0002"
		gd.Alert(Result)
		return Result, true, nil
	}

	return nil, false, errors.New("SSL test not found")
}
