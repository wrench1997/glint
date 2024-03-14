package ssrfcheck

import (
	"errors"
	"glint/config"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	reverse2 "glint/reverse"
	"glint/util"
	"strings"
	"time"
)

func Ssrf(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	util.Setup()
	var Param layers.PluginParam
	ct := layers.CheckType{}
	gd := args
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

	params, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		logger.Debug(err.Error())
		return nil, false, err
	}

	flag := util.RandLowLetterNumber(8)
	reverse := reverse2.NewReverse1(config.CeyeDomain, flag)
	_reverse := reverse.(*reverse2.Reverse1)
	payloads := params.SetPayloads(Param.Url, _reverse.Url, Param.Method)
	logger.Debug("%v", payloads)

	if strings.ToUpper(Param.Method) == "POST" {
		for _, body := range payloads {

			req1, resp1, errs := sess.Post(Param.Url, Param.Headers, []byte(body))
			if errs != nil {
				return nil, false, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle",
					Param.Hostid, string(plugin.Ssrf))
				gd.Alert(Result)
				return Result, true, errs
			}
		}
		return nil, false, errors.New("params errors")
	} else {
		for _, uri := range payloads {
			req1, resp1, errs := sess.Get(uri, Param.Headers)
			if errs != nil {
				return nil, false, errs
			}
			r1 := resp1.Body()
			if reverse2.ReverseCheck(reverse, 5) {
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					"ssrf Vulnerable",
					[]string{string(req1.String())},
					[]string{string(r1)},
					"middle",
					Param.Hostid, string(plugin.Ssrf))
				gd.Alert(Result)
				return Result, true, errs
			}
		}
	}

	return nil, false, errors.New("params errors")
}
