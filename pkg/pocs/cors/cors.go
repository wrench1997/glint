package cors

import (
	"bufio"
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

var DefaultProxy = ""
var cert string
var mkey string

func cors_header_in_response(headers map[string]string) bool {
	var cors_headers = []string{
		"Access-Control-Allow-Origin",
		"Access-Control-Expose-Headers",
		"Access-Control-Max-Age",
		"Access-Control-Allow-Credentials",
		"Access-Control-Allow-Methods",
		"Access-Control-Allow-Headers"}

	for _, v := range cors_headers {
		if _, ok := headers[v]; ok {
			return true
		}
	}
	return false
}

// make http request, return true if origin accepted
func origin_accepted(Param layers.PluginParam, baseorigin string) (bool, *fasthttp.Request, *fasthttp.Response, error) {
	util.Setup()
	Origin := baseorigin
	cert = Param.Cert
	mkey = Param.CertKey
	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       time.Duration(Param.Timeout) * time.Second,
			RetryTimes:    Param.MaxRedirectTimes,
			AllowRedirect: false,
			Proxy:         Param.UpProxy,
			Cert:          Param.Cert,
			PrivateKey:    Param.CertKey,
		})
	//headers := make(map[string]string)
	headers := Param.Headers
	req1, resp1, errs := sess.Get(Param.Url, headers)
	if errs != nil {
		logger.Error("error %v", errs.Error())
		return false, nil, nil, errs
	}

	response, err := http.ReadResponse(bufio.NewReader(strings.NewReader(resp1.String())), nil)
	if err != nil {
		return false, nil, nil, errs
	}
	if response.Header.Get("Access-Control-Allow-Origin") == Origin ||
		response.Header.Get("Access-Control-Allow-Origin") == "null" ||
		response.Header.Get("Access-Control-Allow-Credentials") == "true" {
		return true, req1, resp1, nil
	}

	return false, nil, nil, errs
}

type cors_payload struct {
	origin string
	uri    string
	msg    string
}

func Cors_Valid(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	// var blastIters interface{}
	util.Setup()
	//group := args.(plugin.GroupData)
	var Param layers.PluginParam
	ct := layers.CheckType{}
	ct.IsMultipleUrls = false
	gd := args
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       time.Duration(Param.Timeout) * time.Second,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	if _, ok := Param.Headers["Origin"]; !ok {
		return nil, false, errors.New("not found cors")
	}

	if !strings.HasSuffix(Param.Url, "/") {
		Param.Url = Param.Url + "/"
	}

	u, err := url.Parse(Param.Url)
	if err != nil {
		panic(err)
	}

	baseOrigin := u.Scheme + "://" + u.Hostname()
	hostname := u.Hostname()
	baseHost := u.Host
	if ok, _, _, _ := origin_accepted(Param, baseOrigin); ok {
		CorsPayloads := []cors_payload{
			// reflected origin
			{
				origin: "origin",
				uri:    "https://www.evil.com",
				msg:    "Any origin is accepted (Blindly reflect the Origin header value in Access-Control-Allow-Origin headers in responses)"},
			// prefix origin
			{
				origin: "origin",
				uri:    "https://" + baseHost + ".evil.com",
				msg:    "Prefix origins are accepted (www.example.com trusts example.com.evil.com)"},
			{
				origin: "origin",
				uri:    "https://" + hostname + ".evil.com",
				msg:    "Prefix origins are accepted (www.example.com trusts example.com.evil.com)"},
			// suffix origin
			{
				origin: "origin",
				uri:    "https://evil" + baseHost,
				msg:    "Suffix origins are accepted (www.example.com trusts evilexample.com)"},
			{
				origin: "origin",
				uri:    "https://evil" + hostname,
				msg:    "Suffix origins are accepted (www.example.com trusts evilexample.com)"},
			// null origin
			{
				origin: "null",
				msg:    "null origin is accepted"},
			// substring origin
			{
				origin: "origin",
				uri:    "https://" + hostname[:len(hostname)-1],
				msg:    "Origin is validated via Substring match (wwww.example.com trusts example.co)"},
			{
				origin: "origin",
				uri:    "https://" + baseHost[:len(baseHost)-1],
				msg:    "Origin is validated via Substring match (wwww.example.com trusts example.co)"},
			//subdomains origin
			{
				origin: "origin",
				uri:    "https://" + util.RandLetterNumbers(8) + "." + baseHost,
				msg:    "Any subdomains are accepted as a valid origin (An XSS vulnerability in a subdomain could steal the parent domain secrets)"},
			{
				origin: "origin",
				uri:    "https://" + util.RandLetterNumbers(8) + "." + hostname,
				msg:    "Any subdomains are accepted as a valid origin (An XSS vulnerability in a subdomain could steal the parent domain secrets)"},
			// non-ssl origin
			{
				origin: "origin",
				uri:    "http://" + baseHost,
				msg:    "An HTTP (non-ssl) origin is allowed access to a HTTPS resource, allows MitM to break encryption."},
		}

		known_domains := []string{
			"localhost",
			"127.0.0.1",
			"jsbin.com",
			"codepen.io",
			"jsfiddle.net",
			"plnkr.co",
			"s3.amazonaws.com",
		}

		for _, domain := range known_domains {
			CorsPayloads = append(CorsPayloads,
				cors_payload{
					origin: "origin",
					uri:    "https://" + domain,
					msg:    "Origin accepted from a known domain."},
			)
		}

		for _, v := range CorsPayloads {
			if ok, req1, resp1, _ := origin_accepted(Param, v.origin); ok {

				defer req1.Reset()
				defer req1.ResetBody()
				defer resp1.Reset()
				defer resp1.ResetBody()

				body := resp1.String()
				Result := util.VulnerableTcpOrUdpResult(Param.Url,
					v.msg,
					[]string{string(req1.String())},
					[]string{string(body)},
					"medium",
					Param.Hostid, string(plugin.CORS))
				gd.Alert(Result)
				return Result, true, err
			}
		}

	}

	return nil, false, errors.New("not found cors")
}
