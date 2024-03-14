package layers

import (
	"context"
	"encoding/json"
	"glint/config"
	"glint/logger"
	"glint/nenet"
	"glint/plugin"
	"glint/util"
	"strconv"
	"sync"
	"time"
)

type PluginParam struct {
	Ctx                 *context.Context
	Url                 string
	Method              string
	Headers             map[string]string
	Body                string
	TaskConfig          config.TaskConfig
	Cert                string
	CertKey             string
	Timeout             int64
	Hostid              int64
	UpProxy             string
	ContentType         string
	MaxRedirectTimes    int64 //最大重定向次数
	ResponseSize        int64
	Anti_chain_platform string
	Api_token           string
	PageState           util.PageState
	Session             map[string]interface{}
	Rate                *util.Rate
}

type CheckType struct {
	Urlindex       int  //传递url的位置
	IsMultipleUrls bool //是否一次检测多个url
}

func (p *PluginParam) ParsePluginParams(group *plugin.GroupData, ct CheckType) {
	var err error
	var m sync.Mutex
	m.Lock()
	defer m.Unlock()

	if p.Session == nil {
		p.Session = make(map[string]interface{}, 0)
	}

	if !ct.IsMultipleUrls {

		for k, v := range group.UrlInfo {
			p.Session[k] = v
		}

	} else {
		for k, v := range group.GroupUrls[ct.Urlindex].(map[string]interface{}) {
			p.Session[k] = v
		}

	}
	p.Url = p.Session["url"].(string)
	p.Method = p.Session["method"].(string)
	if value, ok := p.Session["headers"]; ok {
		if v, ok := value.(map[string]interface{}); ok {
			p.Headers, err = util.ConvertHeaders(v)
		} else {
			p.Headers["host"] = p.Url
		}
	} else {
		p.Headers = make(map[string]string)
		p.Headers["host"] = p.Url
	}

	if err != nil {
		logger.Error(err.Error())
	}
	p.Body = p.Session["data"].(string)

	if value, ok := p.Session["hostid"].(int64); ok {
		p.Hostid = value
	}

	if value, ok := p.Session["hostid"].(json.Number); ok {
		p.Hostid, _ = value.Int64()
	}

	if value, ok := p.Headers["Content-Type"]; ok {
		p.ContentType = value
	}

	if value, ok := p.Session["pagestate"].(util.PageState); ok {
		p.PageState = value
	}

	p.Ctx = group.Pctx
	p.TaskConfig.Json = group.Config.Json

	p.TaskConfig.Yaml = group.Config.Yaml
	p.TaskConfig.Yaml.ExtraHeaders, _ = util.CopyMapif(group.Config.Yaml.ExtraHeaders)
	p.TaskConfig.Yaml.CustomFormValues, _ = util.CopyMapif(group.Config.Yaml.CustomFormValues)
	p.TaskConfig.Yaml.CustomFormKeywordValues, _ = util.CopyMapif(group.Config.Yaml.CustomFormKeywordValues)
	p.TaskConfig.Yaml.XssPayloads, _ = util.CopyMapif(group.Config.Yaml.XssPayloads)

	p.TaskConfig.JsonOrYaml = group.Config.JsonOrYaml
	p.Cert = group.HttpsCert
	p.CertKey = group.HttpsCertKey
	if !group.Config.JsonOrYaml {
		p.UpProxy = group.Config.Json.Exweb_scan_param.Http_proxy
		//p.Timeout, _ = group.Config.Json.Exweb_scan_param.Http_response_timeout.Int64()
		p.Timeout = 15
	} else {
		p.UpProxy = group.Config.Yaml.Proxy
		p.Timeout = 15
	}

	RMaxRedirectTimes, err := p.TaskConfig.GetValue("Max_redirect_times")
	if err != nil {
		logger.Error(err.Error())
	}

	if p.TaskConfig.JsonOrYaml {
		o := RMaxRedirectTimes.Int()
		p.MaxRedirectTimes = o
	} else {

		o, err := strconv.Atoi(RMaxRedirectTimes.String())
		if err != nil {
			logger.Error("error RMaxRedirectTimes %s", err.Error())
		}
		p.MaxRedirectTimes = int64(o)
	}

	//RMRDTT, err := strconv.Atoi(RMRDTS)

	// if err != nil {
	// 	logger.Error("error RMaxRedirectTimes %s", err.Error())
	// }

	ResponseSize, err := p.TaskConfig.GetValue("Response_Size")
	if err != nil {
		logger.Error(err.Error())
	}
	if p.TaskConfig.JsonOrYaml {
		o := ResponseSize.Int()
		p.ResponseSize = o
	} else {
		o, err := strconv.Atoi(ResponseSize.String())
		if err != nil {
			logger.Error("error RMaxRedirectTimes %s", err.Error())
		}
		p.ResponseSize = int64(o)
	}

	p.Rate = group.Rate
	// p.Headers =

	//RPST, err := strconv.Atoi(RPSS)

	// if err != nil {
	// 	logger.Error("error RPSS %s", err.Error())
	// }
	// Anti_chain_platform, err := p.TaskConfig.GetValue("Anti_chain_platform")
	// if err != nil {
	// 	logger.Error(err.Error())
	// }
	// p.Anti_chain_platform = Anti_chain_platform.String()

	// Api_token, err := p.TaskConfig.GetValue("Api_token")
	// if err != nil {
	// 	logger.Error(err.Error())
	// }
	// p.Api_token = Api_token.String()

}

func (p *PluginParam) CheckForExitSignal() bool {
	select {
	case <-(*p.Ctx).Done():
		return true
	default:
	}
	return false
}

func (p *PluginParam) GenerateVariable() (*util.Variations, error) {

	// variations,err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := p.Headers["Content-Type"]; ok {
		p.ContentType = value
	}
	variations, err := util.ParseUri(p.Url, []byte(p.Body), p.Method, p.ContentType, p.Headers)
	return variations, err
}

func (p *PluginParam) GenerateSession() (*nenet.Session, error) {
	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       time.Duration(p.Timeout) * time.Second,
			RetryTimes:    p.MaxRedirectTimes,
			AllowRedirect: true,
			Proxy:         p.UpProxy,
			Cert:          p.Cert,
			PrivateKey:    p.CertKey,
		})
	return sess, nil
}
