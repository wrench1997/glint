package layers

import (
	"glint/ast"
	"glint/logger"
	"glint/nenet"
	"glint/util"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
)

type Plreq struct {
	Sess        *nenet.Session
	Method      string
	Headers     map[string]string
	Body        []byte
	ContentType string
	Index       int
}

type IdxVariable struct {
	Idx      int
	Variable string
	Flag     string
}

type Scheme struct {
	Path string
}

type LastJob struct {
	Layer            Plreq
	Features         *MFeatures
	ResponseDuration time.Duration
	Isencode         bool
}

type MFeatures struct {
	Index    int
	Request  fasthttp.Request
	Response fasthttp.Response
}

func (m *MFeatures) Clear() {

	m.Request.Reset()
	m.Request.ResetBody()
	m.Response.Reset()
	m.Response.ResetBody()
}

func (P *LastJob) Clear(args PluginParam) {
	if P.Features != nil {
		P.Features.Clear()
	}
}

func (P *LastJob) Init(args PluginParam) {
	util.Setup()
	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       15 * time.Second,
			AllowRedirect: true,
			Proxy:         args.UpProxy,
			Cert:          args.Cert,
			PrivateKey:    args.CertKey,
			RetryTimes:    args.MaxRedirectTimes,
		})
	P.Layer.Sess = sess
	P.Layer.Headers = make(map[string]string, 0)
}

// func (P *LastJob) RequestAll(originUrl string, paramValue string) ([]*MFeatures, error) {
// 	var features []MFeatures
// 	origin, err := util.ParseUri(originUrl, P.Layer.Body, P.Layer.Method, P.Layer.ContentType, P.Layer.Headers)
// 	if err != nil {
// 		logger.Debug("Plreq request error: %v", err)
// 	}
// 	originpayloads := origin.SetPayload(originUrl, paramValue, P.Layer.Method)
// 	if strings.ToUpper(P.Layer.Method) == "POST" {
// 		for i, v := range originpayloads {
// 			opl := util.Str2Byte(v)
// 			req, resp, err := P.Layer.Sess.Post(&originUrl, &P.Layer.Headers, &opl)
// 			if err != nil {
// 				logger.Debug("Plreq request error: %v", err)
// 				return nil, err
// 			}
// 			f := new(MFeatures)
// 			f.Index = i
// 			f.Request = *req
// 			f.Response = *resp
// 			features = append(features, *f)
// 		}
// 	} else if strings.ToUpper(P.Layer.Method) == "GET" {
// 		for i, v := range originpayloads {
// 			req, resp, err := P.Layer.Sess.Get(&v, &P.Layer.Headers)
// 			if err != nil {
// 				logger.Debug("Plreq request error: %v", err)
// 				return nil, err
// 			}
// 			f := new(MFeatures)
// 			f.Index = i
// 			req.CopyTo(&f.Request)
// 			resp.CopyTo(&f.Response)
// 			P.Features = f
// 			features = append(features, *f)
// 		}
// 	}
// 	return features, nil
// }

func (P *LastJob) RequestByIndexs(ivs []IdxVariable, originUrl string, o ...map[string]string) (*MFeatures, error) {
	var feature MFeatures
	var Timeout int
	var err error
	var originpayload string
	// defer feature.Clear()
	for _, option := range o {
		if value, ok := option["timeout"]; ok {
			Timeout, err = strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			P.Layer.Sess.Timeout = time.Duration(Timeout) * time.Second
		}
	}

	origin, err := util.ParseUri(originUrl, P.Layer.Body, P.Layer.Method, P.Layer.ContentType, P.Layer.Headers)
	if err != nil {
		return &feature, err
	}

	for _, pidxv := range ivs {
		originpayload = origin.SetPayloadByindex_noReset(pidxv.Idx, originUrl, pidxv.Variable, P.Layer.Method)
	}

	t1pre := time.Now()

	defer func(t time.Time) {
		t1post := time.Since(t)
		P.ResponseDuration = t1post
	}(t1pre)
	if strings.ToUpper(P.Layer.Method) == "POST" {
		//opl := util.Str2Byte(originpayload)
		req, resp, err := P.Layer.Sess.Post(originUrl, P.Layer.Headers, []byte(originpayload))
		if err != nil {
			logger.Debug("Plreq request error: %v", err)
			if req != nil {
				req.Reset()
				req.ResetBody()
			}
			if resp != nil {
				resp.Reset()
				resp.ResetBody()
			}
			return &feature, err
		}

		//feature.Index = idx
		req.CopyTo(&feature.Request)
		resp.CopyTo(&feature.Response)
		P.Features = &feature

	} else if strings.ToUpper(P.Layer.Method) == "GET" {

		req, resp, err := P.Layer.Sess.Get(originpayload, P.Layer.Headers)
		if err != nil {
			logger.Debug("Plreq request error: %v", err)
			if req != nil {
				req.Reset()
				req.ResetBody()
			}
			if resp != nil {
				resp.Reset()
				resp.ResetBody()
			}

			return &feature, err
		}
		req.CopyTo(&feature.Request)
		resp.CopyTo(&feature.Response)
		P.Features = &feature
	}

	return &feature, nil
}

func (P *LastJob) RequestByIndex(idx int, originUrl string, paramValue []byte, o ...map[string]string) (*MFeatures, error) {
	var (
		feature       MFeatures
		Timeout       int
		err           error
		isencode      string
		filename      string
		contenttype   string
		escapeValue   string
		originpayload string
		//is_the_bytefilename string
		// ValueType     string
	)
	// defer feature.Clear()
	for _, option := range o {
		if value, ok := option["timeout"]; ok {
			Timeout, err = strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			P.Layer.Sess.Timeout = time.Duration(Timeout) * time.Second
		}
		if value, ok := option["encode"]; ok {
			isencode = value
		}
		if value, ok := option["filename"]; ok {
			filename = value
		}
		if value, ok := option["contenttype"]; ok {
			contenttype = value
		}

		// if value, ok := option["is_the_bytefilename"]; ok {
		// 	is_the_bytefilename = value
		// }

		// if value, ok := option["ValueType"]; ok {
		// 	isBase64 = value
		// }

	}

	origin, err := util.ParseUri(originUrl, P.Layer.Body, P.Layer.Method, P.Layer.ContentType, P.Layer.Headers)
	if err != nil {
		return nil, err
	}
	//设置文件名和文件属性
	if filename != "" {
		for idx, v := range origin.Params {
			if v.IsFile {
				origin.Params[idx].Filename = filename
				origin.Params[idx].ContentType = contenttype
			}
		}
	}
	//url编码
	if !strings.EqualFold(isencode, "encode") {
		escapeValue = string(paramValue)
	} else {
		escapeValue = url.QueryEscape(string(paramValue))
	}

	originpayload = origin.SetPayloadByindex(idx, originUrl, escapeValue, P.Layer.Method)

	// if strings.EqualFold(is_the_bytefilename, "yes") {

	// }

	t1pre := time.Now()

	defer func(t time.Time) {
		t1post := time.Since(t)
		P.ResponseDuration = t1post
	}(t1pre)
	if strings.ToUpper(P.Layer.Method) == "POST" {
		req, resp, err := P.Layer.Sess.Post(originUrl, P.Layer.Headers, []byte(originpayload))
		if err != nil {
			logger.Debug("Plreq request error: %v", err)
			return nil, err
		}

		feature.Index = idx
		req.CopyTo(&feature.Request)
		resp.CopyTo(&feature.Response)
		P.Features = &feature

	} else if strings.ToUpper(P.Layer.Method) == "GET" {

		req, resp, err := P.Layer.Sess.Get(originpayload, P.Layer.Headers)
		if err != nil {
			logger.Debug("Plreq request error: %v", err)
			return nil, err
		}

		defer req.ResetBody()
		defer req.Reset()
		defer resp.ResetBody()
		defer resp.Reset()

		feature.Index = idx
		req.CopyTo(&feature.Request)
		resp.CopyTo(&feature.Response)
		P.Features = &feature
	}

	return &feature, nil
}

// *[]MFeatures
func CompareFeatures(src []*MFeatures, dst []*MFeatures) bool {
	parse1 := ast.Parser{}
	parse2 := ast.Parser{}
	defer parse1.Clear()
	defer parse2.Clear()
	var isEquivalent bool
	if len(src) != len(dst) {
		return false
	}
	isEquivalent = true

	for _, s := range src {
		for _, d := range dst {
			if s != nil && d != nil {
				if s.Index == d.Index {

					body1 := s.Response.String()
					parse1.HttpParser(&body1)
					s_tokens := parse1.GetRoot()

					// defer s.Response.Reset()

					body2 := d.Response.String()
					parse2.HttpParser(&body2)
					d_tokens := parse2.GetRoot()

					// defer d.Response.Reset()

					// if len(s_tokens) == 0 || len(d_tokens) == 0 {
					// 	// logger.Error("SearchInputInResponse tokens 没有发现节点")
					// 	return false
					// }

					if s_tokens.Length() != d_tokens.Length() {
						// logger.Error("SearchInputInResponse tokens 没有发现节点")
						return false
					}

					for i := 0; i < s_tokens.Length(); i++ {
						st := s_tokens.Children[i]
						dt := d_tokens.Children[i]
						if st.Value.Tagname != dt.Value.Tagname {
							isEquivalent = false
						} else {
							if st.Value.Content != dt.Value.Content {
								isEquivalent = false
							}
						}
					}

				}
			}

		}
	}

	return isEquivalent
}
