package util

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"glint/logger"
	"glint/proto"

	// "github.com/jweny/pocassist/pkg/cel/proto"
	// "github.com/jweny/pocassist/pkg/conf"
	// log "github.com/jweny/pocassist/pkg/logging"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	// "github.com/jweny/pocassist/pkg/conf"
	// "github.com/jweny/pocassist/pkg/conf"

	"github.com/valyala/fasthttp"
	"golang.org/x/time/rate"
)

type NetworkManager struct {
	requestid   uint64        //请求id
	createdTime time.Duration //创建时间
	qps         uint          //每毫秒秒最大连接数
}

type Rate struct {
	Limiter *rate.Limiter //速率
	//index   uint64        //请求数或者叫请求ID，同一个任务逐渐递增，
	QPS  uint         //每毫秒秒最大连接数
	lock sync.RWMutex //读写锁
}

func (r *Rate) InitRate(QPS uint) {
	//这个只有uint才是测试准确的，换int强制转换测试时间会有偏差
	r.Limiter = rate.NewLimiter(rate.Limit(QPS), 1)
}

func (r *Rate) LimitWait() {
	r.lock.RLock()
	defer r.lock.RUnlock()
	r.Limiter.Wait(context.Background())
}

// func (r *Rate) GetTokens() float64 {
// 	rate := r.Limiter.Reserve()
// 	if !rate.OK() {

// 	}
// 	return r.Limiter.Tokens()
// }

func (r *Rate) Reset() {
	r.lock.RLock()
	defer r.lock.RUnlock()
	//r.index = 0
}

func (r *Rate) Allow() bool {
	return r.Limiter.Allow()
}

type clientDoer interface {
	// 不跟随重定向
	DoTimeout(req *fasthttp.Request, resp *fasthttp.Response, t time.Duration) error
	// 跟随重定向
	DoRedirects(req *fasthttp.Request, resp *fasthttp.Response, maxRedirectsCount int) error
}

var (
	fasthttpClient clientDoer
)

var (
	requestPool sync.Pool = sync.Pool{
		New: func() interface{} {
			return new(proto.Request)
		},
	}

	responsePool sync.Pool = sync.Pool{
		New: func() interface{} {
			return new(proto.Response)
		},
	}

	formatPool sync.Pool = sync.Pool{
		New: func() interface{} {
			return new(FormatString)
		},
	}
)

type FormatString struct {
	Raw string `json:"raw"`
}

type ReqFormat struct {
	Req *fasthttp.Request
}

type RespFormat struct {
	Resp *fasthttp.Response
}

// Return value if nonempty, def otherwise.
func valueOrDefault(value, def string) string {
	if value != "" {
		return value
	}
	return def
}

// dump 请求报文
func (r *ReqFormat) FormatContent() string {
	reqRaw := formatPool.Get().(*FormatString)
	defer formatPut(reqRaw)
	req := r.Req
	if req == nil {
		return ""
	}
	// fasthttp 请求打印的第一行长这样
	// GET http://jweny.top/ HTTP/1.1
	// 处理下
	tmpList := strings.SplitN(string(req.Header.Header()), "\r\n", 2)

	reqURI := req.URI().RequestURI()
	protocol := string(req.Header.Protocol())
	body := ""
	if len(r.Req.Body()) > 0 {
		body = string(r.Req.Body())
	}

	line1 := fmt.Sprintf("%s %s %s\r\n", valueOrDefault(string(req.Header.Method()), "GET"),
		reqURI, protocol)
	line2 := ""
	// 避免打印的 Host 头重复
	if !strings.Contains(tmpList[1], "Host:") {
		line2 = fmt.Sprintf("%s: %s\r\n", "Host", string(req.Host()))
	}
	requestRaw := line1 + line2 + tmpList[1] + body
	return requestRaw
}

// dump 响应报文
func (r *RespFormat) FormatContent() string {
	respRaw := formatPool.Get().(*FormatString)
	defer formatPut(respRaw)
	header := r.Resp.Header.String()
	body := ""
	if len(r.Resp.Body()) > 0 {
		body = string(r.Resp.Body())
	}
	responseRaw := header + body
	return responseRaw
}

func formatPut(f *FormatString) {
	if f == nil {
		return
	}
	f.Raw = ""
	formatPool.Put(f)
}

func RequestGet() *proto.Request {
	return requestPool.Get().(*proto.Request)
}

func RequestPut(r *proto.Request) {
	if r == nil {
		return
	}
	r.Reset()
	requestPool.Put(r)
}

func RespGet() *proto.Response {
	return responsePool.Get().(*proto.Response)
}

func ResponsePut(resp *proto.Response) {
	if resp == nil {
		return
	}
	resp.Reset()
	responsePool.Put(resp)
}

func ResponsesPut(responses []*proto.Response) {
	for _, item := range responses {
		ResponsePut(item)
	}
}

func ParseUrl(u *url.URL) *proto.UrlType {
	nu := &proto.UrlType{}
	nu.Scheme = u.Scheme
	nu.Domain = u.Hostname()
	nu.Host = u.Host
	nu.Port = u.Port()
	nu.Path = u.EscapedPath()
	nu.Query = u.RawQuery
	nu.Fragment = u.Fragment
	return nu
}

func ParseFasthttpResponse(originalResp *fasthttp.Response, req *fasthttp.Request) (*proto.Response, error) {
	resp := RespGet()
	header := make(map[string]string)
	resp.Status = int32(originalResp.StatusCode())
	u, err := url.Parse(req.URI().String())
	if err != nil {
		logger.Fatal("util/requests.go:ParseFasthttpResponse url parse error", req.URI().String(), err)
		return nil, err
	}
	resp.Url = ParseUrl(u)

	headerContent := originalResp.Header.String()
	headers := strings.Split(headerContent, "\r\n")
	for _, v := range headers {
		// 修复bug: 限制切割次数
		values := strings.SplitN(v, ":", 2)
		if len(values) != 2 {
			continue
		}
		// 修复bug 所有响应头 key 均转为小写（与xray兼容）
		k := strings.ToLower(values[0])
		// 修复bug 所有响应头 value去除左边空格
		v := strings.TrimLeft(values[1], " ")
		// 修复bug 处理响应头 中多个相同的key 产生的覆盖问题
		if header[k] != "" {
			header[k] += v
		} else {
			header[k] = v
		}
	}
	resp.Headers = header
	resp.ContentType = string(originalResp.Header.Peek("Content-Type"))

	resp.Body = make([]byte, len(originalResp.Body()))
	copy(resp.Body, originalResp.Body())
	return resp, nil
}

func DoFasthttpRequest(req *fasthttp.Request, redirect bool) (*proto.Response, error) {
	//RRate.LimitWait()
	defer fasthttp.ReleaseRequest(req)
	bodyLen := len(req.Body())
	if bodyLen > 0 {
		req.Header.Set("Content-Length", strconv.Itoa(bodyLen))
		if string(req.Header.Peek("Content-Type")) == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	var err error

	if redirect {
		// 跟随重定向 最大跳转数从conf中加载
		maxRedirects := 5
		err = fasthttpClient.DoRedirects(req, resp, maxRedirects)
	} else {
		// 不跟随重定向
		timeout := 5
		err = fasthttpClient.DoTimeout(req, resp, time.Duration(timeout)*time.Second)
	}
	if err != nil {
		logger.Fatal("util/requests.go:DoFasthttpRequest fasthttp client doRequest error", string(req.RequestURI()), err)
		return nil, err
	}

	// 处理响应 body: gzip deflate 解包
	fixBody, err := UnzipResponseBody(resp)
	if err != nil {
		logger.Fatal("util/requests.go:DoFasthttpRequest fasthttp client dealResponseBody error", string(req.RequestURI()), err)
		return nil, err
	}
	resp.SetBody(fixBody)
	curResp, err := ParseFasthttpResponse(resp, req)
	// 添加请求和响应报文
	if err != nil {
		return nil, err
	}

	f := RespFormat{
		Resp: resp,
	}
	curResp.RespRaw = f.FormatContent()

	reqf := ReqFormat{
		Req: req,
	}
	curResp.ReqRaw = reqf.FormatContent()
	return curResp, err
}

func UrlTypeToString(u *proto.UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

func CopyRequest(req *http.Request, dstRequest *fasthttp.Request, data []byte) error {

	curURL := req.URL.String()
	dstRequest.SetRequestURI(curURL)
	dstRequest.Header.SetMethod(req.Method)

	for name, values := range req.Header {
		// Loop over all values for the name.
		for index, value := range values {
			if index > 0 {
				dstRequest.Header.Add(name, value)
			} else {
				dstRequest.Header.Set(name, value)
			}
		}
	}
	dstRequest.SetBodyRaw(data)
	return nil
}

// UnzipResponseBody 返回解压缩的 Body : 目前支持 identity gzip deflate
func UnzipResponseBody(response *fasthttp.Response) ([]byte, error) {
	contentEncoding := strings.ToLower(string(response.Header.Peek("Content-Encoding")))
	var body []byte
	var err error
	switch contentEncoding {
	case "", "none", "identity":
		body, err = response.Body(), nil
	case "gzip":
		body, err = response.BodyGunzip()
	case "deflate":
		body, err = response.BodyInflate()
	case "br":
		body, err = response.BodyUnbrotli()
	default:
		body, err = []byte{}, fmt.Errorf("unsupported Content-Encoding: %v", contentEncoding)
	}
	return body, err
}

func VerifyPortConnection(targetAddr string) bool {
	_, err := TcpSend(targetAddr, nil)
	if err != nil {
		return false
	}
	return true
}

// 以后接被动扫描插件的时候用
//func VerifyTargetConnection(originalReq *http.Request) bool {
//	fastReq := fasthttp.AcquireRequest()
//	fastResp := fasthttp.AcquireResponse()
//	oriData, err := GetOriginalReqBody(originalReq)
//	if err != nil {
//		return false
//	}
//	err = CopyRequest(originalReq, fastReq, oriData)
//	if err != nil {
//		return false
//	}
//	timeout := conf.GlobalConfig.HttpConfig.HttpTimeout
//	// 检测原始请求
//	err = fasthttpClient.DoTimeout(fastReq, fastResp, time.Duration(timeout)*time.Second)
//	if err != nil {
//		// 检测原始请求 + index.php
//		uri := string(fastReq.RequestURI())
//		if uri != "" && strings.HasSuffix(uri, "/") {
//			uri = fmt.Sprint(uri, "index.php")
//		} else {
//			uri = fmt.Sprint(uri, "/index.php")
//		}
//		fastReq.SetRequestURI(uri)
//		err = fasthttpClient.DoTimeout(fastReq, fastResp, time.Duration(timeout)*time.Second)
//		if err != nil {
//			return false
//		}
//	}
//	return true
//}

func VerifyInputTarget(target string) (bool, string) {
	// 连通性校验改到这里
	// 1.不带https/http协议 && 不带端口：放弃检查(icmp限制太多)
	// 2.带端口：tcp 端口
	// 3.带https/http协议不带端口：tcp 80/443
	// 生成原始请求
	verify := true
	// 有端口
	if len(strings.Split(target, ":")) > 1 {
		// 带端口
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {

		} else {
			target = "http://" + target
		}
	} else {
		// 不带端口
		if strings.HasPrefix(target, "http://") {
			//	输入 http
			verify = VerifyPortConnection(net.JoinHostPort(target, "80"))
		} else if strings.HasPrefix(target, "https://") {
			// 输入 https
			verify = VerifyPortConnection(net.JoinHostPort(target, "443"))
		} else {
			// 不校验
			target = "http://" + target
		}
	}
	return verify, target
}

func GenOriginalReq(target string) (*http.Request, error) {
	verify, fixTarget := VerifyInputTarget(target)
	if !verify {
		errMsg := fmt.Errorf("util/requests.go:GenOriginalReq %s can not connect", target)
		logger.Fatal(errMsg.Error())
		return nil, errMsg
	}
	originalReq, err := http.NewRequest("GET", fixTarget, nil)
	if err != nil {
		errMsg := fmt.Errorf("util/requests.go:GenOriginalReq %s original request gen error %v", target, err)
		logger.Fatal(errMsg.Error())
		return nil, errMsg
	}
	originalReq.Header.Set("Host", originalReq.Host)
	originalReq.Header.Set("Accept-Encoding", "gzip, deflate")
	originalReq.Header.Set("Accept", "*/*")
	originalReq.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.54 Safari/537.36")
	originalReq.Header.Set("Accept-Language", "en")
	originalReq.Header.Set("Connection", "close")
	return originalReq, nil
}

func GetOriginalReqBody(originalReq *http.Request) ([]byte, error) {
	var data []byte
	if originalReq.Body != nil && originalReq.Body != http.NoBody {
		data, err := ioutil.ReadAll(originalReq.Body)
		if err != nil {
			return nil, err
		}
		originalReq.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}
	return data, nil
}

func DealMultipart(contentType string, ruleBody string) (result string, err error) {
	errMsg := ""
	// 处理multipart的/n
	re := regexp.MustCompile(`(?m)multipart\/form-Data; boundary=(.*)`)
	match := re.FindStringSubmatch(contentType)
	if len(match) != 2 {
		errMsg = "no boundary in content-type"
		//logging.GlobalLogger.Error("util/requests.go:DealMultipart Err", errMsg)
		return "", errors.New(errMsg)
	}
	boundary := "--" + match[1]
	multiPartContent := ""

	// 处理rule
	multiFile := strings.Split(ruleBody, boundary)
	if len(multiFile) == 0 {
		errMsg = "ruleBody.Body multi content format err"
		//logging.GlobalLogger.Error("util/requests.go:DealMultipart Err", errMsg)
		return multiPartContent, errors.New(errMsg)
	}

	for _, singleFile := range multiFile {
		//	处理单个文件
		//	文件头和文件响应
		spliteTmp := strings.Split(singleFile, "\n\n")
		if len(spliteTmp) == 2 {
			fileHeader := spliteTmp[0]
			fileBody := spliteTmp[1]
			fileHeader = strings.Replace(fileHeader, "\n", "\r\n", -1)
			multiPartContent += boundary + fileHeader + "\r\n\r\n" + strings.TrimRight(fileBody, "\n") + "\r\n"
		}
	}
	multiPartContent += boundary + "--" + "\r\n"
	return multiPartContent, nil
}
