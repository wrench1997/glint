package nenet

//这个包主要封装管理浏览器发包
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	ast "glint/ast"
	"glint/config"
	"glint/logger"
	"glint/util"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/har"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
)

type nvPair har.NameValuePair
type hRequest har.Request
type hResponse har.Response

var start = time.Now()

// Headers_IMPORTMENT
var headers_importment = []string{
	"Accept",
	"Content-Type",
	"Cookie",
	"Origin",
	"Referer",
	"Upgrade-Insecure-Requests",
	"User-Agent",
}

// Spider 爬虫资源，设计目的是基于浏览器发送payload，注意使用此结构的函数在多线程中没上锁是不安全的，理想状态为一条线程使用这个结构
type Spider struct {
	Ctx        *context.Context //存储着浏览器的资源
	Cancel     *context.CancelFunc
	TabTimeOut int64
	TaskCtx    *context.Context //存储着任务上下文
	Ratelimite *util.Rate
}

type RWCount struct {
	count int
	mu    sync.RWMutex
}

func (r *RWCount) Get() int {
	r.mu.Lock()
	count := r.count
	r.mu.Unlock()
	return count
}

func (r *RWCount) Set(count int) {
	r.mu.Lock()
	r.count = count
	r.mu.Unlock()
}

type myhttpinfo struct {
	HttpRequest  string
	HttpResponse string
}

// 这个Tab几乎代表单线程所以很多情况不是很担心数据抢占的问题。
type Tabs struct {
	TaskCtx             *context.Context //存储着任务上下文
	Ctx                 *context.Context
	Cancel              *context.CancelFunc
	PackCtx             *context.Context
	PackCancel          *context.CancelFunc
	ConsoleAPIResponses chan map[string]string
	stopConsoleAPI      chan struct{}
	ReqMode             string
	PostData            []byte
	Standardlen         int //爬虫请求的长度
	ReqUrlresplen       int
	Sendlimit           RWCount
	Url                 *url.URL
	Headers             map[string]interface{} //请求头
	Isreponse           bool
	Source              chan string //当前爬虫的html的源码
	stopSourceCh        chan struct{}
	RespDone            chan bool
	Reports             []ReportMsg
	mu                  sync.Mutex //
	RequestsStr         string
	Ratelimite          *util.Rate //每秒请求速率
	PackageExitsignal   chan bool
	// EventConsoleAPIBypayloads []string //监听到payload事件来自Console
	payloadflag        string //发送的md5
	Isflagbyconsoleapi chan bool
	IsEncodeUrl        bool
}

type ReportMsg struct {
	RequestID network.RequestID
	Count     int
}

type UrlOCC struct {
	Request ast.JsonUrl
	OCC     []ast.Occurence
}

func (spider *Spider) Close() {
	defer (*spider.Cancel)()
	// defer chromedp.Cancel(*spider.Ctx)
}

func (t *Tabs) Close() {
	defer (*t.Cancel)()
	//defer chromedp.Cancel(*t.Ctx)
}

func (t *Tabs) GetNodeStackTraces(nodeID cdp.NodeID) (creation *runtime.StackTrace, err error) {
	getStackTraces := dom.GetNodeStackTraces(nodeID)
	return getStackTraces.Do(*t.Ctx)
}

func NewTabsOBJ(spider *Spider) (*Tabs, error) {
	var tab Tabs
	ctx, cancel := chromedp.NewContext(*spider.Ctx)
	// logger.Info("set timeout for the tab page : %d second", 20)
	ctx, cancel = context.WithTimeout(ctx, 20*time.Minute)
	tab.Ctx = &ctx
	tab.Cancel = &cancel
	tab.ConsoleAPIResponses = make(chan map[string]string, 1)
	tab.Source = make(chan string, 1)
	tab.RespDone = make(chan bool, 1)
	tab.stopSourceCh = make(chan struct{})
	tab.stopConsoleAPI = make(chan struct{})
	tab.TaskCtx = spider.TaskCtx
	tab.Sendlimit.Set(1) //最大只能发送一次
	tab.Ratelimite = spider.Ratelimite
	tab.PackageExitsignal = make(chan bool, 1)

	return &tab, nil
}

func (t *Tabs) ListenTarget() {
	ConsoleAPIResponse := make(map[string]string, 0)
	//目前有个bug，go 关键字内就是不能用logger模块的日志输出结构体，使用后Listen内部会出现逻辑顺序错乱的情况，怀疑是logger里面的lock锁有关
	chromedp.ListenTarget(*t.PackCtx, func(ev interface{}) {
		//var RequestID network.RequestID
		// logger.Info("%v", reflect.TypeOf(ev))
		switch ev := ev.(type) {
		case *page.EventLoadEventFired:
		case *runtime.EventConsoleAPICalled:
			for _, arg := range ev.Args {
				ConsoleAPIResponse[string(ev.Type)] = strings.ReplaceAll(string(arg.Value), "\"", "")
			}
			go func() {
				select {
				case t.ConsoleAPIResponses <- ConsoleAPIResponse:
				case <-time.After(5 * time.Second):
					return
				}
			}()

		case *runtime.EventExceptionThrown:
		case *dom.EventChildNodeInserted:

		case *fetch.EventRequestPaused:
			go func() {
				c := chromedp.FromContext(*t.PackCtx)
				ctx := cdp.WithExecutor(*t.PackCtx, c.Target)
				// var req *fetch.ContinueRequestParams
				select {
				case <-ctx.Done():
					println("发包超时结束")
					//close(t.PackageExitsignal)
					return
				default:
				}
				req := fetch.ContinueRequest(ev.RequestID)
				// req.URL = spider.Url.String()
				req.Headers = []*fetch.HeaderEntry{}

				//设置文件头
				for key, value := range t.Headers {
					if value != "" {
						//这里只填写重要的header头
						for _, h := range headers_importment {
							if strings.EqualFold(h, key) {
								req.Headers = append(req.Headers, &fetch.HeaderEntry{Name: key, Value: value.(string)})
							}
						}
					}
				}

				if t.ReqMode == "POST" {
					req.Method = "POST"
					req.PostData = base64.StdEncoding.EncodeToString(t.PostData)
				}

				if err := req.Do(ctx); err != nil {
					logger.Debug("fetch.EventRequestPaused Failed to continue request: %v", err)
				}

				// network.GetRequestPostData()
			}()
		case *network.EventRequestWillBeSent:
			//fmt.Println(aurora.Sprintf("EventRequestWillBeSent==>  url: %s requestid: %s", aurora.Red(ev.Request.URL), aurora.Red(ev.RequestID)))
			//重定向

			//logger.Debug("request:%s", string(array))
			//logger.Info("requestid:%s request:%s", req.RequestID, string(array))

			request := ev

			if ev.RedirectResponse != nil {
				logger.Debug("链接 %s: 重定向到: %s", request.RedirectResponse.URL, request.DocumentURL)
			}

		case *network.EventLoadingFinished:
			go func(ev *network.EventLoadingFinished) {
				c := chromedp.FromContext(*t.PackCtx)
				ctx := cdp.WithExecutor(*t.PackCtx, c.Target)
				array, err := network.GetResponseBody(ev.RequestID).Do(ctx)
				if err != nil {
					return
				}
				select {
				case <-t.stopSourceCh:
					return
				case t.Source <- string(array):
				case <-time.After(5 * time.Second):
				}

			}(ev)

		case *network.EventResponseReceived:

		case *page.EventJavascriptDialogOpening:
			logger.Debug("* EventJavascriptDialogOpening.%s call", ev.Type)
			// Response[string(ev.Type)] = strings.ReplaceAll(ev.Message, "\"", "")
			// Responses = append(Responses, Response)
			go func() {
				c := chromedp.FromContext(*t.PackCtx)
				ctx := cdp.WithExecutor(*t.PackCtx, c.Target)
				//关闭弹窗
				page.HandleJavaScriptDialog(false).Do(ctx)
				// t.Responses <- Responses
			}()
		}
	})
}

func (spider *Spider) Init(TaskConfig config.TaskConfig) error {
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-xss-auditor", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("disable-webgl", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		chromedp.UserAgent(`Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36`),
	}
	options = append(chromedp.DefaultExecAllocatorOptions[:], options...)

	Proxy, err := TaskConfig.GetValue("Proxy")
	if err != nil {
		logger.Error("%s", err.Error())
	} else {
		if Proxy.String() != "" {
			options = append(options, chromedp.Flag("proxy-server", Proxy.String()))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*30)
	c, cancel := chromedp.NewExecAllocator(ctx, options...)
	ctx, cancel = chromedp.NewContext(c) // chromedp.WithDebugf(logger.Info)
	spider.Cancel = &cancel
	spider.Ctx = &ctx
	// TabRunTimeout, err := TaskConfig.GetValue("TabRunTimeout")
	// if err != nil {
	// 	if err != nil {
	// 		logger.Error("%s", err.Error())
	// 	}
	// }

	// reType := reflect.TypeOf(i)
	// fmt.Println("reflect.Type=", reType)

	// // 获取变量的 reflect.Value
	// reVal := reflect.ValueOf(i)
	// fmt.Println("reflect.Value=", reVal)

	// sL := TabRunTimeout.String()
	// if sL == "" {
	// 	sL = "5"
	// }
	// to, err := strconv.Atoi(sL)
	// if err != nil {
	// 	panic(err)
	// }
	// iVal := TabRunTimeout.Interface()

	// if jsonv, ok := iVal.(json.Number); ok {
	// 	ijv, err := jsonv.Int64()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	spider.TabTimeOut = int64(time.Duration(ijv) * time.Second)
	// } else {
	// 	spider.TabTimeOut = int64(iVal.(time.Duration) * time.Second)
	// }

	spider.TabTimeOut = 30

	if spider.Ratelimite == nil {
		spider.Ratelimite = &util.Rate{}
		Qps, err := TaskConfig.GetValue("Qps")
		if err != nil {
			panic(err)
		}
		iValQps := Qps.Interface()

		if jsonv, ok := iValQps.(json.Number); ok {
			ijv, err := jsonv.Int64()
			if err != nil {
				panic(err)
			}
			spider.Ratelimite.InitRate(uint(ijv))
			// spider.TabTimeOut = int64(time.Duration(ijv) * time.Second)
		} else {
			//spider.TabTimeOut = int64(iVal.(time.Duration) * time.Second)
			spider.Ratelimite.InitRate(uint(Qps.Int()))
		}

	}

	err = chromedp.Run(
		*spider.Ctx,
		fetch.Enable(),
		network.Enable(),
	)

	return err
}

func (tab *Tabs) GetExecutor() context.Context {
	c := chromedp.FromContext(*tab.Ctx)
	ctx := cdp.WithExecutor(*tab.Ctx, c.Target)
	return ctx
}

func (t *Tabs) newSpiderTab() (context.Context, context.CancelFunc) {
	ctx, cancel := chromedp.NewContext(*t.Ctx)
	return ctx, cancel
}

// Sendreq 发送请求 url为空使用爬虫装载的url
func (t *Tabs) Send() ([]string, string, error) {
	var htmls []string
	var err error
	var tctx context.Context
	var tcancel context.CancelFunc
	var rawUrl string
	//var btimeout bool
	t.Ratelimite.LimitWait()
	t.stopSourceCh = make(chan struct{})
	// time.Sleep(5)
	ctx, cancel := t.newSpiderTab()
	//ctx, cancel = context.WithTimeout(ctx, time.Minute*5)
	defer cancel()
	subtabctx, subtabcancel := context.WithCancel(ctx)
	defer subtabcancel()
	zzctx, zzcancel := context.WithTimeout(subtabctx, time.Second*20)
	defer zzcancel()
	//ctx, cancel = context.WithTimeout(ctx, time.Second*20)
	t.mu.Lock()
	t.PackCtx = &ctx
	t.PackCancel = &cancel
	t.mu.Unlock()

	select {
	case <-(*t.TaskCtx).Done():
		//logger.Warning("xss插件收到任务过期,中断发包")
		(*t.Cancel)()
		(*t.PackCancel)()
		cancel()
		return htmls, "", errors.New("xss error")
	default:

	}

	t.ListenTarget()

	if t.IsEncodeUrl {
		rawUrl = t.Url.String()
	} else {
		// if strings.HasSuffix(t.Url.Hostname(), "/") {
		// 	rawUrl = t.Url.Scheme + "://" + t.Url.Hostname() + t.Url.RequestURI()
		// } else {

		// }

		rawUrl = t.Url.Scheme + "://" + t.Url.Host + t.Url.RequestURI()

	}
	//logger.Info(rawUrl)
	// ACtx, _ := context.WithTimeout(*t.Ctx, time.Second*120)
	var domhtml string
	err = chromedp.Run(
		zzctx,
		fetch.Enable(),
		chromedp.Navigate(rawUrl),
		//chromedp.OuterHTML("html", &res, chromedp.BySearch),
	)

	if err != nil {
		if err.Error() == context.DeadlineExceeded.Error() {
			errstr := fmt.Sprintf("url:%s 超时发包", t.Url.String())
			logger.Error(errstr)
			return htmls, "", errors.New(errstr)
		} else {
			logger.Error(err.Error())
		}
	}

	//tctx, tcancel = context.WithTimeout(*t.Ctx, time.Duration(time.Second*3))

	subctx, subcancel := context.WithCancel(*t.Ctx)
	defer subcancel()
	tctx, tcancel = context.WithTimeout(subctx, time.Second*2)
	defer tcancel()

	for {
		select {
		case html := <-t.Source:
			htmls = append(htmls, html)
		case <-tctx.Done():
			//btimeout = true

			//最后获取一次经过dom渲染的xss

			c := chromedp.FromContext(ctx)
			ctx := cdp.WithExecutor(ctx, c.Target)

			subctx, _ := context.WithCancel(ctx)
			newctx, cancel3 := context.WithTimeout(subctx, time.Second*1)
			defer cancel3()
			chromedp.OuterHTML("html", &domhtml, chromedp.ByQuery).Do(newctx)
			htmls = append(htmls, domhtml)
			//cancel()
			goto quit
		case <-(*t.TaskCtx).Done():
			//logger.Warning("xss插件收到任务过期,中断发包")
			(*t.Cancel)()
			(*t.PackCancel)()
			//cancel()
			//goto quit
			return htmls, "", errors.New("xss error")
		}
	}

quit:

	if t.stopSourceCh != nil {
		close(t.stopSourceCh)
		t.stopSourceCh = make(chan struct{})
	}

	Str := t.RequestsStr
	return htmls, Str, nil
}

func (t *Tabs) GetRequrlparam() (url.Values, error) {
	if len(t.Url.String()) == 0 {
		panic("request url is emtry")
	}
	u, err := url.Parse(t.Url.String())
	if err != nil {
		panic(err)
	}
	m, err := url.ParseQuery(u.RawQuery)
	return m, err
}

// GetReqLensByHtml 二度获取请求的长度
func (t *Tabs) GetReqLensByHtml(JsonUrls *ast.JsonUrl) error {

	if len(t.Url.String()) == 0 {
		panic("request url is emtry")
	}

	if JsonUrls.MetHod == "GET" {
		t.ReqMode = "GET"
		t.Url, _ = url.Parse(JsonUrls.Url)
		response, _, err := t.Send()
		if err != nil {
			return err
		}
		t.Standardlen = len(response)
	} else {
		t.ReqMode = "POST"
		t.Url, _ = url.Parse(JsonUrls.Url)
		t.PostData = []byte(JsonUrls.Data)
		response, _, err := t.Send()
		if err != nil {
			return err
		}
		t.Standardlen = len(response)
	}

	return nil
}

// BuildPayload words和 extension 是映射关系
type BuildPayload struct {
	i     int
	value string
	words []string
}

func (g *BuildPayload) Next() bool {
	if g.i == len(g.words) {
		return false
	}
	g.value = g.words[g.i]
	g.i++
	return true
}

func (g *BuildPayload) Value() interface{} {
	return g.value
}

// GetPayloadValue 迭代 payload
func (g *BuildPayload) GetPayloadValue() (string, error) {
	if g.Next() {
		switch v := g.Value().(type) {
		case string:
			return v, nil
		}
	}
	return "", fmt.Errorf("the datas is nothing")
}

// PayloadHandle payload处理,把payload根据请求方式的不同修改 paramname
func (t *Tabs) PayloadHandle(payload string, reqmod string, paramname string, Getparams url.Values, IsEncode bool) error {
	var rawUrl string
	t.ReqMode = reqmod

	if reqmod == "GET" {
		if len(Getparams) == 0 {
			return fmt.Errorf("GET参数为空")
		}
		payloads := []string{payload}
		Getparams[paramname] = payloads
		// Getparams.Encode()

		t.Url.RawQuery = Getparams.Encode()

	} else {
		if len(t.PostData) == 0 {
			return fmt.Errorf("POST参数为空")
		}
		t.PostData = []byte(payload)
	}

	if t.IsEncodeUrl {
		rawUrl = t.Url.String()
	} else {
		// if strings.HasSuffix(t.Url.Hostname(), "/") {
		// 	rawUrl = t.Url.Scheme + "://" + t.Url.Hostname() + t.Url.RequestURI()
		// } else {

		// }
		rawUrl = t.Url.Scheme + "://" + t.Url.Host + t.Url.Path + t.Url.RequestURI()
	}

	req, err := http.NewRequest(t.ReqMode, rawUrl, bytes.NewReader(t.PostData))
	if err != nil {
		logger.Error(err.Error())
	}

	for Headerkey, Headervalue := range t.Headers {
		if value, ok := Headervalue.(string); ok {
			req.Header[Headerkey] = []string{value}
		}
	}

	array, err := httputil.DumpRequest(req, true)
	if err != nil {
		logger.Error(err.Error())
	}

	// httpreq := Processequest(request.Tabs)

	t.RequestsStr = string(array)

	return nil
}

// 这个要改一下加速发包速度
func (t *Tabs) CheckPayloadLocation(newpayload string, isflag bool) ([]string, string, error) {
	var (
		htmls         []string
		req_str       string
		resp_str      []string
		sfName        string
		IsEncodeArray = []bool{true, false}
	)
	sfName = path.Base(t.Url.Path)
	if t.ReqMode == "GET" {
		Getparams, err := t.GetRequrlparam()
		tmpParams := make(url.Values)
		for key, value := range Getparams {
			tmpParams[key] = value
		}
		if err != nil {
			logger.Error(err.Error())
		}
		if t.Headers["Referer"] == t.Url.String() {
			resp_str, req_str, err = t.Send()
			if err != nil {
				logger.Warning("xss error %s", err.Error())
				return nil, "", err
			}
			if len(resp_str) != 0 {
				htmls = append(htmls, resp_str...)
			}
		} else {
			//验证flag存在不编码
			if isflag {
				for param, _ := range Getparams {
					t.PayloadHandle(newpayload, "GET", param, Getparams, false)
					Getparams = tmpParams
					resp_str, req_str, err = t.Send()
					if err != nil {
						logger.Warning("xss error %s", err.Error())
					}
					if len(resp_str) != 0 {
						htmls = append(htmls, resp_str...)
					}
				}
			} else {
				for param, _ := range Getparams {
					for _, IsEncode := range IsEncodeArray {
						t.PayloadHandle(newpayload, "GET", param, Getparams, IsEncode)
						Getparams = tmpParams
						resp_str, req_str, err = t.Send()
						if err != nil {
							logger.Warning("xss error %s", err.Error())
						}
						if len(resp_str) != 0 {
							htmls = append(htmls, resp_str...)
						}

					}
				}
			}

		}

		if len(Getparams) == 0 {
			//fmt.Println(t.Url.String())
			if strings.HasSuffix(t.Url.String(), "/") && sfName != "" {
				if isflag {
					for _, IsEncode := range IsEncodeArray {
						t.Url.RawQuery = newpayload
						t.IsEncodeUrl = IsEncode

						req, err := http.NewRequest(t.ReqMode, t.Url.String(), nil)
						if err != nil {
							logger.Error(err.Error())
						}

						for Headerkey, Headervalue := range t.Headers {
							if value, ok := Headervalue.(string); ok {
								req.Header[Headerkey] = []string{value}
							}
						}

						array, err := httputil.DumpRequest(req, true)
						if err != nil {
							logger.Error(err.Error())
						} else {
							t.RequestsStr = string(array)
						}

						resp_str, req_str, err = t.Send()

						if err != nil {
							logger.Warning("xss error %s", err.Error())
						}
						if len(resp_str) != 0 {
							htmls = append(htmls, resp_str...)
						}
					}
				} else {
					t.Url.RawQuery = newpayload
					t.IsEncodeUrl = false
					resp_str, req_str, err = t.Send()
					if err != nil {
						logger.Warning("xss error %s", err.Error())
					}
					if len(resp_str) != 0 {
						htmls = append(htmls, resp_str...)
					}
				}

			}
		}
		return htmls, req_str, nil
	} else {
		PostData := t.PostData
		if value, ok := t.Headers["Content-Type"]; ok {
			params, err := util.ParseUri("", PostData, "POST", value.(string), nil)
			if err != nil {
				logger.Error("CheckPayloadLocation request error: %v", err)
				return nil, "", err
			}
			payloads := params.SetPayloads("", newpayload, "POST")
			if len(payloads) == 0 {
				return nil, "", errors.New("parameter is zero")
			}
			for _, v := range payloads {
				t.PostData = []byte(PostData)
				t.PayloadHandle(v, "POST", "", nil, false)
				resp_str, req_str, err = t.Send()
				if err != nil {
					logger.Warning("xss error %s", err.Error())
				}
				if len(resp_str) != 0 {
					htmls = append(htmls, resp_str...)
				}
			}

		} else {
			logger.Debug("checkpayloadlocation error: haven't found content type")
		}
		return htmls, req_str, nil
	}
}

func (t *Tabs) CheckFLagOnbody(playload *string, urlrequst *ast.JsonUrl) (bool, map[int]interface{}) {
	var urlocc UrlOCC
	var SearchFlag = true
	ReponseInfo := make(map[int]interface{})
	htmls, _, err := t.CheckPayloadLocation(*playload, SearchFlag)
	if err != nil {
		logger.Error("%s", err.Error())
		return false, nil
	}
	var bOnhtml bool = false
	if len(htmls) != 0 {
		for i, html := range htmls {
			Node := ast.SearchInputInResponse(*playload, html)
			if len(Node) != 0 {
				bOnhtml = true
			}
			//重置Url参数
			t.CopyRequest(urlrequst)
			urlocc.Request = t.ReqtoJson()
			urlocc.OCC = Node
			ReponseInfo[i] = urlocc
		}
	}
	return bOnhtml, ReponseInfo
}

func (t *Tabs) CopyRequest(data interface{}) {
	var lock sync.Mutex
	lock.Lock()
	defer lock.Unlock()
	switch v := data.(type) {
	case map[string]interface{}:
		t.ReqMode = v["method"].(string)
		t.Url, _ = url.Parse(v["url"].(string))
		t.PostData = util.Str2Byte(v["data"].(string))
		t.Headers = v["headers"].(map[string]interface{})
	case *ast.JsonUrl:
		t.ReqMode = v.MetHod
		t.Url, _ = url.Parse(v.Url)
		t.PostData = util.Str2Byte(v.Data)
		t.Headers = v.Headers
	default:
		logger.Fatal("无效参数")
	}
}

func (t *Tabs) ReqtoJson() ast.JsonUrl {
	var data ast.JsonUrl
	data.MetHod = t.ReqMode
	data.Url = t.Url.String()
	data.Data = string(t.PostData)
	data.Headers = t.Headers
	return data
}
