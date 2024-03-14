package crawler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"glint/config"
	config2 "glint/config"
	"glint/logger"
	model2 "glint/model"
	"glint/util"

	//log "glint/log"

	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/gogf/gf/encoding/gcharset"
	"github.com/logrusorgru/aurora"
	"github.com/thoas/go-funk"
)

var removeAttribute = `var itags = document.getElementsByTagName('input');for(i=0;i<=itags.length;i++){if(itags[i]){itags[i].removeAttribute('style')}}`

const (
	inViewportJS = `(function(a) {
		var r = a[0].getBoundingClientRect();
		return r.top >= 0 && r.left >= 0 && r.bottom <= window.innerHeight && r.right <= window.innerWidth;
	})($x('%s'))`
	level = 3 //网页抓取深度页数

	sethreftarget = `atags = document.getElementsByTagName('a');for(i=0;i<=atags.length;i++) { if(atags[i]){atags[i].setAttribute('target', '')}}`
)

type GroupsType string

const (
	GroupsButton GroupsType = "Button"
	GroupsNormal GroupsType = "Normal"
	GroupsEmtry  GroupsType = ""
)

type bindingCallPayload struct {
	Name string   `json:"name"`
	Seq  int      `json:"seq"`
	Args []string `json:"args"`
}

type BrowserHttpInfo struct {
	Request  *http.Request
	Response *http.Response
}

type Filter struct {
	MarkedQueryMap    map[string]interface{}
	QueryKeysId       string
	QueryMapId        string
	MarkedPostDataMap map[string]interface{}
	PostDataId        string
	MarkedPath        string
	PathId            string
	UniqueId          string
}

type Options struct {
	Headers  map[string]interface{}
	PostData string
}

// Spider 爬虫资源
type Spider struct {
	Ctx          *context.Context
	Cancel       *context.CancelFunc
	tabs         []*context.Context
	tabCancels   []context.CancelFunc
	ExtraHeaders map[string]interface{}
	lock         sync.Mutex
}

type Eventchanel struct {
	GroupsId       string    //针对爬虫的时候触发某个js事件因此触发其他Url请求，使用此ID作为同一群组的标识符
	ButtonCheckUrl chan bool //Button按钮的上下文
	SubmitCheckUrl chan bool //Submit按钮的上下文
	ButtonRep      chan string
	SubmitRep      chan string
	EventInfo      map[string]bool
	exit           chan int
}

type Tab struct {
	Ctx             *context.Context
	Cancel          context.CancelFunc
	NavigateReq     model2.Request
	ExtraHeaders    map[string]interface{}
	ResultList      []*model2.Request
	WebSiteFileList *[]util.SiteFile
	Eventchanel     Eventchanel
	NavNetworkID    string
	PageCharset     string
	Scandeep        int //扫描深度
	DocBodyNodeId   cdp.NodeID
	config          TabConfig
	lock            sync.Mutex
	filelock        sync.RWMutex
	WG              sync.WaitGroup //当前Tab页的等待同步计数
	collectLinkWG   sync.WaitGroup
	loadedWG        sync.WaitGroup //Loaded之后的等待计数
	formSubmitWG    sync.WaitGroup //表单提交完毕的等待计数
	removeLis       sync.WaitGroup //移除事件监听
	domWG           sync.WaitGroup //DOMContentLoaded 的等待计数
	fillFormWG      sync.WaitGroup //填充表单任务
	Ratelimite      *util.Rate

	IsHTTPS bool //插件扫描的网站是否有https
}

type TabConfig struct {
	TabRunTimeout           time.Duration
	DomContentLoadedTimeout time.Duration
	EventTriggerMode        string        // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration // 事件触发的间隔 单位毫秒
	BeforeExitDelay         time.Duration // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool
	IgnoreKeywords          []string //
	Proxy                   string
	CustomFormValues        map[string]interface{}
	CustomFormKeywordValues map[string]interface{}
	Ratelimite              *util.Rate
	Scandeep                int  //扫描深度
	IsHTTPS                 bool //插件扫描的网站是否有https
	WebsitFileList          *[]util.SiteFile
	//QPS                     uint //每秒请求速率
}

/*
获取当前标签页CDP的执行上下文
*/
func (tab *Tab) GetExecutor() context.Context {
	c := chromedp.FromContext(*tab.Ctx)
	ctx := cdp.WithExecutor(*tab.Ctx, c.Target)
	return ctx
}

func AllocSubContextWithTimeOut(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	subctx, _ := context.WithCancel(ctx)
	newctx, cancel3 := context.WithTimeout(subctx, timeout)
	return newctx, cancel3
}

/*
*
处理 401 407 认证弹窗
*/
func (tab *Tab) HandleAuthRequired(req *fetch.EventAuthRequired) {
	defer tab.WG.Done()
	fmt.Println(aurora.Yellow("auth required found, auto auth."))

	ctx := tab.GetExecutor()

	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()
	authRes := fetch.AuthChallengeResponse{
		Response: fetch.AuthChallengeResponseResponseProvideCredentials,
		Username: "admin",
		Password: "admin",
	}
	// 取消认证
	_ = fetch.ContinueWithAuth(req.RequestID, &authRes).Do(subctx)
}

/*
*
获取的Body的NodeId 用于之后子节点无等待查询
最多等待3秒 如果DOM依旧没有渲染完成，则退出
*/
func (tab *Tab) getBodyNodeId() bool {
	var docNodeIDs []cdp.NodeID
	ctx := tab.GetExecutor()
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()

	err := chromedp.WaitReady(`body`, chromedp.ByQuery).Do(subctx)
	if err != nil {
		fmt.Println(aurora.Red("getBodyNodeId WaitReady failed, maybe DOM not ready?"))
		fmt.Println(aurora.Red(err))
		return false
	}

	subctx1, cancel0 := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel0()

	// 获取 Frame document root
	err = chromedp.NodeIDs(`body`, &docNodeIDs, chromedp.ByQuery).Do(subctx1)
	if len(docNodeIDs) == 0 || err != nil {
		// not root node yet?
		fmt.Println(aurora.Red("getBodyNodeId failed, maybe DOM not ready?"))
		if err != nil {
			fmt.Println(aurora.Red(err))
		}
		return false
	}
	tab.DocBodyNodeId = docNodeIDs[0]
	return true
}

func (tab *Tab) GetContentCharset(v *network.EventResponseReceived) {
	defer tab.WG.Done()
	var getCharsetRegex = regexp.MustCompile("charset=(.+)$")
	for key, value := range v.Response.Headers {
		if key == "Content-Type" {
			value := value.(string)
			if strings.Contains(value, "charset") {
				value = getCharsetRegex.FindString(value)
				value = strings.ToUpper(strings.Replace(value, "charset=", "", -1))
				tab.PageCharset = value
				tab.PageCharset = strings.TrimSpace(tab.PageCharset)
			}
		}
	}
}

/*
*
在DOMContentLoaded完成后执行
*/
func (tab *Tab) AfterDOMRun() {
	defer tab.WG.Done()
	logger.Success("afterDOMRun start")
	// // 获取当前body节点的nodeId 用于之后查找子节点
	// if !tab.getBodyNodeId() {
	// 	fmt.Println(aurora.Red("no body document NodeID, exit."))
	// 	return
	// }
	//填充表单
	tab.domWG.Add(1)
	go tab.fillForm()
	tab.domWG.Wait()
	tab.ClickNodeByOnClick()
	logger.Success("afterDOMRun end")
	tab.WG.Add(1)
	go tab.AfterLoadedRun()
}

/*
*
执行JS
*/
func (tab *Tab) Evaluate(expression string) {
	ctx := tab.GetExecutor()

	_, exception, err := runtime.Evaluate(expression).Do(ctx)
	if exception != nil {
		logger.Debug("tab Evaluate: ", exception.Text)
	}
	if err != nil {
		logger.Debug("tab Evaluate: ", err)
	}
}

/*
*
a标签的href值为伪协议
*/
func (tab *Tab) triggerJavascriptProtocol() {
	defer tab.loadedWG.Done()
	logger.Success("clickATagJavascriptProtocol start")
	tab.Evaluate(fmt.Sprintf(TriggerJavascriptProtocol, tab.config.EventTriggerInterval.Seconds()*1000,
		tab.config.EventTriggerInterval.Seconds()*1000))
	logger.Success("clickATagJavascriptProtocol end")
}

/*
*
触发内联事件
*/
func (tab *Tab) triggerInlineEvents() {
	defer tab.loadedWG.Done()
	logger.Debug("triggerInlineEvents start")
	tab.Evaluate(fmt.Sprintf(TriggerInlineEventJS, tab.config.EventTriggerInterval.Seconds()*1000))
	logger.Debug("triggerInlineEvents end")
}

/*
*
触发DOM2级事件
*/
func (tab *Tab) triggerDom2Events() {
	defer tab.loadedWG.Done()
	logger.Debug("triggerDom2Events start")
	tab.Evaluate(fmt.Sprintf(TriggerDom2EventJS, tab.config.EventTriggerInterval.Seconds()*1000))
	logger.Debug("triggerDom2Events end")
}

/*
*
移除DOM节点变化监听
*/
func (tab *Tab) RemoveDOMListener() {
	defer tab.removeLis.Done()
	logger.Debug("RemoveDOMListener start")
	// 移除DOM节点变化监听
	tab.Evaluate(RemoveDOMListenerJS)
	logger.Debug("RemoveDOMListener end")
}

/*
*
在页面Loaded之后执行
同时等待 afterDOMRun 之后执行
*/
func (tab *Tab) AfterLoadedRun() {
	defer tab.WG.Done()
	logger.Success("afterLoadedRun start")
	tab.formSubmitWG.Add(2)
	tab.loadedWG.Add(3)
	tab.removeLis.Add(1)

	logger.Success("formSubmit start")
	go tab.CommitBySubmit()
	go tab.clickAllButton()
	tab.formSubmitWG.Wait()
	logger.Success("formSubmit end")

	// if tab.config.EventTriggerMode == config.EventTriggerAsync {
	go tab.triggerJavascriptProtocol()
	go tab.triggerInlineEvents()
	go tab.triggerDom2Events()
	tab.loadedWG.Wait()
	// } else if tab.config.EventTriggerMode == config.EventTriggerSync {
	// 	tab.triggerInlineEvents()
	// 	time.Sleep(tab.config.EventTriggerInterval)
	// 	tab.triggerDom2Events()
	// 	time.Sleep(tab.config.EventTriggerInterval)
	// 	tab.triggerJavascriptProtocol()
	// }

	// 事件触发之后 需要等待一点时间让浏览器成功发出ajax请求 更新DOM
	time.Sleep(2 * time.Second)

	go tab.RemoveDOMListener()
	// tab.removeLis.Wait()
	logger.Success("afterLoadedRun end")
}

// ListenTarget
func (tab *Tab) ListenTarget(extends interface{}) {
	var DOMContentLoadedRun = false
	chromedp.ListenTarget(*tab.Ctx, func(ev interface{}) {
		Response := make(map[string]string)
		Responses := []map[string]string{}
		// fmt.Println(aurora.Yellow(reflect.TypeOf(ev)))
		switch ev := ev.(type) {
		case *runtime.EventConsoleAPICalled:
			for _, arg := range ev.Args {
				fmt.Printf("%s - %s\n", arg.Type, string(arg.Value))
				Response[string(ev.Type)] = strings.ReplaceAll(string(arg.Value), "\"", "")
				Responses = append(Responses, Response)
			}
		case *runtime.EventExceptionThrown:

		case *fetch.EventRequestPaused:
			go func(ctx context.Context, ev *fetch.EventRequestPaused) {
				var a chromedp.Action
				Domain1 := tab.NavigateReq.URL.String() + "/"
				rule1 := strings.Replace(tab.NavigateReq.URL.String(), "http://", "https://", -1)
				rule2 := strings.Replace(tab.NavigateReq.URL.String(), "https://", "http://", -1)
				if FilterKey(ev.Request.URL, ForbidenKey) ||
					ev.Request.URL == rule1 ||
					ev.Request.URL == rule2 ||
					ev.ResourceType == network.ResourceTypeXHR ||
					ev.Request.URL == Domain1 {
					//XHR 允许AJAX 代码更新请求，因为它不刷新页面,有可能只刷新dom节点
					if strings.HasSuffix(ev.Request.URL, ".js") {
						if funk.Contains(ev.Request.URL, ".js") {
							jsdata, err := util.ParseJSFile(ev.Request.URL)
							if err != nil {
								logger.Error(err.Error())
							} else {
								tab.AddResultJsRequest(*jsdata)
							}
						}
						a = fetch.ContinueRequest(ev.RequestID)
					} else if util.GetScanDeepByUrl(ev.Request.URL) > int(tab.Scandeep) {
						logger.Debug("AJAX request add Url forbiden because ScanDeep limit")
						a = fetch.FailRequest(ev.RequestID, network.ErrorReasonAborted)

						// a = fetch.ContinueRequest(ev.RequestID)
					} else {
						a = fetch.ContinueRequest(ev.RequestID)
					}
				} else {
					logger.Info("FailRequest:%s", ev.Request.URL)
					c := chromedp.FromContext(ctx)
					ctx = cdp.WithExecutor(ctx, c.Target)
					a = fetch.FailRequest(ev.RequestID, network.ErrorReasonAborted)
					//a = fetch.ContinueRequest(ev.RequestID)
				}
				var req model2.Request
				// decodedValue, err := url.QueryUnescape(ev.Request.URL)
				// if err != nil {
				// 	logger.Error(err.Error())
				// }
				u, err := url.Parse(ev.Request.URL)
				if err != nil {
					logger.Error(err.Error())
				}

				req.URL = &model2.URL{URL: *u}
				req.Method = ev.Request.Method
				req.Headers = map[string]interface{}{}
				req.PostData = ev.Request.PostData
				// file

				// filename, err := util.GetFileNameFromUrl(ev.Request.URL)
				// if err != nil {
				// 	req.PageState.IsFile = false
				// } else {
				// 	req.PageState.Filename = filename
				// 	req.PageState.IsFile = true
				// 	req.PageState.ScanSiteFile = true
				// 	req.PageState.FileContent = base64.StdEncoding.EncodeToString([]byte(ev.Request.PostData))
				// }

				if len(ev.Request.Headers) > 0 {
					req.Headers = ev.Request.Headers
				}
				// 修正Referer
				req.Headers["Referer"] = ev.Request.Headers["Referer"]
				req.Source = string(ev.ResourceType)
				//fmt.Println(req.URL.String())
				if !FilterKey(req.URL.String(), ForbidenKey) {
					if b, ok := tab.Eventchanel.EventInfo["Button"]; ok {
						if b {
							tab.Eventchanel.GroupsId =
								fmt.Sprintf("ButtonDoM-%s", util.RandLetterNumbers(5))
							req.GroupsId =
								tab.Eventchanel.GroupsId
						} else {
							req.GroupsId =
								tab.Eventchanel.GroupsId
						}
					}
					if b, ok := tab.Eventchanel.EventInfo["Submit"]; ok {
						if b {
							tab.Eventchanel.GroupsId =
								fmt.Sprintf("SubmitDoM-%s", util.RandLetterNumbers(5))
							req.GroupsId =
								tab.Eventchanel.GroupsId
						} else {
							req.GroupsId =
								tab.Eventchanel.GroupsId
						}
					} else {
						req.GroupsId = "Normal"
					}
					//fmt.Println("Pre add Url:", aurora.Red(req.URL.String()))

					tab.AddResultRequest(req)
				}
				logger.Debug("chromedp.Run CMD")
				if err := chromedp.Run(ctx, a); err != nil {
					logger.Error("ListenTarget error %s", err.Error())
				}
			}(*tab.Ctx, ev)
		case *page.EventJavascriptDialogOpening:
			// logger.Println("EventJavascriptDialogOpening url:", ev.URL)
			tab.WG.Add(1)
			go tab.dismissDialog()
		case *page.EventNavigatedWithinDocument:
			// logger.Println("EventNavigatedWithinDocument url:", ev.URL)
		case *page.EventFrameStoppedLoading:

		case *page.EventWindowOpen:
			// logger.Println("EventWindowOpen url:", ev.URL)
			var req model2.Request
			u, _ := url.Parse(ev.URL)
			req.URL = &model2.URL{*u}
			req.Method = "GET"
			req.Headers = map[string]interface{}{}
			// ev.
			if !FilterKey(req.URL.String(), ForbidenKey) {
				if !funk.Contains(tab.NavigateReq.URL.String(), req.URL.String()) {
					if !(util.GetScanDeepByUrl(req.URL.String()) > int(tab.Scandeep)) {
						tab.AddResultRequest(req)
					}
					// logger.Println("EventWindowOpen Add crawer url:", req)
				} else {
					// logger.Println("The url is exist:", req)
				}
			}
		case *page.EventDocumentOpened:
			// logger.Println("EventDocumentOpened url:", ev.Frame.URL)
		case *network.EventRequestWillBeSentExtraInfo:

		// 解析所有JS文件中的URL并添加到结果中
		// 解析HTML文档中的URL
		// 查找当前页面的编码
		case *network.EventResponseReceived:
			if ev.Response.MimeType == "application/javascript" || ev.Response.MimeType == "text/html" || ev.Response.MimeType == "application/json" {
				tab.WG.Add(1)
				// ev.RequestID.String()
				go tab.ParseResponseURL(ev)
			}
			if ev.RequestID.String() == tab.NavNetworkID {
				tab.WG.Add(1)
				go tab.GetContentCharset(ev)
			}
		case *network.EventRequestWillBeSent:
			//fmt.Println(aurora.Sprintf("EventRequestWillBeSent==>  url: %s requestid: %s", aurora.Red(ev.Request.URL), aurora.Red(ev.RequestID)))
			//重定向
			request := ev
			if ev.RedirectResponse != nil {
				//url = request.DocumentURL
				logger.Info("链接 %s: 重定向到: %s\n", request.RedirectResponse.URL, request.DocumentURL)
			}
			if ev.Request.HasPostData {
				logger.Success("EventRequestWillBeSent Post %s", ev.Request.PostData)
			}
		case *page.EventDomContentEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			tab.WG.Add(1)
			go tab.AfterDOMRun()
		case *page.EventLoadEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			tab.WG.Add(1)
			go tab.AfterDOMRun()
		case *page.EventFrameRequestedNavigation:
			logger.Debug("开始请求的导航 FrameID:%s url %s , 导航类型 type: %s  导航请求理由：%s ",
				ev.FrameID, ev.URL, ev.Disposition, ev.Reason)
			// handle expose function
		case *runtime.EventBindingCalled:
			tab.WG.Add(1)
			go tab.HandleBindingCalled(ev)

		}

	})
}

func InitSpider(
	ChromiumPath string,
	IncognitoContext bool,
	ExtraHeaders map[string]interface{},
	Proxy string) *Spider {

	spider := Spider{}
	options := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-images", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-xss-auditor", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-setuid-sandbox", true),
		chromedp.Flag("allow-running-insecure-content", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-webgl", true),
		chromedp.Flag("disable-popup-blocking", true),
		chromedp.Flag("block-new-web-contents", true),
		chromedp.Flag("blink-settings", "imagesEnabled=false"),
		// chromedp.Flag("proxy-server", Proxy),

		chromedp.UserAgent(`Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36`),
	}

	if Proxy != "" {
		options = append(options, chromedp.Flag("proxy-server", Proxy))
	}

	ExecAllocator := append(chromedp.DefaultExecAllocatorOptions[:], options...)
	//NewExecAllocator 是新建一个浏览器
	ctx, Cancel := chromedp.NewExecAllocator(context.Background(), ExecAllocator...)
	lctx, Cancel := chromedp.NewContext(ctx,
		chromedp.WithLogf(logger.Printf),
	)
	chromedp.Run(lctx)
	spider.Ctx = &lctx
	spider.Cancel = &Cancel
	return &spider
}

func NewTab(spider *Spider, navigateReq model2.Request, config TabConfig) (*Tab, error) {

	var tab Tab

	ctx, cancel := chromedp.NewContext(*spider.Ctx)
	tCtx, _ := context.WithTimeout(ctx, 30*time.Second)

	spider.lock.Lock()
	spider.tabs = append(spider.tabs, &tCtx)
	spider.tabCancels = append(spider.tabCancels, cancel)
	spider.lock.Unlock()

	// tab.ExtraHeaders = map[string]interface{}{}
	// host := navigateReq.URL.Host
	// fmt.Println(navigateReq.URL.String())
	tab.Ctx = &tCtx
	tab.Cancel = cancel
	tab.NavigateReq = navigateReq
	tab.ExtraHeaders = navigateReq.Headers
	tab.IsHTTPS = config.IsHTTPS
	if _, ok := tab.ExtraHeaders["HOST"]; ok {
		delete(tab.ExtraHeaders, "HOST")
	}
	tab.WebSiteFileList = config.WebsitFileList
	tab.Eventchanel.EventInfo = make(map[string]bool)
	tab.Eventchanel.ButtonCheckUrl = make(chan bool, 1)
	tab.Eventchanel.SubmitCheckUrl = make(chan bool, 1)
	tab.Eventchanel.ButtonRep = make(chan string, 1)
	tab.Eventchanel.SubmitRep = make(chan string, 1)
	tab.Eventchanel.exit = make(chan int, 1)
	tab.Ratelimite = config.Ratelimite
	tab.Scandeep = config.Scandeep

	tab.ListenTarget(nil)
	return &tab, nil
}

func (bro *Spider) Close() {
	fmt.Println(aurora.Green("closing browser."))
	for _, cancel := range bro.tabCancels {
		cancel()
	}
	for _, ctx := range bro.tabs {
		_ = browser.Close().Do(*ctx)
	}
	_ = browser.Close().Do(*bro.Ctx)
	(*bro.Cancel)()
}

/*
*
识别页面的编码
*/
func (tab *Tab) DetectCharset() {
	ctx := tab.GetExecutor()
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*2)
	defer cancel()

	var content string
	var ok bool
	var getCharsetRegex = regexp.MustCompile("charset=(.+)$")
	err := chromedp.AttributeValue(`meta[http-equiv=Content-Type]`, "content", &content, &ok, chromedp.ByQuery).Do(subctx)
	if err != nil || ok != true {
		return
	}
	if strings.Contains(content, "charset=") {
		charset := getCharsetRegex.FindString(content)
		if charset != "" {
			tab.PageCharset = strings.ToUpper(strings.Replace(charset, "charset=", "", -1))
			tab.PageCharset = strings.TrimSpace(tab.PageCharset)
		}
	}
}

/*
*
处理回调
*/
func (tab *Tab) HandleBindingCalled(event *runtime.EventBindingCalled) {
	defer tab.WG.Done()
	payload := []byte(event.Payload)
	var bcPayload bindingCallPayload
	_ = json.Unmarshal(payload, &bcPayload)
	if bcPayload.Name == "addLink" && len(bcPayload.Args) > 1 {
		if !(util.GetScanDeepByUrl(bcPayload.Args[0]) > int(tab.Scandeep)) {
			// tab.AddResultRequest(req)
			tab.AddResultUrl(config.GET, bcPayload.Args[0], bcPayload.Args[1])
		}
	}
	// if bcPayload.Name == "Test" {
	// 	fmt.Println(bcPayload.Args)
	// }
	tab.Evaluate(fmt.Sprintf(DeliverResultJS, bcPayload.Name, bcPayload.Seq, "s"))
}

func (tab *Tab) EncodeAllURLWithCharset() {
	if tab.PageCharset == "" || tab.PageCharset == "UTF-8" {
		return
	}
	for _, req := range tab.ResultList {
		newRawQuery, err := gcharset.UTF8To(tab.PageCharset, req.URL.RawQuery)
		if err == nil {
			req.URL.RawQuery = newRawQuery
		}
		newRawPath, err := gcharset.UTF8To(tab.PageCharset, req.URL.RawPath)
		if err == nil {
			req.URL.RawPath = newRawPath
		}
	}
}

// Crawler 爬取链接
func (tab *Tab) Crawler(extends interface{}) error {
	defer tab.Cancel()
	defer func() { tab.Eventchanel.exit <- 1 }()

	go tab.WatchEventSubmit()
	//fmt.Println(aurora.Green(tab.NavigateReq.URL.String()))
	err := chromedp.Run(*tab.Ctx,
		runtime.Enable(),
		// 开启网络层API
		network.Enable(),
		// 开启请求拦截API
		fetch.Enable().WithHandleAuthRequests(true),

		// network.SetExtraHTTPHeaders(network.Headers(tab.ExtraHeaders)),
		// 设置标签头
		chromedp.ActionFunc(func(c context.Context) error {
			network.SetExtraHTTPHeaders(network.Headers(tab.ExtraHeaders)).Do(c)
			return nil
		}),

		// 初始化执行JS
		chromedp.ActionFunc(func(ctx context.Context) error {
			var err error
			_, err = page.AddScriptToEvaluateOnNewDocument(TabInitJS).Do(ctx)
			if err != nil {
				return err
			}
			return nil
		}),

		// 开启导航
		chromedp.Navigate(tab.NavigateReq.URL.String()),
	)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	//等待DOM更新结束
	// go func() {
	// 	// 等待所有协程任务结束
	// 	tab.WG.Wait()
	// 	// tab.NavDone <- 1
	// }()

	tab.WG.Wait()
	logger.Success("collectLinks start")
	tab.collectLinkWG.Add(3)
	go tab.CollectLink()
	tab.collectLinkWG.Wait()
	logger.Success("collectLinks end")

	// 识别页面编码 并编码所有URL
	// if tab.config.EncodeURLWithCharset {
	tab.DetectCharset()
	tab.EncodeAllURLWithCharset()
	//}

	return nil
}

// CommitBySubmit 提交按钮
func (tab *Tab) CommitBySubmit() error {
	defer tab.formSubmitWG.Done()
	// 首先点击按钮 type=submit
	ctx := tab.GetExecutor()
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()

	// 获取所有的form节点 直接执行submit
	formNodes, err := tab.GetNodeIDs(`form`)
	if err != nil {
		logger.Warning("CommitBySubmit<form> %s", err.Error())
		// return err
	}

	_ = chromedp.Submit(formNodes, chromedp.ByNodeID).Do(subctx)
	// 获取所有的input标签
	node := []*cdp.Node{}
	subctx1, cancel1 := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel1()

	chromedp.Nodes("input[type=submit]", &node, chromedp.BySearch).Do(subctx1)
	if len(node) == 0 {
		errmsg := "CommitBySubmit<input> node is empty"
		logger.Warning(errmsg)
		return errors.New(errmsg)
	}

	for _, v := range node {
		tab.Eventchanel.SubmitCheckUrl <- true
		<-tab.Eventchanel.SubmitRep
		Nodes := []cdp.NodeID{v.NodeID}
		subctx2, cancel2 := AllocSubContextWithTimeOut(ctx, time.Second*3)
		defer cancel2()
		_ = chromedp.Click(Nodes, chromedp.ByNodeID).Do(subctx2)
		//使用sleep顺序执行
		time.Sleep(time.Millisecond * 500)
		tab.Eventchanel.SubmitCheckUrl <- false
		<-tab.Eventchanel.SubmitRep
		time.Sleep(time.Millisecond * 500)
	}
	return nil
}

/*
*
解析响应内容中的URL 使用正则匹配 （2022/9/27不采取这种解析，解析出来没有验证链接是否有效也是醉了。）
*/
func (tab *Tab) ParseResponseURL(v *network.EventResponseReceived) {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()

	res, err := network.GetResponseBody(v.RequestID).Do(subctx)
	if err != nil {
		logger.Debug("ParseResponseURL ", err)
		return
	}
	resStr := string(res)

	urlRegex := regexp.MustCompile(config2.SuspectURLRegex)
	urlList := urlRegex.FindAllString(resStr, -1)
	for _, url := range urlList {

		url = url[1 : len(url)-1]
		url_lower := strings.ToLower(url)
		if strings.HasPrefix(url_lower, "image/x-icon") || strings.HasPrefix(url_lower, "text/css") || strings.HasPrefix(url_lower, "text/javascript") {
			continue
		}

		if !(util.GetScanDeepByUrl(url) > int(tab.Scandeep)) {
			// tab.AddResultRequest(req)
			tab.AddResultUrl("GET", url, config2.FromJSFile)
		}

	}
}

/*
*
立即根据条件获取Nodes的ID，不等待
*/
func (tab *Tab) GetNodeIDs(sel string) ([]cdp.NodeID, error) {
	ctx := tab.GetExecutor()
	return dom.QuerySelectorAll(tab.DocBodyNodeId, sel).Do(ctx)
}

// fillForm 填写表单
func (tab *Tab) fillForm() error {
	defer tab.domWG.Done()
	var lock sync.WaitGroup
	var InputNodes []*cdp.Node
	var TextareaNodes []*cdp.Node
	ctx := tab.GetExecutor()

	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()

	//移除input的 style 属性
	err := chromedp.Evaluate(removeAttribute, nil).Do(subctx)
	if err != nil {
		logger.Error("removeAttribute error: %s", err)
	}

	subctx1, cancel1 := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel1()

	//var res string
	//获取 input节点
	err = chromedp.Nodes("//input", &InputNodes, chromedp.BySearch).Do(subctx1)
	if err != nil {
		logger.Warning("fillForm error: %v", err.Error())
	}
	if len(InputNodes) == 0 {
		err_msg := "fillForm::input find node"
		return errors.New(err_msg)
	}

	subctx2, cancel2 := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel2()

	err = chromedp.Nodes(`input[name="upload"]`, &InputNodes, chromedp.BySearch).Do(subctx2)
	if err != nil {
		logger.Warning("fillForm error: %v", err.Error())
	}

	if len(InputNodes) == 0 {
		err_msg := "fillForm::input find node"
		return errors.New(err_msg)
	} else {
		lock.Add(1)
		go func() {
			// get wd
			wd, err := os.Getwd()
			if err != nil {
				log.Fatal(err)
			}

			filepath := wd + "/fit.txt"

			defer lock.Done()
			ctx := tab.GetExecutor()
			subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
			defer cancel()

			chromedp.SendKeys(`input[name="upload"]`, filepath, chromedp.NodeNotVisible).Do(subctx)
		}()
		// chromedp.SendKeys(`input[name="upload"]`, "glint.txt", chromedp.BySearch).Do(tCtx)
		// chromedp.Click(`input[name="submit"]`)
		lock.Wait()
		// chromedp.Click(`input[name="submit"]`)
	}

	ctx = tab.GetExecutor()
	subctx3, cancel3 := AllocSubContextWithTimeOut(ctx, time.Second*5)
	defer cancel3()

	err = chromedp.Nodes("//textarea", &TextareaNodes, chromedp.BySearch).Do(subctx3)
	if err != nil {
		logger.Debug("fillForm<textarea> error: %v", err.Error())
	}

	if len(InputNodes) == 0 {
		err_msg := "fillForm::input find node"
		return errors.New(err_msg)
	}

	InputNodes = append(TextareaNodes, InputNodes...)

	for _, node := range InputNodes {
		subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*5)
		defer cancel()

		var ok bool
		chromedp.EvaluateAsDevTools(fmt.Sprintf(inViewportJS, node.FullXPath()), &ok).Do(subctx)
		if !(node.AttributeValue("type") == "hidden" || node.AttributeValue("display") == "none") {
			//填写用户名
			if funk.Contains([]string{"user", "用户名", "username", "user_name"}, node.AttributeValue("name")) {
				err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "Wrench1997").Do(subctx)
				if err != nil {
					fmt.Println(aurora.Sprintf("SendKeys username error: %s", err.Error()))
					return err
				}
				continue
			}
			//填写密码
			if funk.Contains([]string{"pwd", "密码", "pass", "password", "user_password", "user_pass", "user_pwd"}, node.AttributeValue("name")) {
				err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "Liujialin1997").Do(subctx)
				if err != nil {
					fmt.Println(aurora.Sprintf("SendKeys password error: %s", err.Error()))
					return err
				}
				continue
			}
			//填写其他
			err = chromedp.SendKeys(fmt.Sprintf(`%s[name=%s]`, node.LocalName, node.AttributeValue("name")), "test1234").Do(subctx)
			if err != nil {
				fmt.Println(aurora.Sprintf("SendKeys %s %s", node.LocalName, err.Error()))
				return err
			}
		}

	}
	return err
}

// 点击input所有onclick属性的节点
func (tab *Tab) ClickNodeByOnClick() error {
	// defer tab.domWG.Done()
	var Nodes []*cdp.Node
	ctx := tab.GetExecutor()
	// tCtx, cancel := context.WithTimeout(ctx, time.Second*4)
	// defer cancel()

	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*5)
	defer cancel()

	err := chromedp.Nodes("//input[@onclick]", &Nodes, chromedp.BySearch).Do(subctx)
	if err != nil {
		logger.Warning("func ClickNodeByOnClick() serarch error:%s ", err.Error())
		return err
	}

	err = chromedp.Click("//input[@onclick]", chromedp.BySearch).Do(subctx)
	if err != nil {
		logger.Warning("func ClickNodeByOnClick() click error:%s ", err.Error())
		return err
	}
	return err
}

// CollectLink 收集链接
func (tab *Tab) CollectLink() error {
	go tab.collectHrefLinks()
	go tab.collectObjectLinks()
	go tab.collectCommentLinks()
	return nil
}

func (tab *Tab) collectHrefLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()

	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*10)
	defer cancel()

	// tCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	// defer cancel()
	// 收集 src href data-url 属性值
	attrNameList := []string{"href", "src", "data-url", "data-href"}
	for _, attrName := range attrNameList {
		var attrs []map[string]string
		err := chromedp.AttributesAll(fmt.Sprintf(`[%s]`, attrName), &attrs, chromedp.BySearch).Do(subctx)
		if err != nil {
			logger.Warning("collectHrefLinks %s", err.Error())
			return
		}
		for _, attrMap := range attrs {
			if !(util.GetScanDeepByUrl(attrMap[attrName]) > int(tab.Scandeep)) {
				tab.AddResultUrl("GET", attrMap[attrName], "DOM")
			}
		}
	}
}

/*
*
关闭弹窗
*/
func (tab *Tab) dismissDialog() {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	_ = page.HandleJavaScriptDialog(false).Do(ctx)
}

func (tab *Tab) collectObjectLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 object[data] links
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()

	var attrs []map[string]string
	_ = chromedp.AttributesAll(`object[data]`, &attrs, chromedp.ByQueryAll).Do(subctx)
	for _, attrMap := range attrs {
		if !(util.GetScanDeepByUrl(attrMap["data"]) > int(tab.Scandeep)) {
			// tab.AddResultRequest(req)
			tab.AddResultUrl("GET", attrMap["data"], "DOM")
		}
		// tab.AddResultUrl("GET", attrMap["data"], "DOM")
	}
}

func (tab *Tab) collectCommentLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集注释中的链接
	var nodes []*cdp.Node
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()

	commentErr := chromedp.Nodes(`//comment()`, &nodes, chromedp.BySearch).Do(subctx)
	if commentErr != nil {
		logger.Warning("get comment nodes err")
		return
	}
	urlRegex := regexp.MustCompile(`((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]`)
	for _, node := range nodes {
		content := node.NodeValue
		urlList := urlRegex.FindAllString(content, -1)
		for _, url := range urlList {
			if !(util.GetScanDeepByUrl(url) > int(tab.Scandeep)) {
				// tab.AddResultRequest(req)
				tab.AddResultUrl("GET", url, "Comment")
			}
		}
	}
}

// GetPageURL 获取当前页面的URL
func (tab *Tab) GetPageURL() (string, error) {
	ctx := tab.GetExecutor()
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*3)
	defer cancel()
	var url string
	// 使用chromedp从当前页面中获取URL
	if err := chromedp.Run(subctx, chromedp.Location(&url)); err != nil {
		return "", fmt.Errorf("获取URL时出错: %w", err)
	}
	return url, nil
}

func (tab *Tab) AddResultUrl(method string, _url string, source string) {
	var Model2url *model2.URL

	PageURL, err := tab.GetPageURL()
	if err != nil {
		logger.Error("error %s", err.Error())
		return
	}

	url, err := util.UriResolve(_url, PageURL)
	if err != nil {
		logger.Error("uri resolve error %s", err.Error())
		return
	}

	option := model2.Options{
		Headers:  map[string]interface{}{},
		PostData: "",
	}

	referer := PageURL
	logger.Debug("pre add url: %s", url.String())

	// 处理Host绑定
	logger.Debug("add url host %s", url.Hostname())
	//option.Headers["Host"] = url.Hostname()
	option.Headers["User-Agent"] = " Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"
	option.Headers["Accept-Encoding"] = "gzip, deflate"
	option.Headers["Accept-Language"] = "zh-CN,zh;q=0.9,en;q=0.8"

	// if host, ok := tab.NavigateReq.Headers["Host"]; ok {
	// 	if url.Hostname() == host {
	// 		url, _ = model2.GetUrl(strings.Replace(url.String(), "://"+url.Hostname(), "://"+navUrl.Hostname(), -1), *navUrl)
	// 		option.Headers["Host"] = host
	// 		referer = strings.Replace(navUrl.String(), navUrl.Host, host.(string), -1)
	// 	}
	// }

	// 转化为新格式
	Model2url = &model2.URL{URL: *url}

	//过滤URL页面是否存在
	if !util.PageExists(url.String()) {
		return
	}

	// 添加Cookie
	if cookie, ok := tab.NavigateReq.Headers["Cookie"]; ok {
		option.Headers["Cookie"] = cookie
	}

	// 修正Referer
	option.Headers["Referer"] = referer
	for key, value := range tab.ExtraHeaders {
		option.Headers[key] = value
	}

	req := model2.GetRequest(method, Model2url, option)
	req.Source = source
	req.GroupsId = "CollectLink"

	// filename, err := util.GetFileNameFromUrl(req.URL.String())
	// if err != nil {
	// 	req.PageState.IsFile = false
	// } else {
	// 	req.PageState.Filename = filename
	// 	req.PageState.IsFile = true
	// 	// req.PageState.ScanSiteFile = true
	// }

	tab.lock.Lock()
	tab.ResultList = append(tab.ResultList, &req)
	tab.lock.Unlock()
}

func (tab *Tab) AddResultRequest(req model2.Request) {
	//这里额外添加站点状态信息
	for key, value := range tab.ExtraHeaders {
		req.Headers[key] = value
	}
	tab.lock.Lock()
	tab.ResultList = append(tab.ResultList, &req)
	tab.lock.Unlock()
}

func (tab *Tab) AddResultJsRequest(File util.SiteFile) {
	//这里额外添加站点状态信息
	tab.filelock.Lock()
	defer tab.filelock.Unlock()
	for _, WebSiteFile := range *tab.WebSiteFileList {
		if WebSiteFile.Hash == File.Hash {
			return
		}
	}
	logger.Info("添加站点文件:%s", File.Url)
	(*tab.WebSiteFileList) = append(*tab.WebSiteFileList, File)
}

/*
*
根据给的Node执行JS
*/
func (tab *Tab) EvaluateWithNode(expression string, node *cdp.Node) error {
	ctx := tab.GetExecutor()
	var res bool
	js := Snippet(expression, CashX(true), "", node)

	err := chromedp.EvaluateAsDevTools(js, &res).Do(ctx)
	if err != nil {
		return err
	}
	return nil
}

/*
*
click all button
*/
func (tab *Tab) clickAllButton() error {
	defer tab.formSubmitWG.Done()

	// 获取所有的form中的button节点
	ctx := tab.GetExecutor()
	subctx, cancel := AllocSubContextWithTimeOut(ctx, time.Second*10)
	defer cancel()

	// tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	// defer cancel()
	var ButtonNodes []*cdp.Node
	err := chromedp.Nodes("//button", &ButtonNodes).Do(subctx)
	if err != nil {
		logger.Warning("clickAllButton %s", err.Error())
		return err
	}
	if len(ButtonNodes) == 0 {
		err := "clickAllButton not found Nodes"
		logger.Warning(err)
		return fmt.Errorf(err)
	}
	for _, node := range ButtonNodes {
		tab.Eventchanel.ButtonCheckUrl <- true
		<-tab.Eventchanel.ButtonRep
		_ = tab.EvaluateWithNode(FormNodeClickJS, node)
		//使用sleep顺序执行
		time.Sleep(time.Millisecond * 500)
		tab.Eventchanel.ButtonCheckUrl <- false
		<-tab.Eventchanel.ButtonRep
		time.Sleep(time.Millisecond * 500)
	}
	delete(tab.Eventchanel.EventInfo, "Button")
	return nil
}
