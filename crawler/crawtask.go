package crawler

import (
	"context"
	"encoding/json"
	"glint/config"
	"glint/logger"
	"glint/model"
	"glint/nenet"
	"glint/util"
	"strings"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

const craw_flag = 5

type Result struct {
	ReqList       []*model.Request // 返回的同域名结果
	AllReqList    []*model.Request // 所有域名的请求
	AllDomainList []string         // 所有域名列表
	SubDomainList []string         // 子域名列表
	HOSTNAME      string           // 收集Uri
	resultLock    sync.Mutex       // 合并结果时加锁
	Hostid        int64            // 域名id，实际上是和前端分不开原因
	WebsitFiles   []util.SiteFile  // 站点文件
}

type CrawlerTask struct {
	Browser         *Spider                      // 爬虫浏览器
	HostName        string                       // 收集Uri
	Scheme          string                       //
	PluginBrowser   *nenet.Spider                // 插件浏览器
	RootDomain      string                       // 当前爬取根域名 用于子域名收集
	Targets         []*model.Request             // 输入目标
	Result          *Result                      // 最终结果
	Config          *config.TaskYamlConfig       // 配置信息
	smartFilter     SmartFilter                  // 过滤对象
	Pool            *ants.Pool                   // 协程池
	taskWG          sync.WaitGroup               // 等待协程池所有任务结束
	crawledCount    int                          // 爬取过的数量
	taskCountLock   sync.Mutex                   // 已爬取的任务总数锁
	TaskCtx         *context.Context             // 任务上下文，这个存储的是任务分配的CTX
	Cancel          *context.CancelFunc          // 取消当前上下文
	Ctx             *context.Context             // 当前上下文
	QPS             int64                        //每秒请求速率
	Scandeep        int                          //扫描深度
	SocketMsg       *chan map[string]interface{} //消息通讯
	IsSocket        bool
	IsHTTPS         bool
	WebSiteFileList []util.SiteFile
	// ScanSiteState util.ScanSiteState
}

func (c *CrawlerTask) Reset() {
	c.Browser = nil
	c.HostName = ""
	c.Scheme = ""
	c.PluginBrowser = nil
	c.RootDomain = ""
	c.Targets = c.Targets[:0]
	c.Result = nil
	c.Config = nil
	c.smartFilter = SmartFilter{}
	// c.Pool = nil
	c.taskWG = sync.WaitGroup{}
	c.crawledCount = 0
	c.taskCountLock = sync.Mutex{}
	c.TaskCtx = nil
	// c.Cancel = nil
	c.Ctx = nil
	c.QPS = 0
	c.Scandeep = 0
	c.SocketMsg = nil
	c.IsSocket = false
	c.WebSiteFileList = []util.SiteFile{}
}

type tabTask struct {
	crawlerTask     *CrawlerTask
	browser         *Spider
	req             *model.Request
	pool            *ants.Pool
	Ratelimite      util.Rate
	Scandeep        int //扫描深度
	SocketMsg       *chan map[string]interface{}
	IsSocket        bool
	PageState       util.PageState
	crawledCount    *int
	WebSiteFileList *[]util.SiteFile
}

// 过滤模式
const (
	SimpleFilterMode = "simple"
	SmartFilterMode  = "smart"
	StrictFilterMode = "strict"
)

/*
*
根据请求列表生成tabTask协程任务列表
*/
func (t *CrawlerTask) generateTabTask(req *model.Request) *tabTask {

	task := tabTask{
		crawlerTask:     t,
		browser:         t.Browser,
		req:             req,
		Scandeep:        t.Scandeep,
		IsSocket:        t.IsSocket,
		crawledCount:    &t.crawledCount,
		WebSiteFileList: &t.WebSiteFileList,
		SocketMsg:       t.SocketMsg,
	}

	task.Ratelimite.InitRate(uint(t.QPS))
	return &task
}

func (t *CrawlerTask) Run() {
	defer t.Pool.Release()  // 释放协程池
	defer t.Browser.Close() // 关闭浏览器

	defer (*t.Cancel)()
	if t.Config.PathFromRobots {
		reqsFromRobots := GetPathsFromRobots(*t.Targets[0])
		logger.Info("get paths from robots.txt: ", len(reqsFromRobots))
		t.Targets = append(t.Targets, reqsFromRobots...)
	}
	if t.Config.FuzzDictPath != "" {
		if t.Config.PathByFuzz {
			logger.Warning("`--fuzz-path` is ignored, using `--fuzz-path-dict` instead")
		}
		reqsByFuzz := GetPathsByFuzzDict(*t.Targets[0], t.Config.FuzzDictPath, *t.TaskCtx)
		t.Targets = append(t.Targets, reqsByFuzz...)
	} else if t.Config.PathByFuzz {
		reqsByFuzz := GetPathsByFuzz(*t.Targets[0], *t.TaskCtx)
		logger.Info("get paths by fuzzing:%d", len(reqsByFuzz))
		t.Targets = append(t.Targets, reqsByFuzz...)
	}
	t.Result.AllReqList = t.Targets[:]
	var initTasks []*model.Request

	for _, req := range t.Targets {
		if t.smartFilter.DoFilter(req) {
			logger.Debug("filter req: %s", req.URL.RequestURI())
			continue
		}
		initTasks = append(initTasks, req)
		t.Result.ReqList = append(t.Result.ReqList, req)
	}

	logger.Info("filter repeat, target count: %d", len(initTasks))

	for _, req := range initTasks {
		if !FilterKey(req.URL.String(), t.Config.IgnoreKeywords) {
			t.addTask2Pool(req)
		}
	}

	t.taskWG.Wait()

	if len(t.Result.AllReqList) != 0 {

		// 全部域名
		t.Result.AllDomainList = AllDomainCollect(t.Result.AllReqList)
		// 子域名
		t.Result.SubDomainList = SubDomainCollect(t.Result.AllReqList, t.RootDomain)
	}

}

/*
*
添加任务到协程池
添加之前实时过滤
*/
func (t *CrawlerTask) addTask2Pool(req *model.Request) {
	logger.Info("运行 addTask2Pool 当前爬虫数%d", t.crawledCount)
	t.taskCountLock.Lock()
	// defer t.taskCountLock.Unlock()
	if t.crawledCount >= t.Config.MaxCrawlCount {
		t.taskCountLock.Unlock()
		return
	} else {
		t.crawledCount += 1
	}
	t.taskCountLock.Unlock()

	t.taskWG.Add(1)
	task := t.generateTabTask(req)

	go func() {
		err := t.Pool.Submit(task.Task)
		if err != nil {
			logger.Error("addTask2Pool ", err)
			t.taskWG.Done()
		}
	}()
}

func (c *CrawlerTask) Waitforsingle() {
	select {
	case <-(*c.TaskCtx).Done():
		logger.Warning("%s 此网站受到当前任务现场回收原因,爬虫结束", c.RootDomain)
	case <-(*c.Ctx).Done():
		logger.Info("%s 此网站爬虫正常结束", c.RootDomain)
	}
}

/*
*
单个运行的tab标签任务，实现了workpool的接口
*/
func (t *tabTask) Task() {
	//fmt.Printf("开始扫描网站:%s", (*t).req.URL.String())
	defer t.crawlerTask.taskWG.Done()
	config := TabConfig{
		TabRunTimeout:           t.crawlerTask.Config.TabRunTimeout,
		DomContentLoadedTimeout: t.crawlerTask.Config.DomContentLoadedTimeout,
		EventTriggerMode:        t.crawlerTask.Config.EventTriggerMode,
		EventTriggerInterval:    t.crawlerTask.Config.EventTriggerInterval,
		BeforeExitDelay:         t.crawlerTask.Config.BeforeExitDelay,
		EncodeURLWithCharset:    t.crawlerTask.Config.EncodeURLWithCharset,
		IgnoreKeywords:          t.crawlerTask.Config.IgnoreKeywords,
		CustomFormValues:        t.crawlerTask.Config.CustomFormValues,
		CustomFormKeywordValues: t.crawlerTask.Config.CustomFormKeywordValues,
		Ratelimite:              &t.Ratelimite,
		IsHTTPS:                 t.crawlerTask.IsHTTPS,
		Scandeep:                int(t.crawlerTask.Config.ScanDepth),
		WebsitFileList:          t.WebSiteFileList,
	}
	tab, _ := NewTab(t.browser, *t.req, config)

	tab.Crawler(nil)

	if len(tab.ResultList) == 0 {
		return
	}

	if tab.ResultList[0] == nil {
		return
	}
	// 收集结果
	//t.crawlerTask.Result.resultLock.Lock()
	//defer t.crawlerTask.Result.resultLock.Unlock()
	t.crawlerTask.Result.AllReqList = append(t.crawlerTask.Result.AllReqList, tab.ResultList...)
	*t.crawledCount -= 1
	logger.Info("当前爬虫完成,剩余爬虫数:%d", (*t.crawledCount))

	if util.CtxDone(*t.crawlerTask.TaskCtx, time.Second*2) {
		return
	}

	for _, req := range tab.ResultList {
		logger.Debug("Filter Request:%s", req.URL.String())
		if t.crawlerTask.Config.FilterMode == SimpleFilterMode {
			if !t.crawlerTask.smartFilter.SimpleFilter.DoFilter(req) {
				//t.crawlerTask.Result.resultLock.Lock()
				t.crawlerTask.Result.ReqList = append(t.crawlerTask.Result.ReqList, req)
				//t.crawlerTask.Result.resultLock.Unlock()
				if !FilterKey(req.URL.String(), t.crawlerTask.Config.IgnoreKeywords) {
					t.crawlerTask.addTask2Pool(req)
					//这里通知进度条
					if t.IsSocket {
						util.SendToSocket(t.SocketMsg, craw_flag, "crawler", req.URL.String())
					}
				}
			}
		} else {
			if !t.crawlerTask.smartFilter.DoFilter(req) {
				//t.crawlerTask.Result.resultLock.Lock()
				t.crawlerTask.Result.ReqList = append(t.crawlerTask.Result.ReqList, req)
				//t.crawlerTask.Result.resultLock.Unlock()
				if !FilterKey(req.URL.String(), t.crawlerTask.Config.IgnoreKeywords) {
					t.crawlerTask.addTask2Pool(req)
					//这里通知进度条
					if t.IsSocket {
						util.SendToSocket(t.SocketMsg, craw_flag, "crawler", req.URL.String())
					}
				}
			}
		}
	}
	logger.Debug("Filter Over")
}

/*
*
新建爬虫任务
*/
func NewCrawlerTask(ctx *context.Context, target *model.Request, taskConf config.TaskConfig, socketMsg *chan map[string]interface{}) (*CrawlerTask, error) {
	mctx, cancel := context.WithCancel(context.Background())
	crawlerTask := CrawlerTask{
		Result: &Result{},
		Config: &taskConf.Yaml,
		smartFilter: SmartFilter{
			SimpleFilter: SimpleFilter{
				HostLimit: target.URL.Host,
			},
		},
		TaskCtx:   ctx,
		Ctx:       &mctx,
		Cancel:    &cancel,
		SocketMsg: socketMsg,
	}

	// _newReq := *target
	// newReq := &_newReq
	// _newURL := *_newReq.URL
	// newReq.URL = &_newURL

	if strings.EqualFold(target.URL.Scheme, "http") {
		target.URL.Scheme = "https"
		if util.PageExists(target.URL.String()) {
			target.URL.Scheme = "https"
			crawlerTask.IsHTTPS = true
		} else {
			target.URL.Scheme = "http"
		}
	} else {
		if util.PageExists(target.URL.String()) {
			target.URL.Scheme = "https"
			crawlerTask.IsHTTPS = true
		} else {
			target.URL.Scheme = "http"
		}
	}

	crawlerTask.Targets = append(crawlerTask.Targets, target)

	// crawlerTask.Targets = targets[:]

	for _, req := range crawlerTask.Targets {
		req.Source = config.FromTarget
	}

	if taskConf.Yaml.TabRunTimeout == 0 {
		taskConf.Yaml.TabRunTimeout = config.TabRunTimeout
	}

	if taskConf.Yaml.MaxTabsCount == 0 {
		taskConf.Yaml.MaxTabsCount = config.MaxTabsCount
	}

	if taskConf.Yaml.FilterMode == config.StrictFilterMode {
		crawlerTask.smartFilter.StrictMode = true
	}

	if taskConf.Yaml.MaxCrawlCount == 0 {
		taskConf.Yaml.MaxCrawlCount = config.MaxCrawlCount
	}

	if taskConf.Yaml.DomContentLoadedTimeout == 0 {
		taskConf.Yaml.DomContentLoadedTimeout = config.DomContentLoadedTimeout
	}

	if taskConf.Yaml.EventTriggerInterval == 0 {
		taskConf.Yaml.EventTriggerInterval = config.EventTriggerInterval
	}

	if taskConf.Yaml.BeforeExitDelay == 0 {
		taskConf.Yaml.BeforeExitDelay = config.BeforeExitDelay
	}

	if taskConf.Yaml.EventTriggerMode == "" {
		taskConf.Yaml.EventTriggerMode = config.DefaultEventTriggerMode
	}

	if len(taskConf.Yaml.IgnoreKeywords) == 0 {
		taskConf.Yaml.IgnoreKeywords = config.DefaultIgnoreKeywords
	}

	if taskConf.Yaml.ExtraHeadersString != "" {
		err := json.Unmarshal([]byte(taskConf.Yaml.ExtraHeadersString), &taskConf.Yaml.ExtraHeaders)
		if err != nil {
			logger.Error("custom headers can't be Unmarshal.")
			return nil, err
		}
	}

	crawlerTask.Browser = InitSpider(taskConf.Yaml.ChromiumPath, taskConf.Yaml.IncognitoContext, taskConf.Yaml.ExtraHeaders, taskConf.Yaml.Proxy)
	crawlerTask.RootDomain = target.URL.RootDomain()
	crawlerTask.HostName = target.URL.Hostname()
	crawlerTask.Scheme = target.URL.Scheme
	crawlerTask.QPS = taskConf.Yaml.Qps
	crawlerTask.smartFilter.Init()

	// 创建协程池
	p, _ := ants.NewPool(taskConf.Yaml.MaxTabsCount)
	crawlerTask.Pool = p
	//fmt.Println(target.Headers)
	// target.Headers = taskConf.Yaml.ExtraHeaders
	return &crawlerTask, nil
}
