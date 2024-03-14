package main

import (
	"context"
	"fmt"
	"glint/ast"
	"glint/config"
	"glint/crawler"
	craw "glint/crawler"
	"glint/logger"
	"glint/model"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/thoas/go-funk"
)

func Test_Crawler(t *testing.T) {
	logger.DebugEnable(false)

	var TaskConfig config.TaskConfig

	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.Yaml.MaxCrawlCount = 100
	TaskConfig.JsonOrYaml = true
	TaskConfig.Yaml.MaxTabsCount = 10
	TaskConfig.Yaml.FilterMode = "smart"
	TaskConfig.Yaml.Response_Size = 10240
	var Results []*crawler.Result
	ctx, _ := context.WithCancel(context.Background())
	// actx, acancel := context.WithTimeout(ctx, TaskConfig.TabRunTimeout)
	// defer acancel()
	err := config.ReadYamlTaskConf("config.yaml", &TaskYamlConfig)
	if err != nil {
		t.Errorf("test ReadTaskConf() fail")
	}
	murl, _ := url.Parse("http://192.168.166.2/pikachu/")
	Headers := make(map[string]interface{})
	//Headers["Cookie"] = "_ga=GA1.1.1124483291.1669624307; _gid=GA1.1.808795582.1672713209; JSESSIONID=20632F5E43D1443AF411906D81797D27; _ga_34B604LFFQ=GS1.1.1672818029.53.1.1672818075.14.0.0"
	targets := &model.Request{
		URL:           &model.URL{URL: *murl},
		Method:        "GET",
		FasthttpProxy: TaskConfig.Yaml.Proxy,
		Headers:       Headers,
	}
	PliuginsMsg := make(chan map[string]interface{}, 1)
	task, err := crawler.NewCrawlerTask(&ctx, targets, TaskConfig, &PliuginsMsg)
	if err != nil {
		t.Errorf("create crawler task failed.")
		os.Exit(-1)
	}
	msg := fmt.Sprintf("Init crawler task, host: %s, max tab count: %d, max crawl count: %d.",
		targets.URL.Host, TaskConfig.Yaml.MaxTabsCount, TaskConfig.Yaml.MaxCrawlCount)
	logger.Info(msg)
	logger.Info("filter mode: %s", TaskConfig.Yaml.FilterMode)
	logger.Info("Start crawling.")
	go task.Run()
	task.Waitforsingle()
	result := task.Result
	// for _, rest := range result.AllReqList {
	// 	fmt.Println(aurora.Red(rest))
	// }
	ReqList := make(map[string][]ast.JsonUrl)
	ALLURLS := make(map[string][]interface{})
	URLSList := make(map[string]interface{})

	//ALLURLS := make(map[string][]interface{})
	ALLURI := make(map[string][]interface{})
	// URLSList := make(map[string]interface{})
	// URISList := make(map[string]interface{})

	mresult := task.Result
	mresult.Hostid = task.Result.Hostid
	mresult.HOSTNAME = task.HostName
	fmt.Printf("爬取 %s 域名结束", task.HostName)
	Results = append(Results, mresult)

	CrawlerConvertToMap(Results, &ALLURI, nil, true)

	funk.Map(result.ReqList, func(r *model.Request) bool {
		// element := make(map[string]interface{})
		element := ast.JsonUrl{
			Url:     r.URL.String(),
			MetHod:  r.Method,
			Headers: r.Headers,
			Data:    r.PostData,
			Source:  r.Source}
		ReqList[r.GroupsId] = append(ReqList[r.GroupsId], element)
		return false
	})
	ast.SaveCrawOutPut(ReqList, "./json_testfile/craw_test.json")
	CrawlerConvertToMap(Results, &ALLURLS, nil, false)
	for s, v := range ReqList {
		URLSList[s] = v
	}
	fmt.Println("PASS")
}

func Test_filter(t *testing.T) {
	const url = `https://ka-f.fontawesome.com/releases/v5.15.4/webfonts/free-fa-solid-900.woff2`
	if craw.FilterKey(url, craw.ForbidenKey) {
	} else {
		t.Errorf("test FilterKey() fail")
	}
}

func writeHTML(content string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		io.WriteString(w, strings.TrimSpace(content))
	})
}

func GetExecutor(Ctx *context.Context) context.Context {
	c := chromedp.FromContext(*Ctx)
	ctx := cdp.WithExecutor(*Ctx, c.Target)
	return ctx
}

func ExampleAllocSubContextWithTimeOut() {

	opts := []chromedp.ExecAllocatorOption{
		chromedp.Flag("headless", false),
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
		// chromedp.ModifyCmdFunc(func(cmd *exec.Cmd) {
		// 	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
		// }),

		chromedp.UserAgent(`Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36`),
	}

	actx, acancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer acancel()

	ctx, cancel := chromedp.NewContext(actx)
	defer cancel()

	// time.Sleep(time.Second * 4)

	ts := httptest.NewServer(writeHTML(`
<head>
	<title>fancy website title</title>
</head>
<body>
	<div id="content"></div>
</body>
	`))
	defer ts.Close()

	var title string
	if err := chromedp.Run(ctx,
		chromedp.Navigate(ts.URL),
		chromedp.Title(&title),
	); err != nil {
		fmt.Println(err)
	}
	//fmt.Println(title)

	subctx0 := GetExecutor(&ctx)

	subctx, cancel0 := context.WithCancel(subctx0)
	defer cancel0()

	ctx1, cancel1 := context.WithTimeout(subctx, time.Second*10)
	defer cancel1()

	// 收集 src href data-url 属性值
	attrNameList := []string{"href", "src", "data-url", "data-href"}
	for _, attrName := range attrNameList {
		var attrs []map[string]string
		//attrs := make(map[string]string)
		err := chromedp.AttributesAll(fmt.Sprintf(`[%s]`, attrName), &attrs, chromedp.BySearch).Do(ctx1)
		if err != nil {
			logger.Warning("collectHrefLinks %s", err.Error())
			break
		}
	}

	subctx1 := GetExecutor(&ctx)

	ctx2, cancel2 := crawler.AllocSubContextWithTimeOut(subctx1, time.Second*10)
	defer cancel2()
	// c := chromedp.FromContext(ctx1,
	// ctx := cdp.WithExecutor(*tab.Ctx, c.Target)
	// return ctx

	if err := chromedp.Run(ctx2,
		chromedp.Navigate(ts.URL),
		chromedp.Title(&title),
	); err != nil {
		log.Fatal(err)
	}
	//fmt.Println(title)

	// Output:
	// fancy website title
}
