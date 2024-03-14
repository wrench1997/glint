package mydemo

import (
	"bufio"
	"fmt"
	"sync"
	"time"

	"glint/config"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/pocs/xsschecker"
	"glint/plugin"
	"glint/util"
	"net/http"
	_ "net/http/pprof"
	"testing"

	"github.com/google/martian/v3/har"
	"github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"github.com/valyala/bytebufferpool"
)

func TestXSS(t *testing.T) {
	logger.DebugEnable(false)

	// go func() {
	// 	ip := "0.0.0.0:6061"
	// 	if err := http.ListenAndServe(ip, nil); err != nil {
	// 		fmt.Printf("start pprof failed on %s\n", ip)
	// 	}
	// }()

	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = false
	TaskYamlConfig.TabRunTimeout = 1000 * time.Second
	TaskYamlConfig.ScanDepth = 10
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	Spider := nenet.Spider{}

	err := Spider.Init(TaskConfig)
	if err != nil {
		t.Fatal(err)
	}
	// defer Spider.Close()
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("../json_testfile/xss_pikachu.json")

	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, xsschecker.CheckXss)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   "XSS",
		PluginId:     plugin.Xss,
		MaxPoolCount: 1,
		// Callbacks:    myfunc,
		Spider:  &Spider,
		Timeout: time.Second * 200,
	}
	pluginInternal.Init()
	pluginInternal.Callbacks = myfunc

	PluginWg.Add(1)
	Progress := 0.0
	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	pluginmsg := make(chan map[string]interface{}, 1)

	args := plugin.PluginOption{
		PluginWg:  &PluginWg,
		Progress:  &Progress,
		IsSocket:  false,
		Data:      data,
		TaskId:    999,
		Config:    TaskConfig,
		Rate:      &Ratelimite,
		SingelMsg: &pluginmsg,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}

	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
	Spider.Close()
	// errc := make(chan error, 1)
	// // go func() {
	// // 	errc <- s.Serve(l)
	// // }()
	// sigs := make(chan os.Signal, 1)
	// signal.Notify(sigs, os.Interrupt)

	// select {
	// case err := <-errc:
	// 	logger.Error("failed to serve: %v", err)
	// case sig := <-sigs:
	// 	logger.Error("terminating: %v", sig)
	// }

}

func TestURL(t *testing.T) {
}

func checkInnerHTML(code string) bool {
	lexer := js.NewLexer(parse.NewInputString(code))
	for {
		tt, text := lexer.Next()
		fmt.Printf("的类型为:%T 内容为:%s \n", tt, string(text))
		if tt == js.ErrorToken {
			// 发生了错误，可能是无效的JavaScript代码
			return false
		} else if tt == js.ErrorToken {
			// 检查完毕，没有找到innerHTML
			return false
		} else if tt == js.IdentifierToken && string(text) == "innerHTML" {
			// 找到了innerHTML
			return true
		}
	}
}

func Test_JS(t *testing.T) {
	script := `window.onload= function(){ 
		var oBox=document.getElementById("box");
		var oSpan=document.getElementById("span1");
		var oText=document.getElementById("text1");
		var oBtn=document.getElementById("Btn");
		oBtn.onclick = function(){
			oBox.innerHTML = oBox.innerHTML + oSpan.innerHTML + oText.value + "<br/>";
			// oBox.innerHTML += oSpan.innerHTML + oText.value +  "<br/>";//这是简便的写法,在js中 a=a+b ,那么也等同于 a+=b
			oText.value=""
		};
	}`
	if checkInnerHTML(script) {
		// 发现了innerHTML的使用
	}
}

type httpWriter interface {
	Write(w *bufio.Writer) error
}

func getHTTPString(hw httpWriter) string {
	w := bytebufferpool.Get()
	bw := bufio.NewWriter(w)
	if err := hw.Write(bw); err != nil {
		return err.Error()
	}
	if err := bw.Flush(); err != nil {
		return err.Error()
	}
	s := string(w.B)
	bytebufferpool.Put(w)
	return s
}

func Test_har_log(t *testing.T) {

	var nhreq har.Request
	nhreq.HTTPVersion = "HTTP/1.1"
	nhreq.Method = "POST"
	nhreq.URL = "http://localhost:5451"
	req, _ := http.NewRequest("GET", "http://api.themoviedb.org/3/tv/popular", nil)
	req.Header.Add("Accept", "application/json")
	// getHTTPString(&req)
	// httputil.DumpRequest()

}
