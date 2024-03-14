package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	lowsomething "glint/pkg/pocs/lowVuln"
	"glint/plugin"
	"glint/util"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"testing"
	"time"
)

func Test_lowSomething(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup

	// 定义处理函数，用于处理 HTTP 请求
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 定义要返回的网页内容
		content := `
			<html>
			<head>
			<title>Example</title>
			</head>
			<body>
			<h1>Hello, World!</h1>
			<!-- 使用 frame 标签嵌套网页 -->
			<frame src="http://www.example.com/frame1" />
			<!-- 使用 iframe 标签嵌套网页 -->
			<iframe src="http://www.example.com/iframe1" />
			</body>
			</html>
			`

		// 将网页内容写入响应体
		fmt.Fprintln(w, content)
	})

	// 监听 8081 端口
	go http.ListenAndServe(":8081", nil)

	time.Sleep(5 * time.Second)

	data, _ := config.ReadResultConf("./json_testfile/low_vuln.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, lowsomething.Jacking_X_Frame_Options_Valid)

	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true
	// VulnerableMsg := make(chan util.ScanResult)
	pluginInternal := plugin.Plugin{
		PluginName:   "LOW_Something",
		PluginId:     plugin.X_Frame_Options,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      999 * time.Second,
	}

	pluginInternal.Init()
	PluginWg.Add(1)
	Progress := 0.
	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	args := plugin.PluginOption{
		PluginWg: &PluginWg,
		Progress: &Progress,
		IsSocket: false,
		Data:     data,
		TaskId:   999,
		Rate:     &Ratelimite,
		Config:   TaskConfig,
		// VulnerableMsg: VulnerableMsg,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")

	// 创建一个信号通道，用于接收程序中断讯号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// 监听信号通道，当收到程序中断讯号时，打印信息并退出程序
	for {
		sig := <-sigChan
		if sig == os.Interrupt {
			fmt.Println("Received interrupt signal, exiting program...")
			os.Exit(0)
		}
	}

}
