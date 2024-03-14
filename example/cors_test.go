package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/cors"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func TestCORS(t *testing.T) {
	logger.DebugEnable(false)
	// go func() {
	// 	ip := "0.0.0.0:6060"
	// 	if err := http.ListenAndServe(ip, nil); err != nil {
	// 		fmt.Printf("start pprof failed on %s\n", ip)
	// 	}
	// }()

	//Spider := brohttp.Spider{}
	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("../json_testfile/cors_test1.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, cors.Cors_Valid)

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   "CROS",
		PluginId:     plugin.CORS,
		MaxPoolCount: 1,
		// Callbacks:    myfunc,
		Spider:  nil,
		Timeout: time.Second * 999,
	}
	pluginInternal.Init()
	pluginInternal.Callbacks = myfunc
	PluginWg.Add(1)
	Progress := 0.0

	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	args := plugin.PluginOption{
		PluginWg:      &PluginWg,
		Progress:      &Progress,
		IsSocket:      false,
		Data:          data,
		TaskId:        999,
		IsAllUrlsEval: false,
		Rate:          &Ratelimite,
		Config:        TaskConfig,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}

	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
