package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/nmapSsl"
	"glint/plugin"
	"glint/util"
	"net/http"
	"sync"
	"testing"
	"time"
)

func Test_TLS(t *testing.T) {
	logger.DebugEnable(false)
	go func() {
		ip := "0.0.0.0:6060"
		if err := http.ListenAndServe(ip, nil); err != nil {
			fmt.Printf("start pprof failed on %s\n", ip)
		}
	}()

	var TaskConfig config.TaskConfig

	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 2
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	//Spider := brohttp.Spider{}
	err := config.ReadYamlTaskConf("config.yaml", &TaskYamlConfig)
	if err != nil {
		t.Errorf("test ReadTaskConf() fail")
	}
	// taskconfig.
	//err := Spider.Init(taskconfig)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	//defer Spider.Close()
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/Blibili.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, nmapSsl.TLSv0verify)
	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	pluginInternal := plugin.Plugin{
		PluginName:   "TLS",
		PluginId:     plugin.TLS,
		MaxPoolCount: 1,
		// Callbacks:    myfunc,
		//Spider:  &Spider,
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
		Rate:          &Ratelimite,
		Config:        TaskConfig,
		IsAllUrlsEval: true,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
