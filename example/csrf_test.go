package mydemo

import (
	"fmt"
	"glint/config"
	"glint/pkg/pocs/csrf"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_CSRF(t *testing.T) {

	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("../json_testfile/fileinclude_dvwa.json")
	myfunc := []plugin.PluginCallback{}
	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = "127.0.0.1:7777"
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Minute
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	myfunc = append(myfunc, csrf.Csrfeval)
	pluginInternal := plugin.Plugin{
		PluginName:   "Csrf",
		PluginId:     plugin.Csrf,
		MaxPoolCount: 20,
		Callbacks:    myfunc,
		Timeout:      200 * time.Second,
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
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}

	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
