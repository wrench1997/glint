package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/directorytraversal"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_TraversalVaild(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/directoryTraversal_test1.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, directorytraversal.TraversalVaild)

	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	pluginInternal := plugin.Plugin{
		PluginName:   "DIR_COSS",
		PluginId:     plugin.DIR_COSS,
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
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")
}
