package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	webapp "glint/pkg/pocs/webapps"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func TestStruts2045(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/craw_test.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, webapp.Struts2_045_Vaild)

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
		PluginName:   "Struts2_s2045",
		PluginId:     plugin.Struts2,
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
}
