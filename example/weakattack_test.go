package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/weakpwd"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func Test_WeakAttack(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/weakattack.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, weakpwd.StartTesting)
	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = ""
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 5
	// TaskYamlConfig.Max_redirect_times = 15
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	config.GlobalUserNameList = []string{"admin", "Admin", "root"}
	config.GlobalPasswordList = []string{"123456", "password", "root"}

	pluginInternal := plugin.Plugin{
		PluginName:   "WeakAttack",
		PluginId:     plugin.WeakPwdAttack,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      30 * time.Second,
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
