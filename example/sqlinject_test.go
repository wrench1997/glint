package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/sql"
	"glint/plugin"
	"glint/util"
	"sync"
	"testing"
	"time"
)

func TestSqlBlinddvwa(t *testing.T) {
	logger.DebugEnable(true)

	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/xss_test_zf.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, sql.Sql_inject_Vaild)

	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = "127.0.0.1:7777"
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	pluginInternal := plugin.Plugin{
		PluginName:   "SQL",
		PluginId:     plugin.SQL,
		MaxPoolCount: 5,
		Callbacks:    myfunc,
		Timeout:      999 * time.Second,
	}
	pluginInternal.Init()
	PluginWg.Add(1)
	Progress := 0.
	Ratelimite := util.Rate{}
	Ratelimite.InitRate(500)
	pluginmsg := make(chan map[string]interface{}, 1)

	args := plugin.PluginOption{
		PluginWg:  &PluginWg,
		Progress:  &Progress,
		IsSocket:  false,
		Data:      data,
		TaskId:    999,
		Rate:      &Ratelimite,
		Config:    TaskConfig,
		SingelMsg: &pluginmsg,
		// Sendstatus: &pluginInternal.PliuginsMsg,
	}
	go func() {
		pluginInternal.Run(args)
	}()
	PluginWg.Wait()
	fmt.Println("exit...")

	// errc := make(chan error, 1)
	// go func() {
	// 	errc <- s.Serve(l)
	// }()
	// sigs := make(chan os.Signal, 1)
	// signal.Notify(sigs, os.Interrupt)

	// select {
	// case err := <-errc:
	// 	logger.Error("failed to serve: %v", err)
	// case sig := <-sigs:
	// 	logger.Error("terminating: %v", sig)
	// }

}

func TestSqlTimeOut(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/sql_timeout.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, sql.Sql_inject_Vaild)

	var TaskConfig config.TaskConfig
	TaskYamlConfig := config.TaskYamlConfig{}
	TaskYamlConfig.Proxy = "127.0.0.1:7777"
	TaskYamlConfig.NoHeadless = true
	TaskYamlConfig.TabRunTimeout = 20 * time.Second
	TaskYamlConfig.ScanDepth = 4
	TaskConfig.Yaml = TaskYamlConfig
	TaskConfig.JsonOrYaml = true

	pluginInternal := plugin.Plugin{
		PluginName:   "SQL",
		PluginId:     plugin.SQL,
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

func Test_sql_math(t *testing.T) {
	x := 5 % 18
	println(x)
	var origValue = "swqedq"
	paramValue := origValue[:1] + "'||'" + origValue[1:]
	println(paramValue)
}
