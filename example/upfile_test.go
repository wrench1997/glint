package mydemo

import (
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/pocs/upfile"
	"glint/plugin"
	"glint/util"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestUPFILE(t *testing.T) {
	logger.DebugEnable(true)
	var PluginWg sync.WaitGroup
	data, _ := config.ReadResultConf("./json_testfile/file_upload.json")
	myfunc := []plugin.PluginCallback{}
	myfunc = append(myfunc, upfile.UpfileVaild)

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
		PluginName:   "UPFile",
		PluginId:     plugin.UPFile,
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

func Test_httpfileparser(t *testing.T) {
	msg := &mail.Message{
		Header: map[string][]string{
			"Content-Type": []string{"multipart/mixed; boundary=foo"},
		},
		Body: strings.NewReader(
			"--foo\r\nFoo: one\r\n\r\nA section\r\n" +
				"--foo\r\nFoo: two\r\n\r\nAnd another\r\n" +
				"--foo--\r\n"),
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		log.Fatal("1 :", err)
	}
	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			p, err := mr.NextPart() //p的类型为Part

			if err == io.EOF {
				return
			}
			if err != nil {
				log.Fatal("2 :", err)
			}
			slurp, err := ioutil.ReadAll(p)
			if err != nil {
				log.Fatal("3 :", err)
			}
			fmt.Printf("Part %q: %q\n", p.Header.Get("Foo"), slurp)
		}
	}
}
