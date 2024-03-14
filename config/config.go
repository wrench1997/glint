package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"time"

	mapset "github.com/deckarep/golang-set"
	"gopkg.in/yaml.v2"
)

const (
	DefaultUA               = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36"
	MaxTabsCount            = 10
	TabRunTimeout           = 20 * time.Second
	DefaultInputText        = "Crawlergo"
	FormInputKeyword        = "Crawlergo"
	SuspectURLRegex         = `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	URLRegex                = `((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]`
	AttrURLRegex            = ``
	DomContentLoadedTimeout = 5 * time.Second
	EventTriggerInterval    = 100 * time.Millisecond // 单位毫秒
	BeforeExitDelay         = 1 * time.Second
	DefaultEventTriggerMode = EventTriggerAsync
	MaxCrawlCount           = 100
)

// 请求方法
const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	DELETE  = "DELETE"
	HEAD    = "HEAD"
	OPTIONS = "OPTIONS"
)

var PassiveProxy bool

// 过滤模式
const (
	SimpleFilterMode = "simple"
	SmartFilterMode  = "smart"
	StrictFilterMode = "strict"
)

// 事件触发模式
const (
	EventTriggerAsync = "async"
	EventTriggerSync  = "sync"
)

var IsSensorServerEnabled bool = true

// 请求的来源
const (
	FromTarget      = "Target"     //初始输入的目标
	FromNavigation  = "Navigation" //页面导航请求·
	FromXHR         = "XHR"        //ajax异步请求
	FromDOM         = "DOM"        //dom解析出来的请求
	FromJSFile      = "JavaScript" //JS脚本中解析
	FromFuzz        = "PathFuzz"   //初始path fuzz
	FromRobots      = "robots.txt" //robots.txt
	FromComment     = "Comment"    //页面中的注释
	FromWebSocket   = "WebSocket"
	FromEventSource = "EventSource"
	FromFetch       = "Fetch"
	FromHistoryAPI  = "HistoryAPI"
	FromOpenWindow  = "OpenWindow"
	FromHashChange  = "HashChange"
	FromStaticRes   = "StaticResource"
	FromStaticRegex = "StaticRegex"
)

// content-type
const (
	JSON       = "application/json"
	URLENCODED = "application/x-www-form-urlencoded"
	MULTIPART  = "multipart/form-data"
)

var StaticSuffix = []string{
	"png", "gif", "jpg", "mp4", "mp3", "mng", "pct", "bmp", "jpeg", "pst", "psp", "ttf",
	"tif", "tiff", "ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
	"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
	"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
	"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "txt", "dll", "ico",
	"gz2", "apk", "crt", "woff", "map", "woff2", "webp", "less", "dmg", "bz2", "otf", "swf",
	"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
}
var StaticSuffixSet mapset.Set

var ScriptSuffix = []string{
	"php", "asp", "jsp", "asa",
}

var DefaultIgnoreKeywords = []string{"logout", "quit", "exit"}
var AllowedFormName = []string{"default", "mail", "code", "phone", "username", "password", "qq", "id_card", "url", "date", "number"}

type ContinueResourceList []string

var InputTextMap = map[string]map[string]interface{}{
	"mail": {
		"keyword": []string{"mail"},
		"value":   "crawlergo@gmail.com",
	},
	"code": {
		"keyword": []string{"yanzhengma", "code", "ver", "captcha"},
		"value":   "123a",
	},
	"phone": {
		"keyword": []string{"phone", "number", "tel", "shouji"},
		"value":   "18812345678",
	},
	"username": {
		"keyword": []string{"name", "user", "id", "login", "account"},
		"value":   "crawlergo@gmail.com",
	},
	"password": {
		"keyword": []string{"pass", "pwd"},
		"value":   "Crawlergo6.",
	},
	"qq": {
		"keyword": []string{"qq", "wechat", "tencent", "weixin"},
		"value":   "123456789",
	},
	"IDCard": {
		"keyword": []string{"card", "shenfen"},
		"value":   "511702197409284963",
	},
	"url": {
		"keyword": []string{"url", "site", "web", "blog", "link"},
		"value":   "https://crawlergo.nice.cn/",
	},
	"date": {
		"keyword": []string{"date", "time", "year", "now"},
		"value":   "2018-01-01",
	},
	"number": {
		"keyword": []string{"day", "age", "num", "count"},
		"value":   "10",
	},
}

type TaskConfig struct {
	Yaml       TaskYamlConfig
	Json       TaskJsonConfig
	JsonOrYaml bool // 0 json   1 yaml
}

type TaskYamlConfig struct {
	MaxCrawlCount           int                    `yaml:"MaxCrawlCount"` // 最大爬取的数量
	FilterMode              string                 `yaml:"FilterMode"`    // simple、smart、strict
	DBName                  string                 `yaml:"DBName"`        //数据库名
	DBUser                  string                 `yaml:"DBUser"`        //数据库用户名
	DBPassWord              string                 `yaml:"DBPassWord"`    //数据库密码
	ExtraHeaders            map[string]interface{} `yaml:"ExtraHeaders"`
	ExtraHeadersString      string                 `yaml:"ExtraHeadersString"`
	AllDomainReturn         bool                   `yaml:"AllDomainReturn"`  // 全部域名收集
	SubDomainReturn         bool                   `yaml:"SubDomainReturn"`  // 子域名收集
	IncognitoContext        bool                   `yaml:"IncognitoContext"` // 开启隐身模式
	NoHeadless              bool                   `yaml:"NoHeadless"`       // headless模式
	DomContentLoadedTimeout time.Duration          `yaml:"DomContentLoadedTimeout"`
	TabRunTimeout           time.Duration          `yaml:"TabRunTimeout"`           // 单个标签页超时
	ScriptTimeout           time.Duration          `yaml:"ScriptTimeout"`           // 单条脚本超时
	PathByFuzz              bool                   `yaml:"PathByFuzz"`              // 通过字典进行Path Fuzz
	FuzzDictPath            string                 `yaml:"FuzzDictPath"`            // Fuzz目录字典
	PathFromRobots          bool                   `yaml:"PathFromRobots"`          // 解析Robots文件找出路径
	MaxTabsCount            int                    `yaml:"MaxTabsCount"`            // 允许开启的最大标签页数量 即同时爬取的数量
	ChromiumPath            string                 `yaml:"ChromiumPath"`            // Chromium的程序路径  `/home/zhusiyu1/chrome-linux/chrome`
	EventTriggerMode        string                 `yaml:"EventTriggerMode"`        // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration          `yaml:"EventTriggerInterval"`    // 事件触发的间隔
	BeforeExitDelay         time.Duration          `yaml:"BeforeExitDelay"`         // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool                   `yaml:"EncodeURLWithCharset"`    // 使用检测到的字符集自动编码URL
	IgnoreKeywords          []string               `yaml:"IgnoreKeywords"`          // 忽略的关键字，匹配上之后将不再扫描且不发送请求
	Proxy                   string                 `yaml:"Proxy"`                   // 请求代理
	CustomFormValues        map[string]interface{} `yaml:"CustomFormValues"`        // 自定义表单填充参数
	CustomFormKeywordValues map[string]interface{} `yaml:"CustomFormKeywordValues"` // 自定义表单关键词填充内容
	XssPayloads             map[string]interface{} `yaml:"XssPayloads"`             // 自定义xss的payload数据
	InstallDb               bool                   `yaml:"InstallDb"`
	EnableCrawler           bool                   `yaml:"EnableCrawler"`
	ProxyPort               int64                  `yaml:"ProxyPort"`
	Qps                     int64                  `yaml:"qps"`                 //每秒最大请求数 qps以下的是主动扫描被动共享
	ScanDepth               int64                  `yaml:"scan_depth"`          //扫描深度
	Max_redirect_times      int64                  `yaml:"max_redirect_times"`  //最大重定向次数
	Response_Size           int64                  `yaml:"response_size"`       //最大重定向次数
	Anti_chain_platform     string                 `yaml:"anti_chain_platform"` //反链平台
	Api_token               string                 `yaml:"api_token"`           //反链平台API Token
	User_dic_id             int64                  `yaml:"user_dic_id"`         //
	Pwd_dic_id              int64                  `yaml:"pwd_dic_id"`          //
	Cert                    string                 `yaml:"server_pem_path"`     //https证书路径
	CertKey                 string                 `yaml:"server_key_path"`     //https证书的私钥路径
}

type TaskJsonConfig struct {
	Exweb_scan_param  Exweb_scan_param    `json:"exweb_scan_param"`
	Exweb_target_info []Exweb_target_info `json:"exweb_target_info"`
	Exweb_task_info   Exweb_task_info     `json:"exweb_task_info"`
}

type Exweb_target_info struct {
	Scan_target  string      `json:"scan_target"`
	Target_id    json.Number `json:"target_id"`
	Target_order json.Number `json:"target_order"`
	Task_id      json.Number `json:"task_id"`
}

type Exweb_task_info struct {
	Create_time string      `json:"create_time"`
	End_time    string      `json:"end_time"`
	Scan_time   string      `json:"scan_time"`
	Start_time  string      `json:"start_time"`
	Task_id     json.Number `json:"task_id"`
	Task_name   string      `json:"task_name"`
}

type Exweb_scan_param struct {
	Anti_chain_platform   string      `json:"anti_chain_platform"`
	Api_token             string      `json:"api_token"`
	Cookie                string      `json:"cookie"`
	Domain_identificate   string      `json:"domain_identificate"`
	Allow_domain          string      `json:"allow_domain"`
	Forbit_domain         string      `json:"forbit_domain"`
	Forbit_path           string      `json:"forbit_path"`
	Forbit_port           string      `json:"forbit_port"`
	Http_proxy            string      `json:"http_proxy"`
	TabRunTimeout         json.Number `json:"TabRunTimeout"` // 单个标签页超时
	Http_response_timeout json.Number `json:"http_response_timeout"`
	Max_redirect_times    json.Number `json:"max_redirect_times"`
	Qps                   json.Number `json:"qps"`
	Max_wait_request      json.Number `json:"max_wait_request"`
	Param_model_id        json.Number `json:"param_model_id"`
	Plugin_thread_num     json.Number `json:"plugin_thread_num"`
	Response_Size         json.Number `json:"response_size"`
	Scan_depth            json.Number `json:"scan_depth"`
	Task_id               json.Number `json:"task_id"`
	Tcp_conn_timeout      json.Number `json:"tcp_conn_timeout"`
	User_agent            string      `json:"user_agent"`
	Web_param_id          json.Number `json:"web_param_id"`
	ScriptTimeout         json.Number `yaml:"script_timeout"` // 单条脚本超时
}

// 数据库配置203
const (
	Ip   = "127.0.0.1"
	Port = "3306"
)

const (
	DefaultConfigPath    string = "itop_task.json"
	DefaultXssConfigPath string = "xss.yaml"
	TesXssConfigPath     string = "../xss.yaml"
	DefaultSocket        string = ""
	DefaultConfigType    string = "json"
	ConfirmSocket        bool   = true
	UnconfirmSocket      bool   = false
	EnableJackdaw        bool   = false
)

var GlobalUserNameList = []string{}
var GlobalPasswordList = []string{}
var CeyeDomain string
var CeyeApiToken string

type SqlInject struct {
	Attacktype     string   `yaml:"attacktype"`
	Attackpayloads []string `yaml:"attackpayloads"`
}

func ReadResultConf(file string) (map[string]interface{}, error) {
	jsonFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	// FileJsonUrls := make(map[string]interface{})
	// err = json.Unmarshal([]byte(byteValue), data)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	var personFromJSON interface{}

	decoder := json.NewDecoder(bytes.NewReader(byteValue))
	decoder.UseNumber()
	decoder.Decode(&personFromJSON)

	r := personFromJSON.(map[string]interface{})

	return r, err
}

func ReadJsonConfig(FilePATH string) (TaskJsonConfig, error) {

	jsonFile, err := os.Open(FilePATH)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer jsonFile.Close()
	byteValue, _ := ioutil.ReadAll(jsonFile)
	JsonObj := TaskJsonConfig{}
	// a := make(map[string]interface{})
	// json.Unmarshal(byteValue, &a)
	d := json.NewDecoder(bytes.NewReader(byteValue))
	d.UseNumber()
	err = d.Decode(&JsonObj)
	if err != nil {
		panic(err)
	}

	return JsonObj, nil
}

func ReadYamlTaskConf(file string, TaskConfig *TaskYamlConfig) error {
	YamlFile, err := os.Open(file)
	if err != nil {
		fmt.Println(err)
	}
	// 要记得关闭
	defer YamlFile.Close()
	byteValue, _ := ioutil.ReadAll(YamlFile)
	// FileJsonUrls := make(map[string]interface{})
	err = yaml.Unmarshal([]byte(byteValue), TaskConfig)
	if err != nil {
		fmt.Println(err)
	}
	return err
}

func (tc *TaskConfig) GetValue(key string) (reflect.Value, error) {
	//var err error
	var value reflect.Value

	if tc.JsonOrYaml {
		//Yaml
		t := reflect.TypeOf(tc.Yaml)
		v := reflect.ValueOf(tc.Yaml) //获取reflect.Type类型
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanInterface() { //判断是否为可导出字段
				//判断是否是嵌套结构
				if strings.EqualFold(t.Field(i).Name, key) {
					return v.Field(i), nil
				}
			}
		}

	} else {
		t := reflect.TypeOf(tc.Json.Exweb_scan_param)
		v := reflect.ValueOf(tc.Json.Exweb_scan_param) //获取reflect.Type类型
		for i := 0; i < v.NumField(); i++ {
			if v.Field(i).CanInterface() { //判断是否为可导出字段
				if strings.EqualFold(t.Field(i).Name, key) {
					return v.Field(i), nil
				}
			}
		}

	}

	// t := reflect.TypeOf(*tc)
	// v := reflect.ValueOf(*tc) //获取reflect.Type类型

	// for i := 0; i < v.NumField(); i++ {
	// 	if v.Field(i).CanInterface() { //判断是否为可导出字段
	// 		//判断是否是嵌套结构
	// 		if v.Field(i).Type().Kind() == reflect.Struct {
	// 			structField := v.Field(i).Type()
	// 			for j := 0; j < structField.NumField(); j++ {
	// 				fmt.Printf("%s %s = %v -tag:%s \n",
	// 					structField.Field(j).Name,
	// 					structField.Field(j).Type,
	// 					v.Field(i).Field(j).Interface(),
	// 					structField.Field(j).Tag)
	// 			}
	// 			continue
	// 		}

	// 	}
	// }

	return value, fmt.Errorf("not value")
}
