package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"glint/config"
	"glint/dbmanager"
	"glint/global"
	"glint/logger"
	"glint/nenet"
	"glint/util"
	"strconv"
	"sync"
	"time"

	"github.com/panjf2000/ants/v2"
)

type Plugin_type string

var IsPauseScan bool = false

const (
	Xss              Plugin_type = "rj-001-0001"
	Csrf             Plugin_type = "rj-002-0001"
	Ssrf             Plugin_type = "rj-003-0001"
	Jsonp            Plugin_type = "rj-004-0001"
	CmdInject        Plugin_type = "rj-005-0001"
	Xxe              Plugin_type = "rj-006-0001"
	Crlf             Plugin_type = "rj-007-0001"
	CORS             Plugin_type = "rj-008-0001"
	SQL              Plugin_type = "rj-009-0001"
	TLS              Plugin_type = "rj-010-0001"
	APPERROR         Plugin_type = "rj-011-0001"
	CSP              Plugin_type = "rj-012-0001"
	DIR_COSS         Plugin_type = "rj-013-0001"
	CONTENTSEARCH    Plugin_type = "rj-014-0001"
	BigPwdAttack     Plugin_type = "rj-015-0001"
	WeakPwdAttack    Plugin_type = "rj-016-0001"
	Fileinclude      Plugin_type = "rj-017-0001"
	UPFile           Plugin_type = "rj-018-0001"
	Struts2          Plugin_type = "rj-019-0001"
	Deserialization  Plugin_type = "rj-020-0001"
	X_Frame_Options  Plugin_type = "rj-021-0001"
	Cookie_detection Plugin_type = "rj-022-0001"
	HSTS_detection   Plugin_type = "rj-023-0001"
	ParamPoll        Plugin_type = "rj-024-0001"
)

type Plugin struct {
	Taskid          int    //任务id,只有插入数据库的时候使用
	PluginName      string //插件名
	PluginId        Plugin_type
	MaxPoolCount    int                //协程池最大并发数
	Callbacks       []PluginCallback   //扫描插件函数
	Pool            *ants.PoolWithFunc //
	threadwg        sync.WaitGroup     //同步线程
	ScanResult      []*util.ScanResult
	mu              sync.Mutex
	Progperc        float64 //总进度百分多少
	Spider          *nenet.Spider
	InstallDB       bool //是否插入数据库
	Ctx             *context.Context
	Cancel          *context.CancelFunc
	Timeout         time.Duration        //插件总超时
	Onestimeout     time.Duration        //单条插件任务超时
	Dm              *dbmanager.DbManager //数据库句柄
	Rate            *util.Rate
	VulnerableMsg   *chan util.ScanResult
	IsEnableCutomJs bool           //是否开启自定义js
	jsthreadwg      sync.WaitGroup //js同步线程
	CustomJs        interface{}    //单独处理自定义js脚本，和meson通讯的桥梁
}

func (p *Plugin) ClearData() {
	p.Taskid = 0
	p.PluginName = ""
	p.PluginId = Plugin_type("")
	p.MaxPoolCount = 0
	p.Callbacks = p.Callbacks[:0]
	// p.Pool = nil
	p.threadwg = sync.WaitGroup{}
	p.ScanResult = p.ScanResult[:0]
	p.mu = sync.Mutex{}
	p.Progperc = 0
	p.Spider = nil
	p.InstallDB = false
	p.Ctx = nil
	p.Cancel = nil
	p.Timeout = 0
	p.Onestimeout = 0
	p.Dm = nil
	p.Rate = nil
	p.VulnerableMsg = nil
}

type PluginOption struct {
	PluginWg            *sync.WaitGroup
	Progress            *float64 //此任务总进度
	Totalprog           float64  //此插件占有的总进度
	IsSocket            bool     //是否与目标通讯
	IsSaveToJsonFile    bool     //是否保存json格式的报表文件
	Data                map[string]interface{}
	SingelMsg           *chan map[string]interface{}
	TaskId              int    //该插件所属的taskid
	Bstripurl           bool   //是否分开groupurl
	HttpsCert           string //
	HttpsCertKey        string //
	IsAllUrlsEval       bool   //是否传递所有URLS给当前某个漏洞插件传递。适合用于一个漏洞报告所有同域名的URLS
	AllUrlsCallMaxCount int    //某些插件一个插件调用多次
	Rate                *util.Rate
	Config              config.TaskConfig
	VulnerableMsg       chan util.ScanResult
	// AllowDomain      string //允许的URL通过
	// VulnerableMsg chan util.ScanResult
	// XssTimeOut   time.Duration //xss扫描总超时
}

type GroupData struct {
	GroupType        string
	UrlInfo          map[string]interface{}
	GroupUrls        []interface{}
	Spider           *nenet.Spider
	Pctx             *context.Context //
	Pcancel          *context.CancelFunc
	IsSocket         bool
	IsSaveToJsonFile bool
	SocketMsg        *chan map[string]interface{}
	VulnerableMsg    *chan *util.ScanResult
	HttpsCert        string //
	HttpsCertKey     string //
	Config           config.TaskConfig
	Rate             *util.Rate
	// util.ScanSiteState
}

// 通知接受线程内容
func (gd *GroupData) Alert(msg interface{}) {
	switch v := msg.(type) {
	case *util.ScanResult:
		select {
		case (*gd.VulnerableMsg) <- v:
		case <-time.After(time.Second * 2):
		}
	}
}

type ExceptionStruct struct {
	Try     func()
	Catch   func(Exception)
	Finally func()
}
type Exception interface{}

func Throw(up Exception) {
	logger.Error("%v", up)
	panic(up)
}
func (this ExceptionStruct) Do() {
	if this.Finally != nil {
		defer this.Finally()
	}
	if this.Catch != nil {
		defer func() {
			if e := recover(); e != nil {
				this.Catch(e)
				panic(e)
			}
		}()
	}
	this.Try()
}

func (p *Plugin) Init() {
	p.Pool, _ = ants.NewPoolWithFunc(p.MaxPoolCount, func(args interface{}) { //新建一个带有同类方法的pool对象
		defer p.threadwg.Done()
		var err error
		// VulnerableMsg := make(chan util.ScanResult)
		data := args.(*GroupData)
		// data.VulnerableMsg = &VulnerableMsg
		if !IsPauseScan {
			for _, f := range p.Callbacks {
				_, _, err = f(data)
				if err != nil {
					logger.Debug("plugin::error %s", err.Error())
				}
			}
			logger.Debug("the end of the plugin[%s]", p.PluginName)
		} else {
			logger.Debug("运行插件[%s]无法执行,因暂停指令开启", p.PluginName)
		}

	})
	ctx, cancel := context.WithTimeout(context.Background(), p.Timeout)
	p.Ctx = &ctx
	p.Cancel = &cancel
}

type PluginCallback func(args *GroupData) (*util.ScanResult, bool, error)

func (p *Plugin) Run(args PluginOption) error {
	defer args.PluginWg.Done()
	defer p.Pool.Release()
	var err error
	IsSocket := args.IsSocket
	IsSaveToJsonFile := args.IsSaveToJsonFile
	//test
	// IsSocket = true

	var Result_id int64

	VulnerableMsg := make(chan *util.ScanResult, 1)
	disableVulnComnications := make(chan bool, 1)

	// fmt.Println(len(urlinters))

	if !args.IsAllUrlsEval {
		for type_name, urlinters := range args.Data {
			ur := urlinters.([]interface{})
			for _, urlinter := range ur {
				p.threadwg.Add(1)
				if urlinter != nil {
					go func(type_name string, urlinter map[string]interface{}) {
						n := util.DeepCopyMap(urlinter)
						//单体封装
						data := GroupData{
							GroupType:        type_name,
							UrlInfo:          n,
							Spider:           p.Spider,
							Pctx:             p.Ctx,
							Pcancel:          p.Cancel,
							IsSocket:         IsSocket,
							SocketMsg:        args.SingelMsg,
							HttpsCert:        args.HttpsCert,
							HttpsCertKey:     args.HttpsCertKey,
							Config:           args.Config,
							Rate:             args.Rate,
							IsSaveToJsonFile: args.IsSaveToJsonFile,
							VulnerableMsg:    &VulnerableMsg,
						}
						err = p.Pool.Invoke(&data)
						if err != nil {
							logger.Debug(err.Error())
						}
					}(type_name, urlinter.(map[string]interface{}))
				}

			}
		}
		//这里发送文件

	} else {
		var urlsinfo []interface{}

		//全体封装
		for _, urlinters := range args.Data {
			convtypeValue := urlinters.([]interface{})
			urlsinfo = append(urlsinfo, convtypeValue...)
		}
		p.threadwg.Add(1)
		go func(urls []interface{}) {
			data := GroupData{
				GroupType:     "ALLTEST",
				GroupUrls:     urlsinfo,
				Spider:        p.Spider,
				Pctx:          p.Ctx,
				Pcancel:       p.Cancel,
				IsSocket:      IsSocket,
				SocketMsg:     args.SingelMsg,
				HttpsCert:     args.HttpsCert,
				HttpsCertKey:  args.HttpsCertKey,
				Config:        args.Config,
				VulnerableMsg: &VulnerableMsg,
			}
			err = p.Pool.Invoke(&data)
			if err != nil {
				logger.Debug(err.Error())
			}

		}(urlsinfo)
	}
	// //自定义js，开启问题
	// if p.IsEnableCutomJs {
	// 	go func ()  {
	// 		for type_name, urlinters := range args.Data {
	// 			ur := urlinters.([]interface{})
	// 			for _, urlinter := range ur {

	// 			}
	// 	}
	// }

	go func(IsSocket bool, IsSaveToJsonFile bool, SingelMsg *chan map[string]interface{}) {
		for {
			select {

			case vuln := <-VulnerableMsg:
				// if scanresult != nil {
				var ReqMsg string
				var Resp string
				//p.mu.Lock()
				p.ScanResult = append(p.ScanResult, vuln)
				//p.mu.Unlock()
				Element := make(map[string]interface{}, 1)
				//TEST IsSocket
				// if !IsSocket {
				if p.InstallDB {
					var PluginId string

					if p.PluginId == CONTENTSEARCH || p.PluginId == TLS {
						PluginId = vuln.Vulnid
					} else {
						PluginId = string(p.PluginId)
					}

					if len(vuln.ReqMsg) != 0 {
						ReqMsg = vuln.ReqMsg[0]
					}

					if len(vuln.RespMsg) != 0 {
						Resp = vuln.RespMsg[0]
					}

					if p != nil && vuln != nil {
						Result_id, err = p.Dm.SaveScanResult(
							p.Taskid,
							PluginId,
							vuln.Vulnerable,
							vuln.Target,
							// s.Output,1
							base64.StdEncoding.EncodeToString([]byte(ReqMsg)),
							base64.StdEncoding.EncodeToString([]byte(Resp)),
							int(vuln.Hostid),
						)
						if err != nil {
							logger.Error("plugin::error %s", err.Error())
							return
						}
					}

				}
				//}

				Element["status"] = 3
				Element["vul"] = p.PluginId
				// Element["request"] = ReqMsg //base64.StdEncoding.EncodeToString([]byte())
				// Element["response"] = Resp  //base64.StdEncoding.EncodeToString([]byte())
				// Element["deail"] = vuln.Output
				Element["url"] = vuln.Target
				Element["vul_level"] = vuln.VulnerableLevel
				Element["result_id"] = Result_id

				//通知socket消息
				if IsSocket {
					*SingelMsg <- Element
				}

				if IsSaveToJsonFile {
					var v global.VulnReport
					v.Hostid = Result_id
					// v.VulnerableLevel = scanresult.VulnerableLevel
					v.Target = vuln.Target
					v.Output = vuln.Output
					v.ReqMsg = base64.StdEncoding.EncodeToString([]byte(ReqMsg))
					v.RespMsg = base64.StdEncoding.EncodeToString([]byte(Resp))
					v.Vulnerable = true
					v.VulnName = string(p.PluginId)
					global.VulnResultReporter.Vulns = append(global.VulnResultReporter.Vulns, v)
					global.VulnResultReporter.Exweb_task_info.Task_id = json.Number(strconv.Itoa(p.Taskid))

				}
			//}
			case <-disableVulnComnications:
				return
			}
		}

	}(IsSocket, IsSaveToJsonFile, args.SingelMsg)

	p.threadwg.Wait()

	if p.IsEnableCutomJs {
		p.jsthreadwg.Wait()
	}

	select {
	case disableVulnComnications <- true:
	case <-time.After(5 * time.Second):

	}

	//插件数据清空
	//logger.Info("Plugin %s has Finished!", p.PluginName)
	if args.IsSocket {
		Element := make(map[string]interface{}, 1)
		Element["status"] = 1
		//logger.Info("Plugin RLocker")
		// lock.RLock()
		Progress := *args.Progress
		*args.Progress = Progress + args.Totalprog
		// lock.RUnlock()
		// logger.Info("Plugin RUnlock")

		Element["progress"] = *args.Progress
		select {
		case (*args.SingelMsg) <- Element:
		case <-time.After(5 * time.Second):
		}

	}

	return err
}
