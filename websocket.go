package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"glint/dbmanager"
	"glint/logger"
	"glint/netcomm"
	"glint/plugin"
	"glint/util"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/thoas/go-funk"
	"golang.org/x/time/rate"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

type TaskServer struct {
	// subscriberMessageBuffer controls the max number
	// of messages that can be queued for a subscriber
	// before it is kicked.
	//
	// Defaults to 16.
	subscriberMessageBuffer int

	// publishLimiter controls the rate limit applied to the publish endpoint.
	//
	// Defaults to one publish every 100ms with a burst of 8.
	publishLimiter *rate.Limiter

	// serveMux routes the various endpoints to the appropriate handler.
	serveMux http.ServeMux

	server_type string

	// DM
	Dm *dbmanager.DbManager
}

// Tasks 进行的任务
var Tasks []*Task

var Taskslock sync.Mutex

// type TaskStatus int

const (
	TaskERROR        util.Status = -1
	TaskHasCompleted util.Status = 0
	TaskHasStart     util.Status = 1
	TaskStop         util.Status = 2
)

// func (t *Task) quitmsg() {
// 	logger.Info("Wait DoStartSignal")
// 	<-t.DoStartSignal
// 	logger.Info("Monitor the exit signal of the task")
// 	// for _, task := range Tasks {

// 	// }
// }

// NewTaskServer
func NewTaskServer(server_type string) (*TaskServer, error) {
	ts := &TaskServer{
		subscriberMessageBuffer: 16,
		// subscribers:             make(map[*subscriber]struct{}),
		publishLimiter: rate.NewLimiter(rate.Every(time.Millisecond*100), 8),
	}

	if strings.ToLower(server_type) == "websocket" {
		ts.serveMux.Handle("/", http.FileServer(http.Dir(".")))
		ts.serveMux.HandleFunc("/task", ts.TaskHandler)
		ts.serveMux.HandleFunc("/publish", ts.PublishHandler)
	}

	if Dbconect {
		ts.Dm = &dbmanager.DbManager{}
		err := ts.Dm.Init()
		if err != nil {
			return nil, err
		}
	}
	ts.server_type = server_type
	netcomm.ServerType = ts.server_type
	return ts, nil
}

func (ts *TaskServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ts.serveMux.ServeHTTP(w, r)
}

// TaskHandler 任务处理
func (ts *TaskServer) TaskHandler(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		logger.Error(err.Error())
		return
	}

	go func() {
		var (
			err     error
			v       interface{}
			jsonobj interface{}
		)

		mjson := make(map[string]interface{}, 0)

		defer c.Close(websocket.StatusInternalError, "")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		info := netcomm.WebSoketinfo__{Conn: c, Ctx: ctx}
		netcomm.Socketinfo = append(netcomm.Socketinfo, &info)

		for {
			err := wsjson.Read(ctx, c, &v)
			if err != nil {
				logger.Warning(err.Error())
				break
			}
			if value, ok := v.(string); ok {
				err = json.Unmarshal([]byte(value), &jsonobj)
				if err != nil {
					logger.Error(err.Error())
					break
				}
				mjson = jsonobj.(map[string]interface{})
			} else if value, ok := v.((map[string]interface{})); ok {
				for k, v := range value {
					mjson[k] = v
				}
			}

			err = ts.Task(ctx, mjson)
			if err != nil {
				logger.Error(err.Error())
				continue
			}
		}

		if errors.Is(err, context.Canceled) {
			logger.Error(err.Error())
			return
		}
		if websocket.CloseStatus(err) == websocket.StatusNormalClosure ||
			websocket.CloseStatus(err) == websocket.StatusGoingAway {
			logger.Error(err.Error())
			return
		}
		if err != nil {
			logger.Error(err.Error())
			return
		}
	}()
}

func (ts *TaskServer) AgentHandler(ctx context.Context, mjson map[string]interface{}) (bool, error) {
	var err error
	if mjson == nil {
		return false, errors.New("parser data fail")
	}
	if v, ok := mjson["action"].(string); ok {
		if v != "runagnet" {
			return false, nil
		}
	}
	if v, ok := mjson["enable_plugin"].(string); ok {
		if v != "runagnet" {
			return false, nil
		}
	} else {
		task, err := ts.start(mjson, true)
		if err != nil {
			logger.Error(err.Error())
			netcomm.Sendmsg(-1, err.Error(), task.TaskId)
			return false, err
		}
		logger.Info("1111111")
		// Taskslock.Lock()
		Tasks = append(Tasks, &task)
		// Taskslock.Unlock()
		netcomm.Sendmsg(0, "The Task is Starting", task.TaskId)
		go task.PluginMsgHandler(*task.Ctx)

		//go task.quitmsg()
	}

	return true, err
}

func (ts *TaskServer) Task(ctx context.Context, mjson map[string]interface{}) error {

	var (
		err    error
		Status string
		taskid string
	)

	if len(mjson) == 0 {
		logger.Error("[./websocket.go:Task() error] the json is empty")
		return err
	}

	// if mjson == nil {
	// 	logger.Error("[./websocket.go:Task() error] the json is empty")
	// 	return err
	// }

	// b, err := ts.AgentHandler(ctx, mjson)
	// if b || err != nil {
	// 	return err
	// }

	if value, ok := mjson["action"].(string); ok {
		Status = value
	} else {
		err = fmt.Errorf("[./websocket.go:Task() error] unkown action for the json")
		logger.Error(err.Error())
		netcomm.Sendmsg(-1, "error: unkown action for the json", 9564)
		return err
	}
	if value, ok := mjson["taskid"].(string); ok {
		taskid = value
	} else {
		err = fmt.Errorf("[./websocket.go:Task() error] unkown taskid for the json")
		logger.Error(err.Error())
		netcomm.Sendmsg(-1, "error: unkown taskid for the json", 9564)
		return err
	}

	id, err := strconv.Atoi(taskid)
	if err != nil {
		panic(err)
	}

	if strings.ToLower(Status) == "start" && !IsStartProxyMode {
		logger.Info("开始任务")
		// if ok, err := util.ConfirmVlockFile("v-clock.lock"); !ok {
		// 	logger.Error("cpu校验失败,error:%s", err.Error())
		// 	netcomm.Sendmsg(-1, "授权校验失败", id)
		// }

		//清理残余的chrome,一般这个操作chrome处理不当的情况下出现，在还没完善前的临时补救方案

		status, err := ts.GetTaskStatus(mjson)
		if err != nil {
			//err = fmt.Errorf("[./websocket.go:Task() error] unkown taskid for the json")
			logger.Error(err.Error())
			netcomm.Sendmsg(-1, err.Error(), id)
			return err
		}
		if status == TaskHasStart {
			netcomm.Sendmsg(6, "The Task Has Started", id)
			return nil
		}
		//开始任务
		task, err := ts.start(mjson, false)
		if err != nil {
			logger.Error(err.Error())
			netcomm.Sendmsg(-1, err.Error(), task.TaskId)
			return err
		}
		Taskslock.Lock()
		Tasks = append(Tasks, &task)
		Taskslock.Unlock()
		netcomm.Sendmsg(0, "The Task is Starting", task.TaskId)
		go task.PluginMsgHandler(*task.Ctx)
		// go task.quitmsg()
	} else if strings.ToLower(Status) == "close" && !IsStartProxyMode {
		var IsClosed = false
		if len(Tasks) != 0 {
			for i, task := range Tasks {
				uinttask, _ := strconv.Atoi(taskid)
				if task.TaskId == uinttask {
					(*task.Cancel)()
					Taskslock.Lock()
					task.Status = TaskStop
					Tasks = append(Tasks[:i], Tasks[i+1:]...)
					Taskslock.Unlock()
					IsClosed = true
				}
			}
			if !IsClosed {
				uinttask, _ := strconv.Atoi(taskid)
				netcomm.Sendmsg(4, "close error", uinttask)
			}
			if len(Tasks) == 0 {
				if err := util.KillChrome(); err != nil {
					logger.Error("failed to kill Chrome: ", err)
				}
				if err := util.KillcustomJS(); err != nil {
					logger.Error("failed to kill customJS: ", err)
				}
			}
			// Tasks = nil
		} else {
			uinttask, err := strconv.Atoi(taskid)
			if err != nil {
				logger.Error("strconv.Atoi taskid error: %v ", err)
				return err
			}
			netcomm.Sendmsg(4, "no task", uinttask)
		}
		//被动扫描专有指令
	} else if strings.ToLower(Status) == "status" && !IsStartProxyMode {

		if len(Tasks) != 0 {
			IsRunning := false
			for _, task := range Tasks {
				uinttask, _ := strconv.Atoi(taskid)
				if task.TaskId == uinttask {
					netcomm.Sendmsg(7, "running", uinttask)
					IsRunning = true
				}
			}
			if !IsRunning {
				msg := fmt.Sprintf("ths task: %s is not running ", taskid)
				uinttask, _ := strconv.Atoi(taskid)
				netcomm.Sendmsg(4, msg, uinttask)
			}
		} else {
			uinttask, err := strconv.Atoi(taskid)
			if err != nil {
				logger.Error("strconv.Atoi taskid error: %v ", err)
				return err
			}
			netcomm.Sendmsg(4, "no task", uinttask)
		}
		//被动扫描专有指令
	} else if strings.EqualFold(Status, "PauseScan") && IsStartProxyMode {
		//设置IsPauseScan全局变量
		plugin.IsPauseScan = true
	} else if strings.EqualFold(Status, "ContinueScan") && IsStartProxyMode {
		plugin.IsPauseScan = false
	} else {
		logger.Info("无效指令")
	}

	return err
}

func (ts *TaskServer) GetTaskStatus(json map[string]interface{}) (util.Status, error) {
	if len(Tasks) != 0 {
		for _, task := range Tasks {
			taskid, err := GetTaskId(json)
			if err != nil {
				task.Status = TaskERROR
				return TaskERROR, err
			}
			if task.TaskId == taskid {
				task.Status = TaskHasStart
				return TaskHasStart, nil
			}
		}
	}
	return TaskHasCompleted, nil
}

func GetTaskId(json map[string]interface{}) (int, error) {
	var taskid int
	if v, ok := json["taskid"].(string); ok {
		id, _ := strconv.Atoi(v)
		taskid = int(id)
	} else if v, ok := json["taskid"].(float64); ok {
		taskid = int(v)
	} else {
		return 0, errors.New("no parse for taskid type")
	}
	return taskid, nil
}

func (ts *TaskServer) start(v interface{}, IsGetDatabydatabase bool) (Task, error) {
	var task Task
	var Err error
	var config tconfig
	json := v.(map[string]interface{})
	// logger.DebugEnable(true)
	logger.Info("%v", json)

	if IsGetDatabydatabase {
		task.TaskId = -1
		config.EnableCrawler = false
		task.ScanType = -1
		task.TaskConfig.JsonOrYaml = true
		// 测试被动代理
		// config.EnableCrawler = false
		config.InstallDb = false
		task.Init()
		task.XssSpider.Init(task.TaskConfig)
	} else {
		config.InstallDb = true
		task.TaskId, Err = GetTaskId(json)
		task.Dm = ts.Dm
		if Err != nil {
			logger.Error(Err.Error())
		}
		DBTaskConfig, Err := ts.Dm.GetTaskConfig(task.TaskId)
		if Err != nil {
			logger.Error(Err.Error())
		}
		TaskConfig, Err := ts.Dm.ConvertDbTaskConfigToYaml(DBTaskConfig)
		if Err != nil {
			logger.Error(Err.Error())
		}
		task.Init()

		task.TaskConfig.Yaml = TaskConfig
		task.TaskConfig.Yaml.CustomFormValues, _ = util.CopyMapif(TaskConfig.CustomFormValues)
		task.TaskConfig.Yaml.CustomFormKeywordValues, _ = util.CopyMapif(TaskConfig.CustomFormKeywordValues)
		task.TaskConfig.Yaml.XssPayloads, _ = util.CopyMapif(TaskConfig.XssPayloads)
		task.TaskConfig.JsonOrYaml = true
		//获取host表
		host_result, err := ts.Dm.GetTaskHostid(task.TaskId)
		if err != nil {
			logger.Error(err.Error())
		}

		for _, hostinfo := range host_result {
			Headers := ts.Dm.GetHeaders(int(hostinfo.Hostid.Int64), task.TaskId, "Headers")
			if hostinfo.ScanTarget.Valid {
				Err = task.UrlExpand(hostinfo.ScanTarget.String, hostinfo.Hostid.Int64, Headers)
				if Err != nil {
					return task, Err
				}
			}
		}
		config.EnableCrawler = true
		// //测试被动代理
		// config.EnableCrawler = false
		config.InstallDb = true
	}
	// ProxyPort, err := task.TaskConfig.GetValue("ProxyPort")
	// if err != nil {
	// 	panic(err)
	// }
	config.ProxyPort = task.TaskConfig.Yaml.ProxyPort

	if task.TaskConfig.Yaml.Cert != "" && task.TaskConfig.Yaml.CertKey != "" {
		config.HttpsCert = task.TaskConfig.Yaml.Cert
		config.HttpsCertKey = task.TaskConfig.Yaml.CertKey
	} else {
		config.HttpsCert = Cert
		config.HttpsCertKey = PrivateKey
	}

	//websocket开启自定义js脚本通讯
	EnalbeJackdaw = true

	go task.dostartTasks(config)
	// go func() {
	// 	task.DoStartSignal <- true
	// }()

	return task, Err
}

// func writeTimeout(ctx context.Context, timeout time.Duration, c *websocket.Conn, msg interface{}) error {
// 	ctx, cancel := context.WithTimeout(ctx, timeout)
// 	defer cancel()
// 	return wsjson.Write(ctx, c, msg)
// }

// PublishHandler 这个专门记录反链记录
func (ts *TaskServer) PublishHandler(w http.ResponseWriter, r *http.Request) {
	id := string(funk.RandomString(11, []rune("0123456789")))
	Host := r.Host
	Method := r.Method
	body := http.MaxBytesReader(w, r.Body, 8192)
	msg, err := ioutil.ReadAll(body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	Data := msg
	User_Agent := r.Header.Get("User-Agent")
	Content_Type := r.Header.Get("Content-Type")
	Created_Time := time.Now().Local()

	State := dbmanager.PublishState{
		Id:          dbmanager.NewNullString(id),
		Host:        dbmanager.NewNullString(Host),
		Method:      dbmanager.NewNullString(Method),
		Data:        dbmanager.NewNullString(base64.RawStdEncoding.EncodeToString(Data)),
		UserAgent:   dbmanager.NewNullString(User_Agent),
		ContentType: dbmanager.NewNullString(Content_Type),
		CreatedTime: Created_Time,
	}

	err = ts.Dm.InstallHttpsReqStatus(&State)
	if err != nil {
		logger.Error(err.Error())
	}

	w.WriteHeader(http.StatusOK)
}

func (t *Task) PluginMsgHandler(ctx context.Context) {
	// var err error
	defer t.ClearData()
	var err error
	for {
		select {
		case msg := <-t.PliuginsMsg:
			status := msg["status"].(int)
			if _, ok := msg["progress"]; ok {
				if t.ScanType == -1 {
				} else {
					err = netcomm.Sendmsg(status, msg, t.TaskId)
				}
			}
			if err != nil {
				msg = make(map[string]interface{})
			}
			if _, ok := msg["vul"]; ok {
				//logger.Info("发送漏洞:%v", msg)
				err = netcomm.Sendmsg(status, msg, t.TaskId)
			}
			// if err != nil {
			// 	msg = make(map[string]interface{})
			// }
			if _, ok := msg["crawler"]; ok {
				//logger.Info("发送漏洞:%v", msg)
				err = netcomm.Sendmsg(status, msg, t.TaskId)
			}

		case <-t.stoppluginmsg:
			_, ok := <-t.PliuginsMsg
			if !ok {
				fmt.Println("channel is closed")
				return
			} else {
				close(t.PliuginsMsg)
			}
			return
		case <-ctx.Done():
			logger.Warning("PluginMsgHandler exit ...")
			// _, ok := <-t.PliuginsMsg
			// if !ok {
			// 	fmt.Println("channel is closed")
			// 	return
			// } else {
			// 	close(t.PliuginsMsg)
			// }

			if t.Status != TaskStop {
				netcomm.Sendmsg(2, "The Task is End", t.TaskId)
			} else {
				netcomm.Sendmsg(4, "The Task is End", t.TaskId)
			}

			time.Sleep(5 * time.Second)

			for _, v := range t.Plugins {
				if v.Spider != nil {
					v.Spider.Close()
				}
			}

			return
		case <-time.After(5 * time.Second):
		}

	}
}
