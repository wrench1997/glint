package dbmanager

import (
	"bufio"
	"database/sql"
	"errors"
	"fmt"
	"glint/config"
	"glint/crawler"
	"glint/logger"
	"io"
	"reflect"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"
)

type DbManager struct {
	Db *sqlx.DB
}

type DbTargetInfo struct {
	Urls sql.NullString `db:"scan_target"`
}

type DbHostResult struct {
	Hostid     sql.NullInt64  `db:"host_id"`
	Taskid     sql.NullInt64  `db:"task_id"`
	ScanTarget sql.NullString `db:"scan_target"`
	Hostip     sql.NullString `db:"host_ip"`
	StartTime  sql.NullTime   `db:"start_time"`
	EndTime    sql.NullTime   `db:"end_time"`
	ServerType sql.NullString `db:"server_type"`
	ServerOs   sql.NullString `db:"server_os"`
	RiskLevel  sql.NullString `db:"risk_level"`
	Headeruuid sql.NullString `db:"header_uuid"`
}

type DbTaskConfig struct {
	Configid sql.NullInt64 `db:"web_param_id"`
	TaskId   sql.NullInt64 `db:"task_id"`
	// Urls                        sql.NullString
	ParamModelId                sql.NullInt64  `db:"param_model_id"`
	FilterMode                  sql.NullString `db:"filter_mode"`
	ExtraHeadersUuid            sql.NullString `db:"extra_headers_id"`
	AllDomainReturn             sql.NullBool   `db:"is_all_domain"`
	SubDomainReturn             sql.NullBool   `db:"is_sub_domain"`
	IncognitoContext            sql.NullBool   `db:"is_invisible_mode"`
	NoHeadless                  sql.NullBool   `db:"is_no_headless"`
	DomContentLoadedTimeout     sql.NullInt64  `db:"dom_timeout"`
	TabRunTimeout               sql.NullInt64  `db:"request_timeout"`
	PathByFuzz                  sql.NullBool   `db:"is_fuzz_dict"`
	FuzzDictPath                sql.NullString `db:"fuzz_dict_value"`
	PathFromRobots              sql.NullBool   `db:"robot_path"`
	MaxTabsCount                sql.NullInt64  `db:"max_page_count"`
	ChromiumPath                sql.NullString `db:"chrom_path"`
	EventTriggerMode            sql.NullString `db:"event_trigger_mode"`
	EventTriggerInterval        sql.NullInt64  `db:"event_trigger_interval"`
	BeforeExitDelay             sql.NullInt64  `db:"exit_delay_time"`
	EncodeURLWithCharset        sql.NullBool   `db:"is_auto_check_code"`
	IgnoreKeywords              sql.NullString `db:"ignore_events"`
	Proxy                       sql.NullString `db:"http_proxy"`
	CustomFormValuesUuid        sql.NullString `db:"custom_fill_form_id"`
	CustomFormKeywordValuesUuid sql.NullString `db:"custom_fill_keyword_id"`
	XssPayloadsUuid             sql.NullString `db:"xss_paloads_id"`
	Qps                         sql.NullInt64  `db:"qps"`
	Max_redirect_times          sql.NullInt64  `db:"max_redirect_times"`  //最大重定向次数
	Response_Size               sql.NullInt64  `db:"response_size"`       //最大重定向次数
	Anti_chain_platform         sql.NullString `db:"anti_chain_platform"` //反链平台
	Api_token                   sql.NullString `db:"api_token"`           //反链平台API Token
	ScanDepth                   sql.NullInt64  `db:"scan_depth"`          //扫描深度
	UserNameUuid                sql.NullInt64  `db:"user_dic_id"`         //网页表单用户组uuid
	PassWordUuid                sql.NullInt64  `db:"pwd_dic_id"`          //网页表单密码组uuid
	Cookie                      sql.NullString `db:"cookie"`              //网页Cookies
	UserAgent                   sql.NullString `db:"user_agent"`          //网页UserAgent
	ServerPemPath               sql.NullString `db:"server_pem_path"`     //https证书
	ServerKeyPath               sql.NullString `db:"server_key_path"`     //https密钥
}

type ExtraHeaders struct {
	Id    sql.NullString `db:"id"`
	Uuid  sql.NullString `db:"header_uuid"`
	Key   sql.NullString `db:"header_key"`
	Value sql.NullString `db:"header_value"`
	Type  sql.NullInt64  `db:"type"`
}

type GrapUrl struct {
	Taskid int64  `db:"task_id"`
	Hostid int64  `db:"host_id"`
	Url    string `db:"url"`
}

type PublishState struct {
	Id          sql.NullString `db:"msg_id"`
	Host        sql.NullString `db:"host_info"`
	Method      sql.NullString `db:"request_mode"`
	Data        sql.NullString `db:"post_param"`
	UserAgent   sql.NullString `db:"user_agent"`
	ContentType sql.NullString `db:"content_type"`
	CreatedTime time.Time      `db:"create_time"`
}

// Init 初始化mysql数据库
func (Dm *DbManager) Init() error {
	TaskConfig := config.TaskYamlConfig{}
	err := config.ReadYamlTaskConf("config.yaml", &TaskConfig)
	if err != nil {
		panic(err)
	}
	//构建连接："用户名:密码@tcp(IP:端口)/数据库?charset=utf8"
	path := strings.Join([]string{TaskConfig.DBUser,
		":", TaskConfig.DBPassWord,
		"@tcp(", config.Ip,
		":", config.Port,
		")/", TaskConfig.DBName,
		"?charset=utf8&parseTime=true&loc=Local"}, "")
	//打开数据库,前者是驱动名，所以要导入： _ "github.com/go-sql-driver/mysql"
	DB, err := sqlx.Connect("mysql", path)
	if err != nil {
		return err
	}
	DB.SetMaxOpenConns(50)
	DB.SetMaxIdleConns(10)
	DB.SetConnMaxLifetime(59 * time.Second)
	if err != nil {
		logger.Info("[DB] open database fail")
		return err
	}
	logger.Info("[DB] connnect success")
	Dm.Db = DB
	return nil
}

// GetTaskHostid
func (Dm *DbManager) GetTaskHostid(taskid int) ([]DbHostResult, error) {
	sql := `
	SELECT
	exweb_host_result.host_id,
	exweb_host_result.scan_target,
	exweb_host_result.start_time, 
	exweb_host_result.end_time,	
	exweb_host_result.server_type,
	exweb_host_result.server_os,
	exweb_host_result.risk_level,
	exweb_host_result.header_uuid
	FROM
	exweb_host_result
	WHERE
	exweb_host_result.task_id = ?`
	values := []DbHostResult{}

	err := Dm.Db.Select(&values, sql, taskid)
	if err != nil {
		logger.Error("get get task hostid error %v", err.Error())
	}
	return values, err
}

// Get

// GetTaskConfig 根据任务ID获取数据库的扫描配置
func (Dm *DbManager) GetTaskConfig(taskid int) (DbTaskConfig, error) {
	sql := `
	SELECT
		exweb_scan_param.web_param_id,
		exweb_scan_param.task_id,
		exweb_scan_param.param_model_id,
		exweb_scan_param.filter_mode,
		exweb_scan_param.extra_headers_id,
		exweb_scan_param.is_all_domain,
		exweb_scan_param.is_sub_domain,
		exweb_scan_param.is_invisible_mode,
		exweb_scan_param.is_no_headless,
		exweb_scan_param.dom_timeout,
		exweb_scan_param.request_timeout,
		exweb_scan_param.is_fuzz_dict,
		exweb_scan_param.fuzz_dict_value,
		exweb_scan_param.robot_path,
		exweb_scan_param.max_page_count,
		exweb_scan_param.chrom_path,
		exweb_scan_param.event_trigger_mode,
		exweb_scan_param.event_trigger_interval,
		exweb_scan_param.exit_delay_time,
		exweb_scan_param.is_auto_check_code,
		exweb_scan_param.ignore_events,
		exweb_scan_param.http_proxy,
		exweb_scan_param.custom_fill_form_id,
		exweb_scan_param.custom_fill_keyword_id,
		exweb_scan_param.xss_paloads_id,
		exweb_scan_param.qps,
		exweb_scan_param.max_redirect_times,
		exweb_scan_param.response_size,
		exweb_scan_param.anti_chain_platform,
		exweb_scan_param.api_token,
		exweb_scan_param.scan_depth,
		exweb_scan_param.user_dic_id,
		exweb_scan_param.pwd_dic_id,
		exweb_scan_param.cookie,
		exweb_scan_param.user_agent,
		exweb_scan_param.server_pem_path,
		exweb_scan_param.server_key_path
	FROM
		exweb_scan_param
	WHERE
		exweb_scan_param.task_id = ?
	`
	values := DbTaskConfig{}
	err := Dm.Db.Get(&values, sql, taskid)
	if err != nil {
		logger.Error("get exweb_scan_param error %v", err.Error())
	}
	//两张表
	// sql = `
	// SELECT
	// exweb_target_info.scan_target
	// FROM
	// exweb_target_info
	// WHERE
	// exweb_target_info.task_id = ?
	// `
	// val2 := DbTargetInfo{}
	// err = Dm.Db.Get(&val2, sql, taskid)
	// if err != nil {
	// 	logger.Error("gettaskConfig error %v", err.Error())
	// }
	// values.Urls = val2.Urls
	return values, err
}

// GetExtraHeaders 根据Uuid获取数据库的扫描头
func (Dm *DbManager) GetExtraHeaders(host_id int, task_id int) ([]ExtraHeaders, error) {
	sql := `
	
	SELECT ehi.* from exweb_host_result ehr,
	exweb_header_info ehi 
	where ehr.header_uuid = ehi.header_uuid and
	 ehr.host_id = ? and ehr.task_id = ?`

	// sql := `
	// SELECT
	// exweb_header_info.header_key,
	// exweb_header_info.header_value
	// FROM
	// exweb_header_info
	// WHERE
	// exweb_header_info.header_uuid = ?`
	values := []ExtraHeaders{}
	err := Dm.Db.Select(&values, sql, host_id, task_id)
	if err != nil {
		logger.Error("get extra headers error %v", err.Error())
	}
	return values, err
}

// 保存web漏扫结果
func (Dm *DbManager) SaveScanResult(
	taskid int,
	plugin_id string,
	Vulnerable bool,
	Target string,
	ReqMsg string,
	RespMsg string,
	hostid int,
) (int64, error) {
	sql := `
	INSERT  
	INTO 
	exweb_task_result (task_id,is_vul,url,vul_id,request_info,host_id) 
	VALUES(:taskid,:vul,:target,:vulid,:reqmsg,:hostid);
	`
	result, err := Dm.Db.NamedExec(sql, map[string]interface{}{
		"taskid": taskid,
		"vul":    Vulnerable,
		"target": Target,
		"vulid":  plugin_id,
		"reqmsg": ReqMsg,
		"hostid": hostid,
		// "respmsg": RespMsg,
		// "vulnerability": VulnerableLevel,
	})

	if err != nil {
		logger.Error("NamedExec() save scan result error %v", err.Error())
	}

	result_id, err := result.LastInsertId()

	if err != nil {
		logger.Error("LastInsertId() save scan result error %v", err.Error())
	}
	return result_id, err
}

// 保存爬取到的链接
func (Dm *DbManager) SaveGrabUri(
	GrapUrls []GrapUrl,
	// taskid int,
	// hostid string,
	// url string,
) (int64, error) {
	sql := `
	INSERT  
	INTO 
	exweb_host_url (task_id,host_id,url) 
	VALUES(:task_id,:host_id,:url);
	`
	result, err := Dm.Db.NamedExec(sql, GrapUrls)

	if err != nil {
		logger.Error("NamedExec() save scan result error %v", err.Error())
		return 0, err
	}

	result_id, err := result.LastInsertId()

	if err != nil {
		logger.Error("LastInsertId() save scan result error %v", err.Error())
	}
	return result_id, err
}

// 保存退出时间
func (Dm *DbManager) SaveQuitTime(
	taskid int,
	t time.Time,
	over string,
) error {
	sql := `UPDATE exweb_task_info SET end_time=:end_time,task_status=:task_status WHERE task_id=:task_id`
	_, err := Dm.Db.NamedExec(sql,
		map[string]interface{}{
			"end_time":    t,
			"task_status": uint16(3),
			"task_id":     taskid,
		})
	//错误处理
	if err != nil {
		fmt.Println("更新退出时间失败!")
	}
	return err
}

// DeleteGrabUri 开始扫描时候删除爬取结果
func (Dm *DbManager) DeleteGrabUri(taskid int) error {
	_, err := Dm.Db.Exec("delete from exweb_host_url where task_id=?", taskid)
	if err != nil {
		logger.Error("delete exweb_host_url error %v", err.Error())
	}
	return err
}

// func (Dm *DbManager) DeleteTreeUrl(taskid int) error {
// 	_, err := Dm.Db.Exec("delete from exweb_host_url where task_id=?", taskid)
// 	if err != nil {
// 		logger.Error("delete exweb_host_url error %v", err.Error())
// 	}
// 	return err
// }

// DeleteScanResult 开始扫描时候删除脚本
func (Dm *DbManager) DeleteScanResult(taskid int) error {
	_, err := Dm.Db.Exec("delete from exweb_task_result where task_id=?", taskid)
	if err != nil {
		logger.Error("delete scan result error %v", err.Error())
	}

	sql := `UPDATE exweb_task_info SET end_time=NULL,scan_time=NULL WHERE task_id=:task_id`
	_, err = Dm.Db.NamedExec(sql,
		map[string]interface{}{
			"task_id": taskid,
		})
	//错误处理
	if err != nil {
		fmt.Println("清空退出时间失败!")
	}
	return err
}

func (Dm *DbManager) ConvertToMap(value interface{}, converted map[string]interface{}) map[string]interface{} {
	// converted := make(map[string]interface{})
	rv := reflect.ValueOf(value)
	rt := reflect.TypeOf(value)
	if _, ok := rt.FieldByName("Key"); ok {
		if _, ok := rt.FieldByName("Value"); ok {
			converted[rv.FieldByName("Key").String()] = rv.FieldByName("Value").String()
		}
	}
	return converted
}

func (Dm *DbManager) GetHeaders(host_id int, task_id int, type_name string) map[string]interface{} {
	converted := make(map[string]interface{})
	// if uuid == "" {
	// 	return converted
	// }
	switch type_name {
	case "Headers":
		ExtraHeaders, err := Dm.GetExtraHeaders(host_id, task_id)
		if err != nil {
			logger.Error(err.Error())
		}
		for _, Header := range ExtraHeaders {
			converted[Header.Key.String] = Header.Value.String
		}
	}
	return converted
}

func NewNullString(s string) sql.NullString {
	if len(s) == 0 {
		return sql.NullString{}
	}
	return sql.NullString{
		String: s,
		Valid:  true,
	}
}

func (Dm *DbManager) InstallHttpsReqStatus(State *PublishState) error {

	sql := `
	INSERT
	INTO
	exweb_publish_msg (msg_id,host_info,request_mode,post_param,user_agent,content_type,create_time) 
	VALUES(:id,:host,:method,:data,:user_agent,:content_type,:created_time); 
	`
	_, err := Dm.Db.NamedExec(sql, map[string]interface{}{
		"id":           State.Id,
		"host":         State.Host,
		"method":       State.Method,
		"data":         State.Data,
		"user_agent":   State.UserAgent,
		"content_type": State.ContentType,
		"created_time": State.CreatedTime,
	})
	if err != nil {
		logger.Error("install https req status error %v", err.Error())
	}
	return err
}

func (Dm *DbManager) SaveUrlTree(duts []crawler.DatabeseUrlTree) error {
	sqlstr := `
	INSERT
	INTO
	exweb_host_url (task_id,host_id,url,current_node_id,parent_node_id) 
	VALUES(:task_id,:host_id,:url,:current_node_id,:parent_node_id);`

	_, err := Dm.Db.NamedExec(sqlstr, duts)
	if err != nil {
		logger.Error("install https req status error %v", err.Error())
	}
	return err
}

func (Dm *DbManager) GetUserNameORPassword(id int) ([]string, error) {
	sqlstr := `
	SELECT
	convert(util_dic_info.dic_content USING utf8)
	FROM
	util_dic_info
	WHERE
	util_dic_info.dic_id = ?`
	var groups []string
	var values sql.NullString
	err := Dm.Db.Get(&values, sqlstr, id)
	if err != nil {
		logger.Error("get GetUserNameORPassword error %v", err.Error())
	}

	if !values.Valid {
		return groups, errors.New("parser dic_content field error")
	}

	ioread := strings.NewReader(values.String)
	buf := bufio.NewReader(ioread)
	for {
		input, err := buf.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				fmt.Println(err)
			}
			break
		}
		// fmt.Printf("Count: %v\n", count)
		fmt.Printf("Data: %v\n", input)
		groups = append(groups, input)
	}
	return groups, err
}

func (Dm *DbManager) ConvertDbTaskConfigToYaml(dbTaskConfig DbTaskConfig) (config.TaskYamlConfig, error) {
	TaskConfig := config.TaskYamlConfig{}
	TaskConfig.MaxTabsCount = int(dbTaskConfig.MaxTabsCount.Int64)
	TaskConfig.FilterMode = dbTaskConfig.FilterMode.String
	//TaskConfig.ExtraHeaders = Dm.GetHeaders(dbTaskConfig.,dbTaskConfig.task_id, "Headers")

	TaskConfig.AllDomainReturn = dbTaskConfig.AllDomainReturn.Bool
	TaskConfig.SubDomainReturn = dbTaskConfig.SubDomainReturn.Bool
	TaskConfig.IncognitoContext = dbTaskConfig.IncognitoContext.Bool
	TaskConfig.NoHeadless = dbTaskConfig.NoHeadless.Bool
	TaskConfig.DomContentLoadedTimeout = time.Duration(dbTaskConfig.DomContentLoadedTimeout.Int64) * time.Millisecond
	TaskConfig.TabRunTimeout = time.Duration(dbTaskConfig.TabRunTimeout.Int64) * time.Second
	TaskConfig.PathByFuzz = dbTaskConfig.PathByFuzz.Bool
	TaskConfig.FuzzDictPath = dbTaskConfig.FuzzDictPath.String
	TaskConfig.PathFromRobots = dbTaskConfig.PathFromRobots.Bool
	TaskConfig.ChromiumPath = dbTaskConfig.ChromiumPath.String
	TaskConfig.EventTriggerMode = dbTaskConfig.EventTriggerMode.String
	TaskConfig.EventTriggerInterval = time.Duration(dbTaskConfig.EventTriggerInterval.Int64) * time.Millisecond
	TaskConfig.BeforeExitDelay = time.Duration(dbTaskConfig.BeforeExitDelay.Int64) * time.Millisecond
	TaskConfig.EncodeURLWithCharset = dbTaskConfig.EncodeURLWithCharset.Bool
	TaskConfig.IgnoreKeywords = func() []string {
		var ignored []string
		if len(dbTaskConfig.IgnoreKeywords.String) == 0 {
			return ignored
		} else {
			return strings.Split(dbTaskConfig.IgnoreKeywords.String, "|")
		}
	}()
	TaskConfig.Proxy = dbTaskConfig.Proxy.String
	//TaskConfig.CustomFormValues = Dm.UuidToMap(dbTaskConfig.CustomFormValuesUuid.String, "CustomFormValues")
	//TaskConfig.CustomFormKeywordValues = Dm.UuidToMap(dbTaskConfig.CustomFormKeywordValuesUuid.String, "CustomFormKeywordValues")
	//TaskConfig.XssPayloads = Dm.UuidToMap(dbTaskConfig.XssPayloadsUuid.String, "XssPayloads")
	TaskConfig.Qps = dbTaskConfig.Qps.Int64
	TaskConfig.Max_redirect_times = dbTaskConfig.Max_redirect_times.Int64
	TaskConfig.ScanDepth = dbTaskConfig.ScanDepth.Int64
	TaskConfig.Response_Size = dbTaskConfig.Response_Size.Int64
	TaskConfig.Anti_chain_platform = dbTaskConfig.Anti_chain_platform.String
	TaskConfig.Api_token = dbTaskConfig.Api_token.String
	TaskConfig.User_dic_id = dbTaskConfig.UserNameUuid.Int64
	TaskConfig.Pwd_dic_id = dbTaskConfig.PassWordUuid.Int64
	TaskConfig.Cert = dbTaskConfig.ServerPemPath.String
	TaskConfig.CertKey = dbTaskConfig.ServerKeyPath.String

	logger.Info("MaxTabsCount:%v", TaskConfig.MaxTabsCount)
	logger.Info("FilterMode:%v", TaskConfig.FilterMode)
	logger.Info("ExtraHeaders:%v", TaskConfig.ExtraHeaders)
	logger.Info("AllDomainReturn:%v", TaskConfig.AllDomainReturn)
	logger.Info("SubDomainReturn:%v", TaskConfig.SubDomainReturn)
	logger.Info("IncognitoContext:%v", TaskConfig.IncognitoContext)
	logger.Info("NoHeadless:%v", TaskConfig.NoHeadless)
	logger.Info("DomContentLoadedTimeout:%v", TaskConfig.DomContentLoadedTimeout)
	logger.Info("TabRunTimeout:%v", TaskConfig.TabRunTimeout)
	logger.Info("PathByFuzz:%v", TaskConfig.PathByFuzz)
	logger.Info("FuzzDictPath:%v", TaskConfig.FuzzDictPath)
	logger.Info("PathFromRobots:%v", TaskConfig.PathFromRobots)
	logger.Info("ChromiumPath:%v", TaskConfig.ChromiumPath)
	logger.Info("EventTriggerMode:%v", TaskConfig.EventTriggerMode)
	logger.Info("EventTriggerInterval:%v", TaskConfig.EventTriggerInterval)
	logger.Info("BeforeExitDelay:%v", TaskConfig.BeforeExitDelay)
	logger.Info("EncodeURLWithCharset:%v", TaskConfig.EncodeURLWithCharset)
	logger.Info("IgnoreKeywords:%v", TaskConfig.IgnoreKeywords)
	logger.Info("Proxy:%v", TaskConfig.Proxy)
	logger.Info("CustomFormValues:%v", TaskConfig.CustomFormValues)
	logger.Info("CustomFormKeywordValues:%v", TaskConfig.CustomFormKeywordValues)
	logger.Info("Qps:%v", TaskConfig.Qps)
	logger.Info("Max_redirect_times:%v", TaskConfig.Max_redirect_times)
	logger.Info("ScanDepth:%v", TaskConfig.ScanDepth)
	logger.Info("Response_Size:%v", TaskConfig.Response_Size)
	logger.Info("Anti_chain_platform:%v", TaskConfig.Anti_chain_platform)
	logger.Info("Api_token:%v", TaskConfig.Api_token)
	logger.Info("User_dic_id:%v", TaskConfig.User_dic_id)
	logger.Info("Pwd_dic_id:%v", TaskConfig.Pwd_dic_id)

	logger.Info("Cert:%v", TaskConfig.Cert)
	logger.Info("CertKey:%v", TaskConfig.CertKey)

	// TaskConfig.TabRunTimeout = time.Duration(dbTaskConfig.TabRunTimeout.Int64)
	return TaskConfig, nil
}

func (Dm *DbManager) GetKeyValues(uuid string, datatype int64) (map[string]interface{}, error) {
	var (
		err error
	)

	sql := `
	SELECT
	exweb_header_info.header_key, 
	exweb_header_info.header_value
	FROM
	exweb_header_info
	WHERE
	exweb_header_info.header_uuid = ?
	AND
	exweb_header_info.type < ?
	`
	values := make(map[string]interface{})
	err = Dm.Db.Select(&values, sql, uuid, datatype)
	if err != nil {
		logger.Error("get extra headers error %v", err.Error())
	}

	return nil, nil
}
