package global

import "glint/config"

type VulnReport struct {
	VulnName   string `json:"vul_id"`        // 漏洞名
	Vulnerable bool   `json:"is_vul"`        // 是否存在漏洞
	Target     string `json:"url"`           // 漏洞url
	Output     string `json:"details"`       // 详细说明
	ReqMsg     string `json:"request_info"`  // 请求列表
	RespMsg    string `json:"response_info"` // 响应列表
	// VulnerableLevel string `json:"vulnerable_level"` // 漏洞等级
	Hostid int64 `json:"hostid"` //
}

var VulnResultReporter VulnerableList

/*
   "exweb_task_info": {
       "create_time": "2022-07-22T10:41:19",
       "end_time": "",
       "scan_time": "",
       "start_time": "",
       "task_id": 40,
       "task_name": "p"
   }
*/
type VulnerableList struct {
	Vulns           []VulnReport           `json:"exweb_task_result"`
	Exweb_task_info config.Exweb_task_info `json:"exweb_task_info"`
}
