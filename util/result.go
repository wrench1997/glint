package util

import (
	"fmt"
	"glint/proto"

	"github.com/logrusorgru/aurora"
)

// 保存扫描结果
type ScanResult struct {
	Vulnid          string   `json:"Vulnid"`           //漏洞id
	Vulnerable      bool     `json:"vulnerable"`       // 是否存在漏洞
	Target          string   `json:"target"`           // 漏洞url
	Output          string   `json:"output"`           // 一些说明
	ReqMsg          []string `json:"req_msg"`          // 请求列表
	RespMsg         []string `json:"resp_msg"`         // 响应列表
	VulnerableLevel string   `json:"vulnerable_level"` // 漏洞等级
	Hostid          int64    `json:"hostid"`           //
}

// 没漏洞时返回的结果
var InVulnerableResult = ScanResult{
	Vulnerable: false,
}

// debug没漏洞返回的结果(http)
func DebugVulnerableHttpResult(target string, output string, respList []*proto.Response) *ScanResult {
	var reqMsg []string
	var respMsg []string
	defer ResponsesPut(respList)

	for _, v := range respList {
		reqMsg = append(reqMsg, v.ReqRaw)
		respMsg = append(respMsg, v.RespRaw)
	}
	return &ScanResult{
		Vulnerable: false,
		Target:     target,
		Output:     output,
		ReqMsg:     reqMsg,
		RespMsg:    respMsg,
	}
}

// 有漏洞时返回的结果(http)
func VulnerableHttpResult(target string, output string, respList []*proto.Response) *ScanResult {
	var reqMsg []string
	var respMsg []string
	defer ResponsesPut(respList)

	for _, v := range respList {
		reqMsg = append(reqMsg, v.ReqRaw)
		respMsg = append(respMsg, v.RespRaw)
	}
	return &ScanResult{
		Vulnerable: true,
		Target:     target,
		Output:     output,
		ReqMsg:     reqMsg,
		RespMsg:    respMsg,
	}
}

// 有漏洞时返回的结果(tcp/udp)
func VulnerableTcpOrUdpResult(target string, output string, payload []string, resp []string, VulnerableLevel string, hostid int64, Vulnid string) *ScanResult {
	sr := &ScanResult{
		Vulnerable:      true,
		Target:          target,
		Output:          output,
		ReqMsg:          payload,
		RespMsg:         resp,
		VulnerableLevel: VulnerableLevel,
		Hostid:          hostid,
		Vulnid:          Vulnid,
	}
	OutputVulnerable(sr)
	return sr
}

func OutputVulnerableList(ScanResults []*ScanResult) {
	for _, s := range ScanResults {
		if s == nil {
			break
		}
		fmt.Println(aurora.Yellow("***********************************"))
		fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("Vulnid:"), aurora.Red(s.Vulnid)))
		fmt.Println(aurora.Sprintf("%s %v", aurora.Yellow("Vulnerable:"), aurora.Red(s.Vulnerable)))
		fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("target:"), aurora.Green(s.Target)))
		// fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("Output:"), aurora.Cyan(s.Output)))
		// fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("ReqMsg:"), aurora.Magenta(s.ReqMsg)))
		fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("VulnerableLevel:"), aurora.Red(s.VulnerableLevel)))
		fmt.Println(aurora.Yellow("***********************************"))
	}
}

func OutputVulnerable(ScanResult *ScanResult) {

	fmt.Println(aurora.Yellow("***********************************"))
	fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("Vulnid:"), aurora.Red(ScanResult.Vulnid)))
	fmt.Println(aurora.Sprintf("%s %v", aurora.Yellow("Vulnerable:"), aurora.Red(ScanResult.Vulnerable)))
	fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("target:"), aurora.Green(ScanResult.Target)))
	fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("Output:"), aurora.Cyan(ScanResult.Output)))
	fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("ReqMsg:"), aurora.Magenta(ScanResult.ReqMsg)))
	// fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("respMsg:"), aurora.Magenta(ScanResult.RespMsg)))
	fmt.Println(aurora.Sprintf("%s %s", aurora.Yellow("VulnerableLevel:"), aurora.Red(ScanResult.VulnerableLevel)))
	fmt.Println(aurora.Yellow("***********************************"))

}
