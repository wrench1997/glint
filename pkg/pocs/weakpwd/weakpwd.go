package weakpwd

import (
	"errors"
	"fmt"
	"glint/config"
	"glint/logger"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"strings"
)

var passArray = []string{"pwd", "密码", "pass", "password", "user_password", "user_pass", "user_pwd"}

var UserArray = []string{"user", "用户名", "username", "user_name"}

var test1userPass = []string{"admin", "Liujadsv1997."}

var test2userPass = []string{"admin", "Liujadsv1998."}

type classWeakPwdAttack struct {
	scheme                 layers.Scheme
	TargetUrl              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	lastJobProof           interface{}
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
}

// type idxvar struct {
// 	idx int
// 	variable string
// }

func StartTesting(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var err error
	var variations *util.Variations
	var WeakPwdAttack classWeakPwdAttack
	gd := args
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
	ct := layers.CheckType{IsMultipleUrls: false}
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	WeakPwdAttack.lastJob.Init(Param)
	// variations, err = util.ParseUri(url)
	// BlindSQL.variations =
	if value, ok := Param.Headers["Content-Type"]; ok {
		Param.ContentType = value
	}
	variations, err = util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		return nil, false, err
	}

	// sess := nenet.GetSessionByOptions(
	// 	&nenet.ReqOptions{
	// 		Timeout:       15 * time.Second,
	// 		RetryTimes:    Param.MaxRedirectTimes,
	// 		AllowRedirect: false,
	// 		Proxy:         Param.UpProxy,
	// 		Cert:          Param.Cert,
	// 		PrivateKey:    Param.CertKey,
	// 	})

	//赋值
	WeakPwdAttack.variations = variations
	WeakPwdAttack.lastJob.Layer.Sess.AllowRedirect = false
	WeakPwdAttack.TargetUrl = Param.Url
	WeakPwdAttack.lastJob.Layer.Method = Param.Method
	WeakPwdAttack.lastJob.Layer.ContentType = Param.ContentType
	WeakPwdAttack.lastJob.Layer.Headers = Param.Headers
	WeakPwdAttack.lastJob.Layer.Body = []byte(Param.Body)

	var userpwdidx []layers.IdxVariable
	var is_user bool
	var is_password bool

	var userindexbyVarparam layers.IdxVariable //用户名的index
	var passindexbyVarparam layers.IdxVariable //密码的index

	for _, u := range UserArray {
		for _, vp := range variations.Params {
			if strings.EqualFold(vp.Name, u) {
				userindexbyVarparam.Idx = vp.Index
				userindexbyVarparam.Flag = "username"
				userpwdidx = append(userpwdidx, userindexbyVarparam)
				is_user = true
				// userpwdidx.
				break
			}
		}
	}

	for _, v := range passArray {
		for _, vp := range variations.Params {
			if strings.EqualFold(vp.Name, v) {
				passindexbyVarparam.Idx = vp.Index
				passindexbyVarparam.Flag = "password"
				userpwdidx = append(userpwdidx, passindexbyVarparam)
				is_password = true
				break
			}
		}
	}

	if !(is_user && is_password) {
		return nil, false, errors.New("not found user and password")
	}
	timeout := make(map[string]string)
	timeout["timeout"] = "25"

	var ERRORPWDFeatures *layers.MFeatures
	//测试特征一

	userpwdidx[0].Variable = test1userPass[0] //设置用户名
	userpwdidx[1].Variable = test1userPass[1] //设置密码
	Features1, err := WeakPwdAttack.lastJob.RequestByIndexs(userpwdidx, Param.Url, timeout)
	if err != nil {
		return nil, false, err
	}
	defer Features1.Clear()

	userpwdidx[0].Variable = test2userPass[0] //设置用户名
	userpwdidx[1].Variable = test2userPass[1] //设置密码
	//测试特征二
	Features2, err := WeakPwdAttack.lastJob.RequestByIndexs(userpwdidx, Param.Url, timeout)
	if err != nil {
		return nil, false, err
	}
	defer Features2.Clear()
	if layers.CompareFeatures([]*layers.MFeatures{Features1}, []*layers.MFeatures{Features2}) {
		ERRORPWDFeatures = Features1
	}

	for _, username := range config.GlobalUserNameList {
		for _, password := range config.GlobalPasswordList {
			userpwdidx[0].Variable = username
			userpwdidx[1].Variable = password
			testFeatures, err := WeakPwdAttack.lastJob.RequestByIndexs(userpwdidx, Param.Url, timeout)
			if err != nil {
				logger.Error(err.Error())
			}
			defer testFeatures.Clear()
			if ERRORPWDFeatures != nil && testFeatures != nil {
				if !layers.CompareFeatures([]*layers.MFeatures{testFeatures}, []*layers.MFeatures{ERRORPWDFeatures}) {
					//都测试完成后，可以断定这个站点没有对密码长度进行限制。
					output := fmt.Sprintf("weak passwd denial of service userName:%s password:%s", username, password)
					Result := util.VulnerableTcpOrUdpResult(Param.Url,
						output,
						[]string{string(testFeatures.Request.String())},
						[]string{string(testFeatures.Response.String())},
						"high",
						Param.Hostid, string(plugin.WeakPwdAttack))
					gd.Alert(Result)
					testFeatures.Clear()
					return Result, true, err
				}
			}

		}
	}

	return nil, false, err
}
