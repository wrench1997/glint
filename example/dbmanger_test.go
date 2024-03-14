package mydemo

import (
	"encoding/base64"
	"glint/crawler"
	"glint/dbmanager"
	"glint/logger"
	"glint/plugin"
	"testing"
	"time"
)

func Test_GetConfig(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	v, err := Dm.GetTaskConfig(1)
	if err != nil {
		t.Error(err)
	}
	Dm.ConvertDbTaskConfigToYaml(v)
}

func Test_InstallScanResult(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	_, err = Dm.SaveScanResult(
		1,
		string(plugin.Xss),
		true,
		"http://rongji.com",
		"desad",
		"sdas",
		1,
	)
	if err != nil {
		t.Error(err)
	}
}

func Test_SaveGrabUri(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}

	u1 := dbmanager.GrapUrl{Taskid: 1, Hostid: 2, Url: "1212"}
	u2 := dbmanager.GrapUrl{Taskid: 1, Hostid: 2, Url: "12161322"}
	u3 := dbmanager.GrapUrl{Taskid: 1, Hostid: 2, Url: "1216132dasdsa2"}

	GrapUrls := []dbmanager.GrapUrl{u1, u2, u3}

	_, err = Dm.SaveGrabUri(
		GrapUrls,
	)
	if err != nil {
		t.Error(err)
	}
}

func Test_install_http_status_(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	State := dbmanager.PublishState{
		Id:          dbmanager.NewNullString("id"),
		Host:        dbmanager.NewNullString("Host"),
		Method:      dbmanager.NewNullString("Method"),
		Data:        dbmanager.NewNullString(base64.RawStdEncoding.EncodeToString([]byte{})),
		UserAgent:   dbmanager.NewNullString("UserAgent"),
		ContentType: dbmanager.NewNullString("ContentType"),
		CreatedTime: time.Now().Local(),
	}
	err = Dm.InstallHttpsReqStatus(&State)
	if err != nil {
		t.Error(err)
	}
}

func Test_QuitTime(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	err = Dm.DeleteScanResult(1)
	if err != nil {
		logger.Error(err.Error())
	}
}

func Test_GetUserNameORPassword(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	username_list, err := Dm.GetUserNameORPassword(6)
	if err != nil {
		t.Error(err)
	}
	logger.Info("%v", username_list)

}

func Test_SaveURLTree(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}

	var SiteRootNode crawler.SiteRootNode

	s := "http://api.themoviedb.org/3/tv/3"

	SiteRootNode.ADD_NODE(s)

	// SiteRootNode

	ss := "http://api.themoviedb.org/3/451/xss_3.php"

	SiteRootNode.ADD_NODE(ss)

	SiteRootNode.TaskId = 1
	SiteRootNode.HostID = 1

	var duts []crawler.DatabeseUrlTree
	duts = SiteRootNode.RootNodetoDBinfo(SiteRootNode.Root())

	err = Dm.SaveUrlTree(duts)
	if err != nil {
		t.Error(err)
	}
}

func Test_GetExtraHeaders(t *testing.T) {
	var err error
	Dm := dbmanager.DbManager{}
	err = Dm.Init()
	if err != nil {
		t.Error(err)
	}
	headers, err := Dm.GetExtraHeaders(6, 5)
	if err != nil {
		t.Error(err)
	}
	logger.Info("%v", headers)

}
