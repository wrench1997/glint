package mydemo

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"glint/crawler"
	"glint/logger"
	"glint/util"
	"io/ioutil"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
	"unsafe"
)

func Test_Post(t *testing.T) {
	body := "file=123456.fkuior.ceye.io&read=load+file"
	param, _ := util.ParseUri("", []byte(body), "POST", "application/x-www-form-urlencoded", nil)
	logger.Debug("%v", param)
	pal := param.SetPayloads("", "122", "POST")
	logger.Debug("%v", pal)
	//Get
	param1, _ := util.ParseUri("https://www.google.com/search?q=dasdas&oq=dasdas", []byte(""), "GET", "None", nil)
	logger.Debug("%v", param1)
	pal1 := param1.SetPayloads("https://www.google.com/search?q=dasdas&oq=dasdas", "122", "GET")
	logger.Debug("%v", pal1)
}

func Test_For(t *testing.T) {
	for i := 0; i < 2; i++ {
		fmt.Printf("%d", i)
	}
}

func Test_Regex(t *testing.T) {
	var tsr = `我的邮箱 ljl260435988@gmail.com`
	var regexemails = `(?i)([_a-z\d\-\.]+@([_a-z\d\-]+(\.[a-z]+)+))`
	re, _ := regexp.Compile(regexemails)
	result := re.FindString(tsr)
	fmt.Println(result)

	var tsrs = `192.168.166.16 192.168.166.7`
	regexIp := `\b(192\.168\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|172\.(?:16|17|18|19|(?:2[0-9])|30|31)\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|10\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5])))\b`
	RE, _ := regexp.Compile(regexIp)
	ips := RE.FindAllString(tsrs, -1)
	fmt.Println(ips)

	var tsrss = `"Db_user"="1221"
	"Db_pass"='20sdasdasd'`
	regexx := `(?i)(?m)(['"]?(db[\-_])?(uid|user|username)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){3,}['"]?[,]?([\r\n]+)\s*['"]?(db[\-_])?(pass|pwd|passwd|password)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){6,}['"]?([,\r\n]|$))`
	RE1, _ := regexp.Compile(regexx)
	m := RE1.FindAllString(tsrss, -1)
	fmt.Println(m)

	tsrsss := "/cn/about\r\n\r\r\n   "
	r := regexp.MustCompile(`(\r|\n|\s+)`)
	_url := r.ReplaceAllString(tsrsss, "")
	fmt.Println(_url)

}

func Test_Rate(t *testing.T) {
	//测试每秒发送10个链接,测试10秒
	myRate := util.Rate{}
	// bShutdown := make(chan bool)
	myRate.InitRate(20)

	requests := make(chan int, 5)
	for i := 1; i <= 5; i++ {
		requests <- i
	}
	close(requests)

	limiter := time.Tick(200 * time.Millisecond)

	for req := range requests {
		<-limiter
		fmt.Println("request", req, time.Now())
	}

	burstyLimiter := make(chan time.Time, 3)

	for i := 0; i < 3; i++ {
		burstyLimiter <- time.Now()
	}

	go func() {
		for t := range time.Tick(200 * time.Millisecond) {
			burstyLimiter <- t
		}
	}()

	burstyRequests := make(chan int, 5)
	for i := 1; i <= 5; i++ {
		burstyRequests <- i
	}
	close(burstyRequests)

	for req := range burstyRequests {
		<-burstyLimiter
		fmt.Println("request", req, time.Now())
	}

}

func Test_Ts(t *testing.T) {
	nm := util.NetworkManager{}
	arrays := unsafe.Sizeof(nm)
	// consumeGb := 1073741824
	// Count := consumeGb / arrays
	fmt.Println(arrays) // 8
}

func Test_mapinstaface(t *testing.T) {
	demo1 := make(map[string]interface{})
	demo2 := make(map[string]interface{})
	demo2["ssssss"] = 11122
	demo1["url"] = 1
	demo1["uk"] = demo2
	index := 0
	for _, v := range demo1 {
		rv := reflect.TypeOf(demo1)
		Field := rv.Field(index)
		fmt.Println(v)
		fmt.Println(Field.Name)
		index++
	}
}

func Test_AES_CBC_SHA256(t *testing.T) {
	ccc := "<script>var div=document.createElement('div');div.innerText = 'ab49bdd251591b16da'+'541abad631329c';document.body.appendChild(div);</script>"
	fmt.Println(len(ccc))
	orig := "hello world"
	key := "web2.0_password0"
	fmt.Println("原文：", orig)
	encryptCode := util.AesEncrypt(orig, key)
	fmt.Println("密文：", encryptCode)
	decryptCode := util.AesDecrypt(encryptCode, key)
	fmt.Println("解密结果：", decryptCode)
	fp, err := os.OpenFile("test64.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		logger.Fatal("%s", err.Error())
	}
	defer fp.Close()
	_, err = fp.Write([]byte(encryptCode))
	if err != nil {
		logger.Fatal("%s", err.Error())
	}
}

func Test_runFunc(t *testing.T) {
	s := "https://www.google.com/search/dsadsad?q=dasdas&oq=dasdas"
	//解析这个 URL 并确保解析没有出错。
	fmt.Println(util.GetScanDeepByUrl(s))

	rule1 := strings.Replace(s, "http://", "https://", -1)
	println(rule1)
	rule2 := strings.Replace(s, "https://", "http://", -1)
	println(rule2)
}

func Test_base64_encode(t *testing.T) {

	// fp, err := os.OpenFile("wvsc_blob.bin", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	file, err := os.Open("wvsc_blob.bin")
	if err != nil {
		panic(err)
	}
	defer file.Close()
	content, err := ioutil.ReadAll(file)
	// fp.Read()

	encryptCode := base64.StdEncoding.EncodeToString(content)

	fp, err := os.OpenFile("wvsc_blob.base64", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		logger.Fatal("%s", err.Error())
	}
	defer fp.Close()
	_, err = fp.Write([]byte(encryptCode))
	if err != nil {
		logger.Fatal("%s", err.Error())
	}
}

func Test_base64_decode(t *testing.T) {

	// fp, err := os.OpenFile("wvsc_blob.bin", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)

	// fp.Read()

	decryptArray, err := base64.StdEncoding.DecodeString("PCUgUmVzcG9uc2UuV3JpdGUoIjRkMDIwNzBlZmZkZDdlMzE5IiArICJjYTU2MWJjNjY2MTdhOGEiKSAlPg==")
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	fmt.Println(string(decryptArray))
}

func Test_GenVclock(t *testing.T) {
	err := util.GenerateVlockFile(30000)
	if err != nil {
		panic(err)
	}
}

func Test_GetFileNameFromUrl(t *testing.T) {
	ts1 := "http://localhost/slow/1222.json"
	filename, err := util.GetFileNameFromUrl(ts1)
	if err != nil {
		t.Fatalf("%s", err.Error())
	}
	fmt.Println(string(filename))
}

func Test_url_parse(t *testing.T) {
	//ListURLPath 此变量具有继承效应
	// var ListURLPath []string
	var SiteRootNode crawler.SiteRootNode

	s := "http://api.themoviedb.org/3/tv/3"

	SiteRootNode.ADD_NODE(s)

	// SiteRootNode

	ss := "http://api.themoviedb.org/3/451"

	SiteRootNode.ADD_NODE(ss)

	fmt.Println(SiteRootNode)

}

func Test_json_iterate(t *testing.T) {

	example2 := "{\"token\":\"Epoint_WebSerivce_**##0601\",\"params\":{\"currentpage\":\"111\",\"pagesize\":\"50\",\"areacode\":\"411500\"}}"
	var data interface{}
	if err := json.Unmarshal([]byte(example2), &data); err != nil {
		panic(err)
	}

	jsoniter := util.JSONKeyValueIterator{}

	len := jsoniter.Parser(data)

	fmt.Printf("itertator lenth:%d\n", len)

	dimensionKeys := jsoniter.GetstoreSort()

	for _, v := range dimensionKeys {
		fmt.Printf("dimension:%d Key:%s Keyindex:%d\n", v.Dimension(), v.Key(), v.KeyIndex())
	}

	jsoniter.Reset(data)

	jsoniter.SetValues(data, 3, "66666")

	jsoniter.Copytarget(data)

	// fmt.Printf("result :%s", jsoniter.String())
}

func Test_matchtohref(t *testing.T) {
	// 定义要匹配的正则表达式模式
	pattern := `href=".*8634&n974065=v934137.*"`

	// 将模式编译成正则表达式对象
	re := regexp.MustCompile(pattern)

	// 待匹配的字符串
	str := `<a href="https://example.com/index.html?8634&n974065=v934137">Link</a>`

	// 匹配字符串
	match := re.MatchString(str)

	fstr := re.FindAllString(str, -1)

	fmt.Println(match) // true
	fmt.Println(fstr)  // true
}

var sensitive_dirs = []string{"admin-console", "adminconsole", "jmx-console",
	"_layouts", "crm", "nbproject",
	"_private", ".ssh", "bin",
	"phpsysinfo", "phpldapadmin", "uploadify", "phpThumb", "zeroclipboard",
	"session", "sessions",
	"jenkins", "axis2",
	"_source", "_src", "_www", "spool",
	"tar.gz", "tar.bz2", "tar",
	"uploader", "uploads", "upload", "Upload", "incomming", "user_uploads",
	"New Folder", "New folder (2)",
	"log", "logs", "_logs", "logfile", "logfiles", "~log", "~logs",
	"settings", "global", "globals",
	"admin", "Admin", "ADMIN", "adminpanel", "admin0", "admin1", "admin_", "_admin", "_adm", "administrator", ".adm", ".admin", "~admin", "admin_files", "Administrator", "site_admin", "fileadmin", "adminfiles", "administration", "sysadmin", "administrative", "webadmin", "admins", "administrivia", "useradmin", "sysadmins", "admin_login", "admin_logon", "INSTALL_admin", "fpadmin", "siteadmin",
	".subversion", "services",
	"_sqladm", "sqladm",
	"client", "clients", "cmd",
	"restricted", "_pages",
	"webmin",
	"reseller", "personal", "updates",
	"err", "error", "_errors", "errors",
	"secret", "secrets", "Secret",
	"msql", "mysql", "mssql", "oracle",
	"db", "DB", "db2",
	"sql", "SQL", "__SQL", "_SQL",
	"dbase", "database",
	"cvs", "CVS", "svn", "SVN",
	"member", "members", "orders", "billing", "memberlist", "membersonly",
	"dump", "ftp", "accounts", "warez",
	"conf", "config", "Config",
	"phpmyadmin", "phpmyadmin0", "phpmyadmin1", "phpMyAdmin", "phpMyAdmin0", "phpMyAdmin1",
	"phpPgAdmin", "phppgadmin", "pgadmin", "pgmyadmin",
	"sqlbuddy", "solr", "SOLR",
	"customer", "customers",
	"intranet", "users",
	"setup", "install", "Install", "_install", "install_", "ainstall", "!install", "installer",
	"oldfiles", "old_files", "_files",
	"sysbackup", "export",
	"TEMP", "TMP", "TODO", "WS_FTP",
	"temp", "tmp", "test", "_test", "test_", "!test", "tst", "tests", "tools", "save", "testing", "_tests",
	"secure", "secured", "internal",
	"prv", "private", "csv", "CSV",
	"staff", "src", "etc",
	"system", "dev", "devel", "devels", "developer", "developers",
	"share", "beta", "bugs",
	"auth", "import", "stats", "statistics", "ini",
	"access-log", "error-log", "access_log", "error_log", "accesslog", "errorlog",
	"backup", "backups", "bak", "bac", "old", "_old",
	"inc", "include", "includes", "_include",
	"pass", "passwd", "password", "Password", "passwords",
	"jdbc", "odbc", "xls",
	"FCKeditor", "fckeditor", "ckeditor", "filemanager", "UserFiles", "UserFile", "userfiles",
	"__MACOSX", "horde", "webgrind",
	"management", "manager",
	"user_guide"}

func sensitiveDir(dirPath string) bool {
	// Define a list of sensitive directories
	var sensitiveDirs = sensitive_dirs

	// Check if the given directory path matches any of the sensitive directories
	for _, sensitiveDir := range sensitiveDirs {
		if strings.EqualFold(sensitiveDir, dirPath) {
			return true
		}
	}

	return false
}

func handleRequest(targeturl string) {
	// Parse the query parameter from the URL
	parsedURL, _ := url.Parse(targeturl)
	pathSegments := strings.Split(parsedURL.Path, "/")

	// Loop through the segments and print each one
	for _, segment := range pathSegments {
		// Call the sensitiveDir function to check if the directory is sensitive
		isSensitive := sensitiveDir(segment)
		// Send the result back to the client
		if isSensitive {
			fmt.Printf("The directory %s is sensitive.\n", segment)
		}
	}
}

func Test_Name(t *testing.T) {
	target := `http://xyzwfw.gov.cn/share`
	handleRequest(target)
}

func TestParseJSFile(t *testing.T) {
	url := "http://192.168.166.2/pikachu/assets/js/ace-extra.min.js"
	expectedFilename := "ace-extra.min.js"

	fileType, err := util.ParseJSFile(url)

	if err != nil {
		t.Fatalf("Error parsing JS file: %v", err)
	}

	if fileType.Filename != expectedFilename {
		t.Errorf("Expected filename %s, but got %s", expectedFilename, fileType.Filename)
	}

}
