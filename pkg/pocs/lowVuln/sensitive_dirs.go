package lowsomething

import (
	"errors"
	"fmt"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"net/http"
	"net/url"
	"strings"
	"time"
)

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

// these variants will only be added to the crawler (tested on all dirs)
var interesting_dirs = []string{
	"plupload", "js", "lib", "libs", "report", "soap", "nusoap", "docs", "assets",
	"ad", "ads", "banner", "banners", "account", "api", "ws", "vendor", "Flex",
	"restservice", "service", "RestApi", "rest", "amcharts", "amcolumn",
	"blogs", "apps", "chat", "console", "addons", "attachments",
	"php-ofc-library", "player",
	"invoker", "cp", "testweb", "pma", "dav", "frontend",
	"plugins", "themes", "upgrade", "text-base",
	"wp-content", "wp-admin", "wp-includes",
	"iishelp", "iisadmin", "tsweb", "xmlrpc",
	"cache", "cache_html", "genericons",
	"common", "shell", "core", "menu", "v1", "types", "base", "group", "languages", "english", "smarty",
	"example", "examples", "sample", "samples", "script", "scripts", "list", "mime", "threads", "fonts",
	"class", "classes", "download", "downloads", "Downloads", "Download", "modules", "down", "oauth", "json",
	"compat", "recaptcha", "html", "controller",
	"signup", "login",
	"WebService", "aspnet", "Exchange", "webaccess", "web", "exchange",
	"~root", "root", "htdocs", "www", "Root",
	"~ftp", "~guest", "~nobody", "~www",
	"CMS", "cms",
	"wizards", "editor", "fck", "edit",
	"info", "dat", "data", "file", "files", "zip", "zipfiles", "zips", "mp3",
	"search", "rss", "feed", "atom",
	"image", "images", "img", "Images", "pictures", "icons", "resources", "graphics", "pics", "icon", "thumb", "thumbnail", "photo",
	"tag", "tags", "messages",
	"audio", "dl", "package", "build", "snapshot",
	"profile", "Profile",
	"Default", "default", "archives", "documents",
	"'", "!", "!!", "!!!", "@", "_", "$", "#", "-", "+", "?",
	"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "r", "s", "t", "q", "v", "w", "z",
	"0", "00", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10",
	"2011", "2012", "2013", "2014",
	"security", "content", "main", "media", "templates", "forms", "flash", "portal",
	"xml", "user", "view", "browse", "demo", "thread",
	"php", "PHP",
	"index", "Index", "music", "contents",
	"projects", "site", "version", "static", "space", "folder", "servlet", "storage",
	"misc", "page", "doc", "access", "release", "latest", "manual", "manuals", "usercp",
	"cerberusweb", "uri", "url", "utf8",
	"lostpassword", "forgot", "help",
	"index_files", "reset", "wp",
	"fileserver", "tcpdf",
	"de", "fr", "en", "mt"}

// these variants will only be tested in the start directory
var testOnRootDir_dirs = []string{
	"_vti_bin", "_vti_pvt", "_vti_aut", "_vti_adm",
	"cgi-bin", "cgi-sys", "manage_main", "workarea", "WorkArea",
	"adminzone", "na_admin", "simpleviewer",
	// web applications
	"phpBB", "phpBB2", "phpbb", "phpnuke", "sqlnet", "vb", "vbulletin", "wwwboard", "zope", "viewcvs",
	"nagios", "cacti", "munin", "zenoss",
	"cubecart", "cc", "cpg", "coppermine", "4images", "cart", "SugarCRM", "sugarcrm", "gallery",
	"joomla", "drupal", "oscommerce", "zencart", "eticket", "moodle", "piwik", "zenphoto", "tinymce", "firephp",
	"wordpress", "zenpage", "openx", "mambo", "buddypress", "aMember", "ATutor", "b2evolution", "autocms",
	"bbpress", "bitweaver", "bmforum", "cerberus", "cmsmadesimple", "cs-cart", "cs-whois", "cutenews",
	"deluxebb", "dchat", "phpFreeChat", "phpfreechat", "livechat", "livezilla", "trac", "e107", "ezPublish",
	"FusionBB", "geeklog", "ImageVue", "kayako", "mantis", "mint", "Mint", "multihost", "mybb", "opencart",
	"osTicket", "photopost", "phpAddressBook", "phpfusion", "phpgedview", "PHPizabi", "phplinks", "phplist",
	"phpmyfaq", "phponline", "phpshop", "pligg", "pmwiki", "postnuke", "punbb", "runcms", "serendipity", "smf", "ipb",
	"sphider", "typolight", "ubb_threads", "ultrastats", "vanilla", "videodb", "xoops", "x-cart", "alegrocart",
	"dotproject", "fluxbb", "interspire", "magento", "lifetype", "minibb", "modx", "prestashop", "silverstripe",
	"tikiwiki", "mediawiki", "dokuwiki", "piwigo", "phpCollab", "phpads", "noah", "redmine", "flyspray", "dolphin",
	"twiki", "vtiger", "adminui", "roller-ui",
	"solr1", "solr2", "solr3", "solr4", "solr5",
	"owa", "mrtg",
	"squirrel", "squirrelmail", "roundcube", "atmail", "roundcubemail",
	"whmcs",
	"ibill", "ccbill",
	"juddi",
	"anoncvs",
	"tomcat",
	"bugzilla",
	"django",
	"moinmoin",
	"xampp",
	"cfdocs", "CFIDE",
	"jrun",
	"forum", "blog", "poll", "support",
	"register", "tracker",
	"software", "category",
	"appengine", "symfony",
	"webstats",
	"webmail", "cpanel", "mail", "email", "mailman",
	"WebApplication1", "WebApplication2", "WebApplication3"}

type ClassSensitive struct {
	scheme                 layers.Scheme
	targetURL              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	trueFeatures           *layers.MFeatures
	lastJobProof           interface{}
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
}

func (c *ClassSensitive) ClearFeature() {
	if c.lastJob.Features != nil {
		c.lastJob.Features.Clear()
	}
	if c.trueFeatures != nil {
		c.trueFeatures.Clear()
	}
}

func sensitiveDir(dirPath string) bool {
	// Define a list of sensitive directories
	// sensitiveDirs :=

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

func (c *ClassSensitive) StartTesting(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	//var err error
	var variations *util.Variations

	var SensitiveDir ClassSensitive
	//var hostid int64
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
	gd := args
	ct := layers.CheckType{IsMultipleUrls: false}
	Param.ParsePluginParams(args, ct)
	if Param.CheckForExitSignal() {
		return nil, false, errors.New("receive task exit signal")
	}

	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       60 * time.Second,
			RetryTimes:    Param.MaxRedirectTimes,
			AllowRedirect: false,
			Proxy:         Param.UpProxy,
			Cert:          Param.Cert,
			PrivateKey:    Param.CertKey,
		})

	SensitiveDir.lastJob.Init(Param)

	variations, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		// logger.Error(err.Error())
		return nil, false, errors.New("not found")
	}
	//赋值
	SensitiveDir.variations = variations
	SensitiveDir.lastJob.Layer.Sess = sess
	SensitiveDir.targetURL = Param.Url
	SensitiveDir.lastJob.Layer.Method = Param.Method
	SensitiveDir.lastJob.Layer.ContentType = Param.ContentType
	SensitiveDir.lastJob.Layer.Headers = Param.Headers
	SensitiveDir.lastJob.Layer.Body = []byte(Param.Body)
	defer SensitiveDir.ClearFeature()

	timeout := make(map[string]string)
	timeout["timeout"] = "3"

	for _, dir := range sensitive_dirs {
		// Construct the full URL for the current directory
		dirURL := Param.Url + dir

		// Send a GET request to the current directory URL
		dirResp, err := http.Get(dirURL)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		defer dirResp.Body.Close()

		// Check the response status code for the current directory
		if dirResp.StatusCode == http.StatusOK {
			Result := util.VulnerableTcpOrUdpResult(Param.Url,
				"Possisble sensitive dirs",
				[]string{string("")},
				[]string{string("")},
				"low",
				Param.Hostid, string(plugin.ParamPoll))
			gd.Alert(Result)
			return Result, true, err
		}
	}

	return nil, false, errors.New("not found")
}
