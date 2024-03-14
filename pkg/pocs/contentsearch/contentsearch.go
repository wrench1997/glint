package contentsearch

import (
	"bytes"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/thoas/go-funk"
)

var DefaultProxy = ""
var cert string
var mkey string
var threadwg sync.WaitGroup //同步线程

type Text struct {
	CONTENTSEARCH []string
	idxs          []int
}

type classcontentsearch struct {
	scheme layers.Scheme
	// InjectionPatterns      classInjectionPatterns
	TargetUrl            string
	inputIndex           int
	reflectionPoint      int
	disableSensorBased   bool
	currentVariation     int
	foundVulnOnVariation bool
	variations           *util.Variations
	lastJob              layers.LastJob
	lastJobProof         interface{}
	// injectionValidator     TInjectionValidator
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
}

func (t *Text) String() string {
	var bufio bytes.Buffer
	for _, v := range t.CONTENTSEARCH {
		bufio.WriteString(v + "\n")
	}
	return bufio.String()
}

func (t *Text) IsEmpty() bool {
	if len(t.CONTENTSEARCH) == 0 {
		return false
	}
	return true
}

func VaildEmail(email string) bool {
	var skippedEndings = []string{
		"@example.com",
		".example.com",
		"@sample.com",
		"@email.tst",
		"@domain.com",
		"@sitename.com",
		"@php.net",
		"@httpd.apache.org",
		"@magento.com",
		"@email.com",
		".png",
		".jpeg",
		".gif",
		".jpg",
		".bmp",
		".tif",
		".svg",
	}
	var skippedEmails = []string{
		"webmaster@", "hostmaster@", "info@", "support@", "sales@", "marketing@", "news@", "contact@", "helpdesk@", "help@", "sample@", "postmaster@", "security@", "root@",
		"sysadmin@", "abuse@",
		"admin@", "administrator@",
		"noreply@", "no-reply@",
		"your@", "your@friend.com",
	}
	if email != "" {
		regstr := "(?i)(^u00[a-f0-9]{2})"
		re, _ := regexp.Compile(regstr)
		if re.Match([]byte(email)) {
			return false
		}
		for _, v := range skippedEndings {
			if strings.HasSuffix(strings.ToLower(email), v) {
				return false
			}
		}
		for _, v := range skippedEmails {
			if strings.HasPrefix(strings.ToLower(email), v) {
				return false
			}
		}
	}
	return true
}

func (s *classcontentsearch) CheckForEmailAddr(responseBody []string, contentTypes []string) (Text, bool) {
	// var excludedContentTypes = []string{
	// 	"text/css", "application/javascript", "application/ecmascript", "application/x-ecmascript",
	// 	"application/x-javascript", "text/javascript", "text/ecmascript", "text/javascript1.0",
	// 	"text/javascript1.1", "text/javascript1.2", "text/javascript1.3", "text/javascript1.4",
	// 	"text/javascript1.5", "text/jscript", "text/livescript", "text/x-ecmascript", "text/x-javascript",
	// }
	var matchstr Text
	// for idx, v := range excludedContentTypes {
	// 	if strings.EqualFold(v, contentTypes[idx]) {
	// 		continue
	// 	}
	// }

	regexEmails := `(?i)([_a-z\d\-\.]+@([_a-z\d\-]+(\.[a-z]+)+))`
	re, _ := regexp.Compile(regexEmails)
	for idx, body := range responseBody {
		email_str := re.FindString(body)
		if VaildEmail(email_str) && email_str != "" {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, email_str)
			matchstr.idxs = append(matchstr.idxs, idx)
			// return email_str, true

		}
	}

	return matchstr, matchstr.IsEmpty()
}

func invalidIPAddress(input string) bool {
	// regexIp := `\b(.0\.0$`
	// RE, err := regexp.Compile(regexIp)
	// if err != nil {
	// 	logger.Error("Invalid IP regexp : %s", err.Error())
	// }

	matched, err := regexp.MatchString("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}", input)
	if err != nil {
		logger.Error("Invalid IP regexp : %s", err.Error())
	}
	if matched {
		return true
	}
	return false
}

func (s *classcontentsearch) CheckForIpAddr(responseBody []string) (Text, bool) {
	regexIp := `\b(192\.168\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|172\.(?:16|17|18|19|(?:2[0-9])|30|31)\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))|10\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5]))\.(?:[0-9]{1,2}|[01][0-9]{2}|2(?:[0-4][0-9]|5[0-5])))\b`
	RE, _ := regexp.Compile(regexIp)
	var matchstr Text
	for idx, body := range responseBody {
		ips := RE.FindAllString(body, -1)
		if ips != nil && !invalidIPAddress(ips[0]) {
			if !funk.Contains(s.TargetUrl, ips[0]) {
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, ips[0])
				matchstr.idxs = append(matchstr.idxs, idx)
			}
		}
	}
	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForTrojanShellScript(responseBody []string) (Text, bool) {
	regexes := []string{
		`(<title>nsTView\s\v[\s\S]*?nst.void.ru<\/title>[\s\S]*?<b>nsTView\sv[\s\S]*?<a\shref=http:\/\/nst.void.ru\sstyle\='text-decoration:none;'>[\s\S]*?<b>Host:<\/b>[\s\S]*?<b>IP:<\/b>[\s\S]*?<b>Your\sip:<\/b>)`,
		`(<\/font><\/b><\/td><td\sclass=td1\salign=left><input\stype=checkbox\sname=m\sid=m\svalue="1"><input\stype=text\sname=s_mask\ssize=82\svalue=".txt;.php">\*\s\(\s.txt;.php;.htm\s\)<input\stype=hidden\sname=cmd\svalue="search_text"><input\stype=hidden\sname=dir\svalue="[^"]*"><\/td><\/tr><\/table><\/)`,
		`(<\/th><\/tr><tr><td><p\salign="left"><b>Software:&nbsp;[\s\S]*act=phpinfo"\starget="[\s\S]*<\/b>&nbsp;<\/p><p\salign="left"><b>Safe-mode:&nbsp;<font\scolor=[\s\S]*act=ftpquickbrute&d=C%3A%[\s\S]*act=selfremove"><)`,
		`(<title>\sCrystal\sshell<\/title>[\s\S]*?<font size="1"\sface="Arial">Crystal hack shellphp<\/font><\/span>[\s\S]*2006-2007<\/span>)`,
		`(<pre><form\saction\=""\sMETHOD\=GET\s>execute\scommand\:\s<input\stype="text"\sname="c"><input\stype="submit"\svalue="go"><hr><\/form>)`,
		`(Usage\:\shttp\:\/\/target\.com\/simple-backdoor.php\?cmd=cat\+\/etc\/passwd)`,
		`(<FORM\saction="[\s\S]*?"\smethod="POST">\n<input\stype=text\sname="\.CMD"\ssize=45\svalue="">\n<input\stype=submit\svalue="Run">\n<\/FORM>)`,
		`(<title>[\s\S]*?WSO\s\d\.\d<\/title>[\s\S]*?<span>Execute:<\/span><br><input class='toolsInp' type=text name=c value=)`,
		`(<head><title>\n\s+ASPXSpy\d\.\d\s->\sBin\:\)\n<\/title>[\s\S]*<span\sid="PassLabel">Password:<\/span>)`,
		`(<h1>ASPX Shell by LT<\/h1>)`,
		`<b>Mass deface<\/b><\/u><\/a>.*<b>Bind<\/b><\/u><\/a>.*<b>Processes<\/b>.*<b>FTP Quick brute<\/b>.*<b>LSA<\/b>.*<b>SQL<\/b>.*<b>PHP-code<\/b>.*<b>PHP-info<\/b>.*<b>Self remove<\/b>.*<b>Logout<\/b>`,
		`<b>Encoder<\/b>.*<b>Bind<\/b>.*<b>Proc.<\/b>.*<b>FTP brute<\/b>.*<b>Sec.<\/b>.*<b>SQL<\/b>.*<b>PHP-code<\/b>.*<b>Feedback<\/b>.*<b>Self remove<\/b>.*<b>Logout<\/b>`,
		`\$sess_cookie = "c99shvars"; \/\/ cookie-variable name`,
		`<input type=text name="\.CMD" size=45 value="[^"<]*">[\n\r]{2}<input type=submit value="Run">`,
		`<input type=text name="\.CMD" size=45 value="<%= szCMD %>">[\n\r]{2}<input type=submit value="Run">`,
		`<title>nsTView v[^<]*<\/title>[\S\s]+<input type=password name=pass size=30 tabindex=1>\r\n<\/form>\r\n<b>Host:<\/b> [^<]*<br>\r\n<b>IP:<\/b>[^<]*<br>\r\n<b>Your ip:<\/b>[^<]*`,
		`<b>Rename<\/b><\/a><br><a href='\$php_self\?d=\$d&download=\$files\[\$i\]' title='Download \$files\[\$i\]'><b>Download<\/b><\/a><br><a href='\$php_self\?d=\$d&ccopy_to=\$files\[\$i]' title='Copy \$files\[\$i\] to\?'><b>Copy<\/b><\/a><\/div><\/td><td bgcolor=\$color>\$siz<\/td><td bgcolor=\$color><center>\$owner\/\$group<\/td><td bgcolor=\$color>\$info<\/td><\/tr>";`,
		`<b>Rename<\/b><\/a><br><a href='[^'$]*' title='[^'$]*'><b>Download<\/b><\/a><br><a href='[^'$]*' title='[^'$]*'><b>Copy<\/b><\/a><\/div><\/td><td bgcolor=[^>$]*>[^>$]*<\/td><td bgcolor=[^>$]*><center>[^>$]*<\/td><td bgcolor=[^>$]*>[^>$]*<\/td>`,
		`<pre><form action="[^<]*" METHOD=GET >execute command: <input type="text" name="c"><input type="submit" value="go">`,
		`<pre><form action="<\? echo \$PHP_SELF; \?>" METHOD=GET >execute command: <input type="text" name="c"><input type="submit" value="go">`,
		`<font color=black>\[<\/font> <a href=[^?]*\?phpinfo title="Show phpinfo\(\)"><b>phpinfo<\/b><\/a> <font color=black>\]<\/font>`,
		`<a href=".\$_SERVER\['PHP_SELF'\]."\?phpinfo title=\\"".\$lang\[\$language.'_text46'\]\."\\"><b>phpinfo<\/b><\/a>`,
		`<form name="myform" action="[^<"]*" method="post">\r\n<p>Current working directory: <b>\r\n<a href="[^"]*">Root<\/a>\/<\/b><\/p>`,
		`echo "<option value=\\"". strrev\(substr\(strstr\(strrev\(\$work_dir\), "\/"\), 1\)\) ."\\">Parent Directory<\/option>\\n";`,
		`<center><h2>vBulletin pwn v0\.1<\/h2><\/center><br \/><br \/><center>`,
		`<p class='danger'>Using full paths in your commands is suggested.<\/p>`,
		`<head><title>Win MOF Shell<\/title><\/head>`,
		`<title>Weakerthan PHP Exec Shell - 2015 WeakNet Labs<\/title>`,
	}
	var matchstr Text
	for idx, body := range responseBody {
		for _, r := range regexes {
			RE, _ := regexp.Compile(r)
			matcharray := RE.FindAllString(body, -1)
			if len(matcharray) != 0 {
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, matcharray[0])
				matchstr.idxs = append(matchstr.idxs, idx)
				// return matcharray[0], true
			}
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForColdFusionPathDisclosure(responseBody []string) (Text, bool) {
	r1 := regexp.MustCompile(`The Error Occurred in <b>([\s\S]*): line[\s\S]*<\/b><br>`)
	r2 := regexp.MustCompile(`The error occurred while processing[\s\S]*Template: ([\s\S]*) <br>.`)
	r3 := regexp.MustCompile(`The error occurred while processing[\s\S]*in the template file ([\s\S]*)\.<\/p><br>`)
	var m []string
	var matchstr Text
	for idx, body := range responseBody {
		m = r1.FindAllString(body, -1)
		if len(m) == 0 {
			m = r2.FindAllString(body, -1)
			if len(m) == 0 {
				m = r3.FindAllString(body, -1)
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
				matchstr.idxs = append(matchstr.idxs, idx)
			}
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForRSAPrivateKey(responseBody []string) (Text, bool) {

	var matchstr Text
	r1 := regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----([\r\n][^\-]+)+-----END RSA PRIVATE KEY-----`)
	for idx, body := range responseBody {
		m := r1.FindAllString(body, -1)
		if len(m) != 0 {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForASPNETPathDisclosure(responseBody []string) (Text, bool) {
	r1 := regexp.MustCompile(`<title>Invalid\sfile\sname\sfor\smonitoring:\s'([^']*)'\.\sFile\snames\sfor\smonitoring\smust\shave\sabsolute\spaths\,\sand\sno\swildcards\.<\/title>`)
	var matchstr Text
	for idx, body := range responseBody {
		m := r1.FindAllString(body, -1)
		if len(m) != 0 {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForMySQLConnectionInfo(responseBody []string) (Text, bool) {
	var matchstr Text
	for idx, body := range responseBody {
		if !funk.Contains(body, `<?`) {
			continue
		}

		r1 := regexp.MustCompile(`mysql_[p]*connect\(["']{0,1}[a-z0-9\-\.]+["']{0,1}\s*,`)
		m := r1.FindAllString(body, -1)
		if len(m) != 0 {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForDatabaseConnectionStringDisclosure(responseBody []string) (Text, bool) {
	var matchstr Text
	for idx, body := range responseBody {
		if !funk.Contains(body, `;DATABASE=`) && !funk.Contains(body, `;UID=`) && !funk.Contains(body, `;PWD=`) {
			continue
		}

		if !funk.Contains(body, `!function(`) || !funk.Contains(body, `function(`) || !funk.Contains(body, `(window.webpackJsonp=`) {
			continue
		}
		m := []string{}
		r1 := regexp.MustCompile(`.*?(;DATABASE=[a-zA-Z0-9]+;UID=[a-zA-Z0-9]+;.*?;PWD=).*`)
		m = r1.FindAllString(body, -1)
		if len(m) == 0 {
			r2 := regexp.MustCompile(`.*?(;DATABASE=[a-zA-Z0-9]+;UID=[a-zA-Z0-9]+;.*?;PWD=).*`)
			m = r2.FindAllString(body, -1)
		}
		if len(m) != 0 {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForUsernameOrPasswordDisclosure(responseBody []string) (Text, bool) {
	var matchstr Text
	r1 := regexp.MustCompile(`(?i)(?m)(['"]?(db[\-_])?(uid|user|username)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){3,}['"]?[,]?([\r\n]+)\s*['"]?(db[\-_])?(pass|pwd|passwd|password)['"]?\s?(:|=)\s*['"]?([A-Za-z0-9_\-@$!%*#?&]){6,}['"]?([,\r\n]|$))`)
	for idx, body := range responseBody {
		m := r1.FindAllString(body, -1)
		if len(m) != 0 {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}
	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForPathDisclosure(responseBody []string, fullPath []*url.URL) (Text, bool) {
	var matchstr Text
	for idx, body := range responseBody {
		// Windows
		r1 := regexp.MustCompile(`(?i)([a-z])\:\\(program files|windows|inetpub|php|document and settings|www|winnt|xampp|wamp|temp|websites|apache|apache2|site|sites|htdocs|web|http|appserv)[\\\w]+(\.\w+)?`)
		m := r1.FindAllString(body, -1)
		if len(m) != 0 {
			continue
		}
		// Unix
		r2 := regexp.MustCompile(`[\s\t:><|\(\)\[\}](\/(var|www|usr|Users|user|tmp|etc|home|mnt|mount|root|proc)\/[\w\/\.]*(\.\w+)?)`)
		m2 := r2.FindAllString(body, -1)
		if len(m2) != 0 {
			if strings.HasSuffix(m2[0], fullPath[idx].Path) {
				continue
			}
			fileExts := strings.Split(m2[0], ".")
			if len(fileExts) != 0 {
				fExt := fileExts[len(fileExts)-1]
				if fExt == "js" {
					continue
				}
			}

			DIRS := strings.Split(m2[0], "/")
			if len(DIRS) < 3 {
				continue
			}

			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForDjangoDebugMode(responseBody []string) (Text, bool) {
	var matchstr Text
	r1 := regexp.MustCompile(`(?i)(?m)<th>Django Version:<\/th>[\S\s]*<th>Exception Type:<\/th>`)
	for idx, body := range responseBody {
		m := r1.FindAllString(body, -1)
		if len(m) != 0 {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, m...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForWhenRegexMatch(regex string, responseBody string) ([]string, bool) {
	r1 := regexp.MustCompile(`regex`)
	m := r1.FindAllString(responseBody, -1)
	if len(m) != 0 {
		return m, true
	}
	return m, false
}

func (s *classcontentsearch) CheckForStackTraces(responseBody []string) (Text, bool) {
	//foundIssues := false
	var MatchInfo []string
	var IsVuln bool
	var matchstr Text
	for idx, body := range responseBody {
		// ASP.NET Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<b>Stack Trace:<\/b> <br><br>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// ColdFusion Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<td class="struct" onClick="cfdump_toggleRow\(this\);" style="[^"]*" title="click to collapse">StackTrace<\/td>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Python Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<td class="struct" onClick="cfdump_toggleRow\(this\);" style="[^"]*" title="click to collapse">StackTrace<\/td>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Ruby Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<p id="explanation">You're seeing this error because you have`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`onclick="toggleBacktrace\(\); return false">\(expand\)<\/a><\/p>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<h3 id="env-info">Rack ENV<\/h3>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Tomcat Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<b>exception<\/b> <pre>[\S\s]*<\/pre><\/p><p><b>root cause<\/b> <pre>[\S\s]*javax\.servlet\.http`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<b>note<\/b>\s*<u>The full stack trace of the root cause is available in the Apache Tomcat\/`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Grails Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<h1>Grails Runtime Exception<\/h1> <h2>Error Details<\/h2>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Apache MyFaces Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<h1>An Error Occurred:<\/h1>[\n\r ]*<div id="error" class="grayBox" style="[\s\S]*-<\/span> Stack Trace<\/a><\/h2>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}

		// Laravel Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<h1>Whoops, looks like something went wrong\.<\/h1>\s*<h2 class="block_exception clear_fix">`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}

		//  RoR Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<title>Action Controller: Exception caught<\/title>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}

		// CakePHP Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<div id="stack-frame-0" style="display:none;" class="stack-details">`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}

		// CherryPy Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<pre id="traceback">.+<\/pre>\r?\n.+<div id="powered_by">\r?\n.+<span>\r?\n.+Powered by <a href="http:\/\/www.cherrypy.org"><\/a>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForelmahInfoDisclosure(responseBody []string) (Text, bool) {
	var MatchInfo []string
	var IsVuln bool
	var matchstr Text
	for idx, body := range responseBody {
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<th class="host-col"[^\>]*>Host<\/th>\s*<th class="code-col"[^\>]*>Code<\/th>\s*<th class="type-col"[^\>]*>Type<\/th>\s*<th class="error-col"[^\>]*>Error<\/th>\s*<th class="user-col"[^\>]*>User<\/th>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Apache MyFaces Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<li><a href="\/elmah.axd" title="List of logged errors">Errors<\/a><\/li><li><a href="http:\/\/elmah.googlecode.com\/" title="Documentation, discussions, issues and more">Help<\/a>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
	}
	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForSQLDatabaseDump(responseBody []string) (Text, bool) {
	var MatchInfo []string
	var IsVuln bool
	var matchstr Text
	for idx, body := range responseBody {
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<th class="host-col"[^\>]*>Host<\/th>\s*<th class="code-col"[^\>]*>Code<\/th>\s*<th class="type-col"[^\>]*>Type<\/th>\s*<th class="error-col"[^\>]*>Error<\/th>\s*<th class="user-col"[^\>]*>User<\/th>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}
		// Apache MyFaces Stack Trace
		MatchInfo, IsVuln = s.CheckForWhenRegexMatch(`<li><a href="\/elmah.axd" title="List of logged errors">Errors<\/a><\/li><li><a href="http:\/\/elmah.googlecode.com\/" title="Documentation, discussions, issues and more">Help<\/a>`, body)
		if IsVuln {
			matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
			matchstr.idxs = append(matchstr.idxs, idx)
		}

	}
	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForStrutsDevMode(responseBody []string) (Text, bool) {
	var MatchInfo []string
	var IsMatch bool
	var matchstr Text
	for idx, body := range responseBody {
		MatchInfo, IsMatch = s.CheckForWhenRegexMatch(`<title>Struts Problem Report<\/title>`, body)
		if IsMatch {
			patternStr := `You are seeing this page because development mode is enabled.  Development mode, or devMode, enables extra`
			if funk.Contains(body, patternStr) {
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, MatchInfo...)
				matchstr.idxs = append(matchstr.idxs, idx)
			}
		}
	}
	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForWordPressDBCredentials(responseBody []string) (Text, bool) {
	var matchstr Text
	for idx, Body := range responseBody {
		if funk.Contains(Body, `/** The name of the database for WordPress */`) &&
			funk.Contains(Body, `/** MySQL database username */`) &&
			funk.Contains(Body, `/** MySQL database password */`) {
			patternStr := "define( 'DB_PASSWORD', '"
			if funk.Contains(Body, patternStr) {
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, patternStr)
				matchstr.idxs = append(matchstr.idxs, idx)
			}
		}
	}
	return matchstr, matchstr.IsEmpty()
}

func (s *classcontentsearch) CheckForErrorMessages(responseBody []string) (Text, bool) {
	var matchstr Text
	for idx, body := range responseBody {
		for _, plain := range layers.ErrorMessagesPlainText {
			if funk.Contains(body, plain) {
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, plain)
				matchstr.idxs = append(matchstr.idxs, idx)
			}
		}
		for _, regex := range layers.ErrorMessagesRegexes {
			r, _ := regexp.Compile(regex)
			C := r.FindAllStringSubmatch(body, -1)
			if len(C) != 0 {
				matchstr.CONTENTSEARCH = append(matchstr.CONTENTSEARCH, C[0]...)
				matchstr.idxs = append(matchstr.idxs, idx)
				// return C[0][0], true
			}
		}
	}

	return matchstr, matchstr.IsEmpty()
}

func Start_text_Macth(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	// var err error
	var replyinfo []util.Reply
	util.Setup()
	// cvs := args.(int)
	// println(cvs)

	// var blastIters interface{}
	group := args
	// urlsinfo = group.GroupUrls.([]interface{})
	// for i := 0; i < len(group.GroupUrls); i++ {

	// }
	sess := nenet.GetSessionByOptions(
		&nenet.ReqOptions{
			Timeout:       5 * time.Second,
			RetryTimes:    5,
			AllowRedirect: true,
			Proxy:         "",
			Cert:          "",
			PrivateKey:    "",
		})

	for i := 0; i < len(group.GroupUrls); i++ {

		//group := args.(plugin.GroupData)
		var Param layers.PluginParam
		ct := layers.CheckType{IsMultipleUrls: true, Urlindex: i}
		ct.IsMultipleUrls = true
		Param.ParsePluginParams(args, ct)
		if Param.CheckForExitSignal() {
			continue
		}

		sess.ReqOptions.Timeout = time.Duration(Param.Timeout) * time.Second
		sess.ReqOptions.Proxy = Param.UpProxy
		sess.ReqOptions.Cert = Param.Cert
		sess.ReqOptions.PrivateKey = Param.CertKey

		body := util.Str2Byte(Param.Body)
		req, resp, err := sess.Request(Param.Method, &Param.Url, &Param.Headers, &body)

		if err != nil {
			continue
		}
		defer req.ResetBody()
		defer req.Reset()
		defer resp.ResetBody()
		defer resp.Reset()

		replyinfo = append(replyinfo, util.Reply{Idx: i,
			Req:         req,
			Resp:        resp,
			Hostid:      Param.Hostid,
			Url:         Param.Url,
			ContentType: Param.ContentType,
		})
		//fmt.Println(resp.String())

	}

	var bodys []string
	var urlParsers []*url.URL
	var ContentTypes []string
	for _, reply := range replyinfo {
		// fmt.Println(idx)
		bodys = append(bodys, reply.Resp.String())

		u, err := url.Parse(reply.Url)
		if err != nil {
			logger.Error(err.Error())
			continue
		}
		urlParsers = append(urlParsers, u)
		ContentTypes = append(ContentTypes, reply.ContentType)
	}

	var contentsearch classcontentsearch

	matchtext, IsVuln := contentsearch.CheckForErrorMessages(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"medium",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0004")
		Result.Vulnid = "rj-014-0004"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForWordPressDBCredentials(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0005")

		Result.Vulnid = "rj-014-0005"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForStrutsDevMode(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0006")
		Result.Vulnid = "rj-014-0006"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForSQLDatabaseDump(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"medium",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0003")
		Result.Vulnid = "rj-014-0003"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForelmahInfoDisclosure(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"medium",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0007")
		Result.Vulnid = "rj-014-0007"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForStackTraces(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"medium",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0002")
		Result.Vulnid = "rj-014-0002"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForDatabaseConnectionStringDisclosure(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0008")
		Result.Vulnid = "rj-014-0008"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForEmailAddr(bodys, ContentTypes)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0001")
		Result.Vulnid = "rj-014-0001"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForDjangoDebugMode(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0009")
		Result.Vulnid = "rj-014-0009"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	// u, err := url.Parse(Param.Url)
	// if err != nil {
	// 	//logger.Error(err.Error())
	// 	return nil, true, fmt.Errorf("NOT FOUND VULN")
	// }

	matchtext, IsVuln = contentsearch.CheckForPathDisclosure(bodys, urlParsers)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0010")
		Result.Vulnid = "rj-014-0010"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"high",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0011")
		Result.Vulnid = "rj-014-0011"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	//
	matchtext, IsVuln = contentsearch.CheckForMySQLConnectionInfo(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0012")
		Result.Vulnid = "rj-014-0012"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForASPNETPathDisclosure(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0013")
		Result.Vulnid = "rj-014-0013"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForRSAPrivateKey(bodys)

	if IsVuln {

		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"high",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0014")

		Result.Vulnid = "rj-014-0014"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForColdFusionPathDisclosure(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"informaintion",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0015")
		Result.Vulnid = "rj-014-0015"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForTrojanShellScript(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"low",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0016")
		Result.Vulnid = "rj-014-0016"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	matchtext, IsVuln = contentsearch.CheckForIpAddr(bodys)

	if IsVuln {
		Result := util.VulnerableTcpOrUdpResult(replyinfo[matchtext.idxs[0]].Url,
			matchtext.String(),
			[]string{replyinfo[matchtext.idxs[0]].Req.String()},
			[]string{replyinfo[matchtext.idxs[0]].Resp.String()},
			"low",
			replyinfo[matchtext.idxs[0]].Hostid, "rj-014-0017")
		Result.Vulnid = "rj-014-0017"
		//通知收取漏洞线程
		group.Alert(Result)
	}

	return nil, IsVuln, nil
}
