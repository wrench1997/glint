package util

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"glint/logger"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/PuerkitoBio/goquery"
	"github.com/shirou/gopsutil/v3/cpu"

	// conf2 "github.com/jweny/pocassist/pkg/conf"
	// log "github.com/jweny/pocassist/pkg/logging"
	"github.com/Ullaakut/nmap/v2"
	"github.com/beevik/etree"
	"github.com/shopspring/decimal"
	"github.com/thoas/go-funk"
	"github.com/valyala/fasthttp"
	"github.com/valyala/fasthttp/fasthttpproxy"
)

var RRate = Rate{}
var IsSetup bool

type SiteFile struct {
	Filename    string
	Url         string
	Hash        string
	Filecontent []byte
	Synhash     string
}

func Setup() {
	// 请求限速 limiter 初始化
	RRate.InitRate(500)
	if !IsSetup {

		// fasthttp client 初始化
		DownProxy := ""
		client := &fasthttp.Client{
			// If InsecureSkipVerify is true, TLS accepts any certificate
			TLSConfig:                &tls.Config{InsecureSkipVerify: true},
			NoDefaultUserAgentHeader: true,
			DisablePathNormalizing:   true,
		}
		if DownProxy != "" {
			logger.Info("[fasthttp client use proxy ]", DownProxy)
			client.Dial = fasthttpproxy.FasthttpHTTPDialer(DownProxy)
		}

		fasthttpClient = client
	}

	IsSetup = true
	// jwt secret 初始化
	// jwtSecret = []byte("test")
}

func CLosefasthttp() {
	if IsSetup {
		fasthttpClient = nil
		IsSetup = false
	}
}

func IsFileExist(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func MergeMap(mObj ...map[int]interface{}) map[int]interface{} {
	newObj := map[int]interface{}{}
	for _, m := range mObj {
		for k, v := range m {
			newObj[k] = v
		}
	}
	return newObj
}

func StrMd5(str string) string {
	h := md5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}

func ConvertHeaders(headers interface{}) (map[string]string, error) {
	newheaders := map[string]string{}
	var err error
	if h, ok := headers.(map[string]interface{}); ok {
		for key, value := range h {
			if value != nil {
				newheaders[key] = value.(string)
			}
		}
	} else if h, ok := headers.([]Header); ok {
		for _, v := range h {
			newheaders[v.Name] = v.Value
		}
	} else if h, ok := headers.(map[string]string); ok {
		for key, value := range h {
			if value != "" {
				newheaders[key] = value
			}
		}

	} else {
		err = errors.New("invalid headers")
	}
	return newheaders, err
}

func ConvertHeadersinterface(headers interface{}) (map[string]interface{}, error) {
	newheaders := make(map[string]interface{})
	var err error
	if h, ok := headers.([]Header); ok {
		for _, v := range h {
			newheaders[v.Name] = v.Value
		}
	} else {
		err = errors.New("invalid headers")
	}
	return newheaders, err
}

func ReadFile(filePath string) []string {
	filePaths := []string{}
	f, err := os.OpenFile(filePath, os.O_RDONLY, 0644)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		rd := bufio.NewReader(f)
		for {
			line, err := rd.ReadString('\n')
			if err != nil || io.EOF == err {
				break
			}
			filePaths = append(filePaths, line)
		}
	}
	return filePaths
}

func JsontoStr(Element interface{}) (string, error) {
	jsonElement, err := json.Marshal(Element)
	if err != nil {
		logger.Error(err.Error())
	}
	msgstr := string(jsonElement)
	return msgstr, err
}

func deepCopySlice(original []interface{}) []interface{} {
	newSlice := make([]interface{}, len(original))
	for i, v := range original {
		switch val := v.(type) {
		case map[string]interface{}:
			newSlice[i] = DeepCopyMap(val)
		case []interface{}:
			newSlice[i] = deepCopySlice(val)
		default:
			newSlice[i] = v
		}
	}
	return newSlice
}

func DeepCopyMap(m map[string]interface{}) map[string]interface{} {
	newMap := make(map[string]interface{})
	for k, v := range m {
		switch val := v.(type) {
		case map[string]interface{}:
			newMap[k] = DeepCopyMap(val)
		case []interface{}:
			newMap[k] = deepCopySlice(val)
		default:
			newMap[k] = v
		}
	}
	return newMap
}

// type post struct {
// 	Key          string
// 	Value        string
// 	index        int //
// 	Content_type string
// 	// url   string
// }

// type Param []post

// Param describes an individual posted parameter.
type Param struct {
	// Name of the posted parameter.
	Name string `json:"name"`
	// Value of the posted parameter.
	Value string `json:"value,omitempty"`

	// Filename of a posted file.
	Filename string `json:"fileName,omitempty"`
	// ContentType is the content type of a posted file.
	ContentType string `json:"contentType,omitempty"`

	FileHeader   textproto.MIMEHeader
	FileSize     int64
	FileContent  []byte
	IsFile       bool
	IsJson       bool
	Boundary     string
	FilenotFound bool
	IsBase64     bool
	Index        int //
}

type JsonRecord struct {
	Index int //
	// Name of the posted parameter.
	Name string `json:"name"`
	// Value of the posted parameter.
	Value string `json:"value,omitempty"`
}

// QueryString is a query string parameter on a request.
type QueryString struct {
	// Name is the query parameter name.
	Name string `json:"name"`
	// Value is the query parameter value.
	Value string `json:"value"`
}

// Header is an HTTP request or response header.
type Header struct {
	// Name is the header name.
	Name string `json:"name"`
	// Value is the header value.
	Value string `json:"value"`
}

// PostData describes posted data on a request.
type Variations struct {
	// MimeType is the MIME type of the posted data.
	MimeType string `json:"mimeType"`
	// Params is a list of posted parameters (in case of URL encoded parameters).
	Params []Param `json:"params"`

	JsonParams JSONKeyValueIterator
	//Jsonvale
	JsonValue map[string]interface{}
	// Text contains the posted data. Although its type is string, it may contain
	// binary data.
	Text string `json:"text"`
}

type Cookie struct {
	// Name is the cookie name.
	Name string `json:"name"`
	// Value is the cookie value.
	Value string `json:"value"`
	// Path is the path pertaining to the cookie.
	Path string `json:"path,omitempty"`
	// Domain is the host of the cookie.
	Domain string `json:"domain,omitempty"`
	// Expires contains cookie expiration time.
	Expires time.Time `json:"-"`
	// Expires8601 contains cookie expiration time in ISO 8601 format.
	Expires8601 string `json:"expires,omitempty"`
	// HTTPOnly is set to true if the cookie is HTTP only, false otherwise.
	HTTPOnly bool `json:"httpOnly,omitempty"`
	// Secure is set to true if the cookie was transmitted over SSL, false
	// otherwise.
	Secure bool `json:"secure,omitempty"`
}

// Request holds data about an individual HTTP request.
type Request struct {
	// Method is the request method (GET, POST, ...).
	Method string `json:"method"`
	// URL is the absolute URL of the request (fragments are not included).
	URL string `json:"url"`
	// HTTPVersion is the Request HTTP version (HTTP/1.1).
	HTTPVersion string `json:"httpVersion"`
	// Cookies is a list of cookies.
	Cookies []Cookie `json:"cookies"`
	// Headers is a list of headers.
	Headers []Header `json:"headers"`
	// QueryString is a list of query parameters.
	QueryString []QueryString `json:"queryString"`
	// PostData is the posted data information.
	PostData *Variations `json:"postData,omitempty"`
	// HeaderSize is the Total number of bytes from the start of the HTTP request
	// message until (and including) the double CLRF before the body. Set to -1
	// if the info is not available.
	HeadersSize int64 `json:"headersSize"`
	// BodySize is the size of the request body (POST data payload) in bytes. Set
	// to -1 if the info is not available.
	BodySize int64 `json:"bodySize"`
}

// Content describes details about response content.
type Content struct {
	// Size is the length of the returned content in bytes. Should be equal to
	// response.bodySize if there is no compression and bigger when the content
	// has been compressed.
	Size int64 `json:"size"`
	// MimeType is the MIME type of the response text (value of the Content-Type
	// response header).
	MimeType string `json:"mimeType"`
	// Text contains the response body sent from the server or loaded from the
	// browser cache. This field is populated with fully decoded version of the
	// respose body.
	Text []byte `json:"text,omitempty"`
	// The desired encoding to use for the text field when encoding to JSON.
	Encoding string `json:"encoding,omitempty"`
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {
	return quoteEscaper.Replace(s)
}

// Response holds data about an individual HTTP response.
type Response struct {
	// Status is the response status code.
	Status int `json:"status"`
	// StatusText is the response status description.
	StatusText string `json:"statusText"`
	// HTTPVersion is the Response HTTP version (HTTP/1.1).
	HTTPVersion string `json:"httpVersion"`
	// Cookies is a list of cookies.
	Cookies string `json:"cookies"`
	// Headers is a list of headers.
	Headers []Header `json:"headers"`
	// Content contains the details of the response body.
	Content *Content `json:"content"`
	// RedirectURL is the target URL from the Location response header.
	RedirectURL string `json:"redirectURL"`
	// HeadersSize is the total number of bytes from the start of the HTTP
	// request message until (and including) the double CLRF before the body.
	// Set to -1 if the info is not available.
	HeadersSize int64 `json:"headersSize"`
	// BodySize is the size of the request body (POST data payload) in bytes. Set
	// to -1 if the info is not available.
	BodySize int64 `json:"bodySize"`
}

// Len()
func (p Variations) Len() int {
	return len(p.Params)
}

// Less(): 顺序有低到高排序
func (p Variations) Less(i, j int) bool {
	return p.Params[i].Index < p.Params[j].Index
}

// Swap()
func (p Variations) Swap(i, j int) {
	p.Params[i], p.Params[j] = p.Params[j], p.Params[i]
}

// func GetUnderlyingAsValue(data interface{}) reflect.Value {
// 	return reflect.ValueOf(data)
// }

func (p *Variations) Release() string {
	var buf bytes.Buffer
	//mjson := make(map[string]interface{})
	if funk.Contains(p.MimeType, "application/json") {
		//count := 0
		// Paramsjson := p.JsonValue

		// p.JsonParams.Parser(Paramsjson)

		// p.JsonParams.SetValues(Paramsjson, 0)

		// buf.WriteString(p.JsonParams.String())
	} else if funk.Contains(p.MimeType, "multipart/form-data") {
		// bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(&buf)
		// bodyWriter.CreateFormFile(p.Params[0], p.Params[0].Filename)

		if p.Params[0].Boundary != "" {
			bodyWriter.SetBoundary(p.Params[0].Boundary)
		}

		for _, Param := range p.Params {
			if Param.IsFile {
				h := make(textproto.MIMEHeader)
				h.Set("Content-Disposition",
					fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
						escapeQuotes(Param.Name), escapeQuotes(Param.Filename)))
				h.Set("Content-Type", Param.ContentType)
				part, err := bodyWriter.CreatePart(h)
				if err != nil {
					logger.Error(err.Error())
				}
				// 写入文件数据到multipart，和读取本地文件方法的唯一区别
				_, err = part.Write([]byte(Param.Value))
			} else {
				_ = bodyWriter.WriteField(Param.Name, Param.Value)
			}
		}
		bodyWriter.Close()
		// fmt.Println(buf.String())
	} else {
		for i, Param := range p.Params {
			buf.WriteString(Param.Name + "=" + Param.Value)
			if i != p.Len()-1 {
				buf.WriteString("&")
			}
		}
	}

	return buf.String()
}

func (p Variations) Set(key string, value string) error {
	for i, Param := range p.Params {
		if Param.Name == key {
			p.Params[i].Value = value
			return nil
		}
	}
	return fmt.Errorf("not found: %s", key)
}

const MAX_SEND_COUNT = 20

func (p *Variations) SetPayloads(uri string, payload string, method string) []string {
	var result []string
	if strings.ToUpper(method) == "POST" {

		for idx, kv := range p.Params {
			//小于MAX_SEND_COUNT一个链接参数不能超过MAX_SEND_COUNT
			if idx <= MAX_SEND_COUNT {
				p.Set(kv.Name, payload)
				result = append(result, p.Release())
				p.Set(kv.Name, kv.Value)
			} else {
				logger.Warning("当前url超出参数最大发送参数,自动pass不填写参数")
			}
		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			logger.Debug(err.Error())
			return nil
		}
		v := u.Query()
		for idx, kv := range p.Params {
			if idx <= MAX_SEND_COUNT {
				v.Set(kv.Name, payload)
				result = append(result, strings.Split(string(uri), "?")[0]+"?"+v.Encode())
				v.Set(kv.Name, kv.Value)
			} else {
				logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
			}
		}
	}
	return result
}

// SetPayloadByindex_noreset 这版本并不会重置Variations Params 成员的结构
func (p *Variations) SetPayloadByindex_noReset(index int, uri string, payload string, method string) string {
	var result string
	if strings.ToUpper(method) == "POST" {
		if funk.Contains(p.MimeType, "application/json") {
			Paramsjson := p.JsonValue

			p.JsonParams.Parser(Paramsjson)

			rawdata := p.JsonParams.SetValues(Paramsjson, index, payload)

			return string(rawdata)
		} else {
			for idx, kv := range p.Params {
				//小于5一个链接参数不能超过5
				if idx <= MAX_SEND_COUNT {
					if idx == index {
						p.Set(kv.Name, payload)
						str := p.Release()
						// p.Set(kv.Name, kv.Value)
						return str
					}
				} else {
					logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
				}

			}
		}
	} else if strings.ToUpper(method) == "GET" {
		for idx, kv := range p.Params {
			if idx <= MAX_SEND_COUNT {
				if idx == index {
					p.Set(kv.Name, payload)
					stv := p.Release()
					str := strings.Split(string(uri), "?")[0] + "?" + stv
					// v.Set(kv.Name, kv.Value)
					return str
				}
			} else {
				logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
			}
		}
	}
	return result
}

func (p *Variations) SetPayloadByindex(index int, uri string, payload string, method string) string {
	var result string
	if strings.ToUpper(method) == "POST" {
		if funk.Contains(p.MimeType, "application/json") {
			Paramsjson := p.JsonValue
			p.JsonParams.Parser(Paramsjson)
			rawdata := p.JsonParams.SetValues(Paramsjson, index, payload)
			return string(rawdata)
		} else {
			for idx, kv := range p.Params {
				//小于5一个链接参数不能超过5
				if idx <= MAX_SEND_COUNT {
					if idx == index {
						p.Set(kv.Name, payload)
						str := p.Release()
						p.Set(kv.Name, kv.Value)
						return str
					}
				} else {
					logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
				}
			}
		}
	} else if strings.ToUpper(method) == "GET" {
		u, err := url.Parse(uri)
		if err != nil {
			logger.Error(err.Error())
			return ""
		}
		v := u.Query()
		for idx, kv := range p.Params {
			if idx <= MAX_SEND_COUNT {
				if idx == index {
					p.Set(kv.Name, payload)
					stv := p.Release()
					str := strings.Split(string(uri), "?")[0] + "?" + stv
					v.Set(kv.Name, kv.Value)
					return str
				}
			} else {
				logger.Warning("当前url超出参数最小发送数,自动pass不填写参数")
			}
		}
	}
	return result
}

type contentType string

const (
	application_json       contentType = "application/json"
	application_urlencoded contentType = "application/x-www-form-urlencoded"
	multipart_data         contentType = "multipart/form-data"
	ctunknown              contentType = "unknown"
)

func getContentType(data string) contentType {
	if funk.Contains(data, application_json) {
		return application_json
	}
	if funk.Contains(data, application_urlencoded) {
		return application_urlencoded
	}
	if funk.Contains(data, multipart_data) {
		return multipart_data
	}
	return ctunknown
}

func ParseUri(uri string, body []byte, method string, content_type string, headers map[string]string) (*Variations, error) {
	var (
		err error
		//index    int
		Postinfo Variations
	)

	json_map := make(map[string]interface{})
	if strings.ToUpper(method) == "POST" {
		if len(body) > 0 {
			switch getContentType(strings.ToLower(content_type)) {
			case application_json:
				//fmt.Println(string(body))
				err := json.Unmarshal(body, &json_map)
				if err != nil {
					return nil, err
				}
				Postinfo.JsonValue = json_map
				Postinfo.MimeType = content_type
				len := Postinfo.JsonParams.Parser(json_map)
				for i := 0; i < len; i++ {
					Post := Param{Name: "", Value: "", Index: i, ContentType: content_type}
					Postinfo.Params = append(Postinfo.Params, Post)
				}

			case application_urlencoded:
				strs := strings.Split(string(body), "&")
				for i, kv := range strs {
					kvs := strings.Split(string(kv), "=")
					if len(kvs) == 2 {
						key := kvs[0]
						value := kvs[1]
						Post := Param{Name: key, Value: value, Index: i, ContentType: content_type}
						Postinfo.Params = append(Postinfo.Params, Post)
					} else {
						logger.Error("exec function strings.Split fail")
						return nil, err
					}
				}
				Postinfo.MimeType = content_type
			case multipart_data:

				var iindex = 0
				var boundary string
				//base64.StdEncoding.DecodeString (
				// array := string()
				iobody := bytes.NewReader(body)
				req, err := http.NewRequest(method, uri, iobody)

				for k, v := range headers {
					req.Header[k] = []string{v}
				}

				if err != nil {
					logger.Error(err.Error())
					return nil, err
				}

				reader, err := req.MultipartReader()
				if err != nil {
					logger.Error(err.Error())
				}

				_, params, err := mime.ParseMediaType(content_type)
				if err != nil {
					log.Fatal("1 :", err)
				}
				if value, ok := params["boundary"]; ok {
					boundary = value
				}

				for {
					var isfile = false
					if reader == nil {
						break
					}
					p, err := reader.NextPart()
					if err == io.EOF {
						break
					}
					if err != nil {
						return nil, err
					}
					defer p.Close()

					body, err := ioutil.ReadAll(p)
					if err != nil {
						return nil, err
					}
					iindex++
					if p.FileName() != "" {
						isfile = true
					}

					Postinfo.MimeType = content_type
					Postinfo.Params = append(Postinfo.Params, Param{
						Name:        p.FormName(),
						Boundary:    boundary,
						Filename:    p.FileName(),
						ContentType: p.Header.Get("Content-Type"),
						// FileContent: body,
						Value:  string(body),
						IsFile: isfile,
						Index:  iindex,
					})
				}
			}

			sort.Sort(Postinfo)
			return &Postinfo, nil
		} else {
			return nil, fmt.Errorf("post data is empty")
		}

	} else if strings.ToUpper(method) == "GET" {
		if !funk.Contains(string(uri), "?") {
			return nil, fmt.Errorf("GET data is empty")
		}
		urlparams := strings.Split(string(uri), "?")[1]
		strs := strings.Split(string(urlparams), "&")
		//params := Param{}
		for i, kv := range strs {
			kvs := strings.Split(string(kv), "=")
			if len(kvs) == 2 {
				key := kvs[0]
				value := kvs[1]
				Post := Param{Name: key, Value: value, Index: i, ContentType: content_type}
				Postinfo.Params = append(Postinfo.Params, Post)
			} else {
				err = fmt.Errorf("exec function strings.Split fail")
				logger.Error("%s", err.Error())
				return nil, err
			}
		}
		sort.Sort(Postinfo)
		return &Postinfo, nil
	} else {
		err = fmt.Errorf("method not supported")
	}
	return nil, err
}

func Decimal(value float64) float64 {
	value, _ = strconv.ParseFloat(fmt.Sprintf("%.2f", value), 64)
	return value
}

func FmtDuration(d time.Duration) string {

	hour, _ := decimal.NewFromFloat(d.Hours()).Round(1).Float64()
	hour_int := int(hour)
	minutes, _ := decimal.NewFromFloat(d.Minutes()).Round(1).Float64()
	minutes_int := int(minutes)
	second, _ := decimal.NewFromFloat(d.Seconds()).Round(1).Float64()
	second_int := int(second)
	return fmt.Sprintf("%02d小时%02d分钟%02d秒", hour_int, minutes_int, second_int)
}

type Status int

func RepairUrl(url string) string {
	//strings.Hasprefix(url, "https")
	lowurl := strings.ToLower(url)
	if strings.HasPrefix(lowurl, "http") || strings.HasPrefix(lowurl, "https") {
		return url
	} else {
		url = "http://" + url
	}
	return url
}

// 判断所给路径文件/文件夹是否存在
func Exists(path string) bool {
	_, err := os.Stat(path) //os.Stat获取文件信息
	if err != nil {
		if os.IsExist(err) {
			return true
		}
		return false
	}
	return true
}

func ParseXMl(xmlData []byte) (*etree.Document, error) {
	var err error
	var rootElement *etree.Element
	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(xmlData); err != nil {
		return nil, err
	}
	// bufs.Reset()
	doc.Indent(2)
	doc.WriteTo(os.Stdout)

	rootElement = doc.Copy().Root()

	for _, t := range rootElement.Child {
		if c, ok := t.(*etree.Element); ok {
			tag := c.Tag
			c.SetText(c.Text() + `;&content`)
			logger.Info("tag := %s", tag)
		}
	}

	doc.SetRoot(rootElement)
	// Child := etree.NewDocument()
	// Target := Child.CreateElement("a")
	// Target.SetText("&content")
	// rootElement.AddChild(Target)
	// rootElement.Indent(2)
	// rootElement.WriteTo(os.Stdout)
	doc.Indent(2)
	doc.WriteTo(os.Stdout)

	return doc, nil
}

func RandStr(length int) string {
	strRange := "0123456789"
	ret := `'` + funk.RandomString(length, []rune(strRange)) + `'`
	return ret
}

func InterfaceToString(data map[string]string) map[string]interface{} {
	Variations := make(map[string]interface{})
	for k, v := range data {
		Variations[k] = v
	}
	return Variations
}

func JsonWrite(filepath string, data []byte) {
	fp, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		logger.Fatal("%v", err)
	}
	defer fp.Close()
	_, err = fp.Write(data)
	if err != nil {
		logger.Fatal("%v", err)
	}
}

func GetScanDeepByUrl(uri string) int {
	u, err := url.Parse(uri)
	if err != nil {
		//logger.Error(err.Error())
		return 65535
	}
	deeps := strings.Split(u.Path, "/")
	//logger.Debug("当前扫描路径:%s 当前深度 %d", u.Path, len(deeps))
	return len(deeps) - 1
}

func Isdomainonline(URLPath string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	u, err := url.Parse(URLPath)
	if err != nil {
		return false
	}
	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(u.Hostname()),
		nmap.WithContext(ctx),
	)

	if err != nil {
		log.Printf("unable to create nmap scanner: %v", err)
		return false
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Printf("unable to run nmap scan: %v", err)
		return false
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}
	var buf bytes.Buffer

	rawXml := result.ToReader()
	buf.ReadFrom(rawXml)
	// fmt.Printf(buf.String())
	if funk.Contains(buf.String(), `service name="http`) || funk.Contains(buf.String(), `service name="https`) {
		return true
	}

	return false
}

type VclockLock struct {
	Starttime string `json:"starttime"`
	Endtime   string `json:"endtime"`
	Hash      string `json:"hash"`
}

func ConfirmVlockFile(lockPath string) (bool, error) {
	filePtr, err := os.Open(lockPath)
	if err != nil {
		fmt.Println("文件打开失败 [Err:%s]", err.Error())
		return false, err
	}
	defer filePtr.Close()
	var vcl VclockLock
	// 创建json解码器
	decoder := json.NewDecoder(filePtr)
	err = decoder.Decode(&vcl)
	if err != nil {
		fmt.Println("解码失败", err.Error())
	}
	cpuinfo, _ := cpu.Info()
	PhysicalID := cpuinfo[0].PhysicalID
	startclock := vcl.Starttime
	endclock := vcl.Endtime
	sha1str := PhysicalID + startclock + endclock
	Sha1Inst := sha1.New()
	Sha1Inst.Write([]byte(sha1str))
	truehash := Sha1Inst.Sum([]byte(""))
	//fmt.Printf("%x\n\n", truehash)
	validhashstr, err := base64.StdEncoding.DecodeString(vcl.Hash)
	if err != nil {
		//fmt.Println(err)
		return false, err
	}
	if bytes.Equal(truehash, validhashstr) {
		return true, nil
	}
	return false, fmt.Errorf("valid error")
}

func GenerateVlockFile(Auth_time uint) error {
	var vcl VclockLock
	info, _ := cpu.Info()
	PhysicalID := info[0].PhysicalID

	//fmt.Println(PhysicalID)
	starttime := time.Now().Local()
	startclock := starttime.Format("2006-01-02")
	Endtime := starttime.Add(time.Hour * 24 * time.Duration(Auth_time))
	endclock := Endtime.Format("2006-01-02")
	// time.Now().Local().Add(time.)
	//fmt.Println(startclock)
	//fmt.Println(endclock)
	sha1str := PhysicalID + startclock + endclock
	Sha1Inst := sha1.New()
	Sha1Inst.Write([]byte(sha1str))
	Result := Sha1Inst.Sum([]byte(""))
	fmt.Printf("%x\n\n", Result)
	vcl.Starttime = startclock
	vcl.Endtime = endclock
	vcl.Hash = base64.StdEncoding.EncodeToString(Result)
	data, err := json.Marshal(vcl)
	if err != nil {
		fmt.Println(err)
		return err
	}
	err = ioutil.WriteFile("v-clock.lock", data, 0777)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return err
}

type Globalvariable struct {
	Variable string
	Isdetect bool
	Ischeck  bool
}

var Globalvariables []Globalvariable

func SetGlobalValue(Variable string, ischeck bool, isdetect bool) error {
	var err error
	g := Globalvariable{
		Variable: Variable,
		Isdetect: isdetect,
		Ischeck:  ischeck,
	}
	Globalvariables = append(Globalvariables, g)
	return err
}

func GetGlobalValue(Variable string) {

}

func getFormData(form *multipart.Form) {

	//获取 multi-part/form body中的form value

	for k, v := range form.Value {
		fmt.Println("value,k,v = ", k, ",", v)
	}

	fmt.Println()

	//获取 multi-part/form中的文件数据

	for _, v := range form.File {

		for i := 0; i < len(v); i++ {

			// fmt.Println("file part ", i, "-->")

			// fmt.Println("fileName   :", v[i].Filename)

			// fmt.Println("part-header:", v[i].Header)

			f, _ := v[i].Open()

			buf, _ := ioutil.ReadAll(f)

			fmt.Println("file-content", string(buf))

			// fmt.Println()

		}

	}

}

func GetMultiPart(r *http.Request) {

	/**

	底层通过调用multipartReader.ReadForm来解析

	如果文件大小超过maxMemory,则使用临时文件来存储multipart/form中文件数据

	*/
	r.ParseMultipartForm(128)

	fmt.Println("r.Form:         ", r.Form)

	fmt.Println("r.PostForm:     ", r.PostForm)

	fmt.Println("r.MultiPartForm:", r.MultipartForm)

	getFormData(r.MultipartForm)

}

func GetFileExt(filename string) (string, error) {
	// u, err := url.Parse(rawUrl)
	// if err != nil {
	// 	return "", err
	// }
	pos := strings.LastIndex(filename, ".")
	if pos == -1 {
		return "", errors.New("couldn't find a period to indicate a file extension")
	}
	return filename[pos+1:], nil
}

func GetFileNameFromUrl(rawUrl string) (string, error) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}
	filename := path.Base(u.Path)
	return filename, nil
}

// Str2Byte return bytes of s
func Str2Byte(s string) []byte {
	x := (*[2]uintptr)(unsafe.Pointer(&s))
	h := [3]uintptr{x[0], x[1], x[1]}
	return *(*[]byte)(unsafe.Pointer(&h))
}

// Byte2Str return string of b
func Byte2Str(b []byte) string {
	if !utf8.Valid(b) {
		return ""
	}
	return string(b[:])
}

func Initgob() {
	gob.Register(map[string]interface{}{})
}

// Map performs a deep copy of the given map m.
func CopyMapif(m map[string]interface{}) (map[string]interface{}, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	dec := gob.NewDecoder(&buf)
	err := enc.Encode(m)
	if err != nil {
		return nil, err
	}
	var copy map[string]interface{}
	err = dec.Decode(&copy)
	if err != nil {
		return nil, err
	}
	return copy, nil
}

func Call(m map[string]interface{}, name string, params ...interface{}) (result []reflect.Value, err error) {
	f := reflect.ValueOf(m[name])
	if len(params) != f.Type().NumIn() {
		err = errors.New("The number of params is not adapted.")
		return
	}
	in := make([]reflect.Value, len(params))
	for k, param := range params {
		in[k] = reflect.ValueOf(param)
	}
	result = f.Call(in)
	return
}

var (
	// 定义一些常见的停用词，可以根据需要添加或删除
	stopwords = map[string]bool{
		"a": true, "an": true, "and": true, "are": true, "as": true, "at": true,
		"be": true, "by": true,
		"for": true, "from": true,
		"has": true, "he": true, "her": true, "his": true,
		"in": true, "is": true, "it": true,
		"of": true, "on": true, "or": true,
		"that": true, "the": true, "this": true, "to": true,
		"was": true, "were": true, "with": true,
	}

	// 定义一个正则表达式，用于去除文本中的非字母字符
	regex = regexp.MustCompile(`[^a-zA-Z]+`)
)

// // GenerateSynHash 将输入的文本转换成一个哈希值
// func GenerateSynHash(text string) string {
// 	// 将文本转换成小写，并去除非字母字符
// 	text = strings.ToLower(text)
// 	text = regex.ReplaceAllString(text, " ")

// 	// 分词，去除停用词，词干化
// 	words := strings.Split(text, " ")
// 	var filtered []string
// 	for _, word := range words {
// 		if _, ok := stopwords[word]; !ok {
// 			filtered = append(filtered, word)
// 		}
// 	}
// 	filtered = stemWords(filtered)

// 	// 计算哈希值并返回
// 	hash := fnv.New32a()
// 	for _, word := range filtered {
// 		hash.Write([]byte(word))
// 	}
// 	return string(hash.Sum32())
// }

// stemWords 对输入的单词列表进行词干化处理
// func stemWords(words []string) []string {
// 	var stemmed []string
// 	for _, word := range words {
// 		// 这里可以使用自己喜欢的词干化算法
// 		// 这里使用的是Porter Stemming算法，需要安装porterstemmer包
// 		stemmed = append(stemmed, porterstemmer.StemString(word))
// 	}
// 	return stemmed
// }

// 从网页中解析出js文件的信息，并存储到FileType结构体中
func ParseJSFile(url string) (*SiteFile, error) {
	var jsContentResp *http.Response
	var jsUrl string
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if funk.Contains(url, ".js") {
		jsContentResp = resp
		jsUrl = url
	} else {

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return nil, err
		}

		// 从网页中获取js文件的url和内容
		jsUrl, ok := doc.Find("script[src]").Attr("src")
		if !ok {
			return nil, errors.New("JS file not found")
		}
		jsContentResp, err = http.Get(jsUrl)
		if err != nil {
			return nil, err
		}
	}
	defer jsContentResp.Body.Close()
	jsContent, err := ioutil.ReadAll(jsContentResp.Body)
	if err != nil {
		return nil, err
	}

	// 计算文件的hash值和synhash值
	hash := md5.Sum(jsContent)
	hashStr := hex.EncodeToString(hash[:])
	//synhashStr := synset.GenerateSynHash(string(jsContent))

	// 创建FileType结构体实例并返回
	fileType := &SiteFile{
		Filename:    filepath.Base(jsUrl),
		Url:         jsUrl,
		Hash:        hashStr,
		Filecontent: jsContent,
		// Synhash:     synhashStr,
	}

	return fileType, nil
}

func KillChrome() error {
	cmd := exec.Command("killall", "chrome")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

func KillcustomJS() error {
	cmd := exec.Command("pm2", "restart", "glint_meson")
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}
