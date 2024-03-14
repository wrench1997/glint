package upfile

import (
	"encoding/base64"
	"errors"
	"glint/logger"
	"glint/nenet"
	"glint/pkg/layers"
	"glint/plugin"
	"glint/util"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/thoas/go-funk"
)

type classUPFile struct {
	scheme                 layers.Scheme
	TargetUrl              string
	inputIndex             int
	reflectionPoint        int
	disableSensorBased     bool
	currentVariation       int
	foundVulnOnVariation   bool
	variations             *util.Variations
	lastJob                layers.LastJob
	TrueFeatures           *layers.MFeatures
	lastJobProof           interface{}
	scanningWAVSEP         bool
	scanningOwaspBenchmark bool
	isUnix                 bool
	isWindows              bool
	isJava                 bool
	isUnknown              bool
}

func (uf *classUPFile) TestUploadedFileOnUrl(url string, search string, expectedContent string) {

}

func (uf *classUPFile) TestFileUpload(index int, filename string, contenttype string, data []byte, lookFor string, appendPHPFilename string, expectedContentType string) bool {
	var (
		lookfor_filepaths []string
	)
	exp := make(map[string]string)
	exp["filename"] = filename
	exp["contenttype"] = contenttype
	///先请求一次
	uf.lastJob.RequestByIndex(index, uf.TargetUrl, data, exp)

	///先检测OOB

	///在检测文件回复里面是否有漏洞
	regexEmails := "([\\.\\w\\/]+\\/)" + strings.Replace(filename, ".", "\\.", -1)
	re, _ := regexp.Compile(regexEmails)
	lookfor_filepaths = re.FindAllString(uf.lastJob.Features.Response.String(), -1)
	//fmt.Println(lookfor_filepaths)
	if len(lookfor_filepaths) != 0 {

	}
	///最后在暴力枚举

	///根据不同的上传文件上传对应的payload

	///根据flag寻找是否存在漏洞
	for _, filepath := range lookfor_filepaths {
		// newurl :=  +
		u, err := url.JoinPath(uf.TargetUrl, filepath)
		if err != nil {
			return false
		}
		_, resp, err := uf.lastJob.Layer.Sess.Get(u, nil)
		// logger.Info(resp.String())
		if err != nil {
			logger.Error(err.Error())
		}
		if funk.Contains(resp.String(), lookFor) {
			return true
		}
	}

	return false
}

func (uf *classUPFile) StartTesting() bool {
	var (
		foundfile       bool
		foundfile_index int
		// vfilename        string
		// lookfor_filepath string
		// contenttype      string
	)
	for idx, v := range uf.variations.Params {
		if v.IsFile {
			foundfile = true
			foundfile_index = idx
			// vfilename = v.Filename
			// contenttype = v.ContentType
		}
	}
	if !foundfile {
		return false
	}
	//1
	data, err := base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//2
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php.php.rar", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//3
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php.php.rar", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//4
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEARwBHAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAEAAQAwEiAAIRAQMRAf/EABYAAQEBAAAAAAAAAAAAAAAAAAQAAf/EACIQAAEEAgEEAwAAAAAAAAAAAAIBAwQFBhEHABITMSFBYf/EABUBAQEAAAAAAAAAAAAAAAAAAAQH/8QAIhEBAAECBAcAAAAAAAAAAAAAERIAEwMEFUEiJTJCYqGx/9oADAMBAAIRAxEAPwB1CxxdV8a01pk9Lb3OQ2kmajcaHZymyMQlutivaDqCKIIiKaT5169r1t9H4utONLm1xelt6bIauTCRyNMs5ThNi5LabJe03VEkUSIV2nxv16XovHzvH7IVFhkmT2tfMhx7CG/EYqZZkPklSDbcbeBshRex7e039fvVyA7x+63cWGN5Ra2EybHr4jEN+plgReKVHNxxx420FV7Gd7XX3+dI5vqvfC55BL5VPhlmLiXVeIZ9IAb+9q//2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php\x00.jpg", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//5
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".phtml", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//6
	data, err = base64.StdEncoding.DecodeString("PD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php", "text/plain", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//7
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php.jpg", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//8
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php.123", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//9
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php::$DATA", "image/png", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//10
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php::$DATA", "image/png", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//11
	data, err = base64.StdEncoding.DecodeString("I0FjdW5ldGl4IC5odGFjY2VzcyBGaWxlIFVwbG9hZCB0ZXN0DQpBZGRUeXBlIGFwcGxpY2F0aW9uL3gtaHR0cGQtcGhwIC5qcGcgLnBuZyAuZ2lmIC5odG0gLmh0bWwg")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".htaccess", "image/jpeg", data, "#testing .htaccess File Upload test", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//12
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEARwBHAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAEAAQAwEiAAIRAQMRAf/EABYAAQEBAAAAAAAAAAAAAAAAAAQAAf/EACIQAAEEAgEEAwAAAAAAAAAAAAIBAwQFBhEHABITMSFBYf/EABUBAQEAAAAAAAAAAAAAAAAAAAQH/8QAIhEBAAECBAcAAAAAAAAAAAAAERIAEwMEFUEiJTJCYqGx/9oADAMBAAIRAxEAPwB1CxxdV8a01pk9Lb3OQ2kmajcaHZymyMQlutivaDqCKIIiKaT5169r1t9H4utONLm1xelt6bIauTCRyNMs5ThNi5LabJe03VEkUSIV2nxv16XovHzvH7IVFhkmT2tfMhx7CG/EYqZZkPklSDbcbeBshRex7e039fvVyA7x+63cWGN5Ra2EybHr4jEN+plgReKVHNxxx420FV7Gd7XX3+dI5vqvfC55BL5VPhlmLiXVeIZ9IAb+9q//2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".php.ajpg", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//13
	data, err = base64.StdEncoding.DecodeString("PCUgUmVzcG9uc2UuV3JpdGUoIjRkMDIwNzBlZmZkZDdlMzE5IiArICJjYTU2MWJjNjY2MTdhOGEiKSAlPg==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".asp", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//14
	data, err = base64.StdEncoding.DecodeString("PHNjcmlwdCBydW5hdD0ic2VydmVyIiBsYW5ndWFnZT0iQyMiPg0Kdm9pZCBQYWdlX0xvYWQob2JqZWN0IHNlbmRlciwgRXZlbnRBcmdzIGUpew0KICBSZXNwb25zZS5Xcml0ZSgiNGQwMjA3MGVmZmRkN2UzMTkiICsgImNhNTYxYmM2NjYxN2E4YSIpOw0KfQ0KPC9zY3JpcHQ+DQo=")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".aspx", "image/png", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//15
	data, err = base64.StdEncoding.DecodeString("PCUgUmVzcG9uc2UuV3JpdGUoIjRkMDIwNzBlZmZkZDdlMzE5IiArICJjYTU2MWJjNjY2MTdhOGEiKSAlPg==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".asp", "text/plain", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//16
	data, err = base64.StdEncoding.DecodeString("PCUgUmVzcG9uc2UuV3JpdGUoIjRkMDIwNzBlZmZkZDdlMzE5IiArICJjYTU2MWJjNjY2MTdhOGEiKSAlPg==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".asp;.jpg", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}

	//17
	data, err = base64.StdEncoding.DecodeString("PCUgUmVzcG9uc2UuV3JpdGUoIjRkMDIwNzBlZmZkZDdlMzE5IiArICJjYTU2MWJjNjY2MTdhOGEiKSAlPg==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".asp;.jpg", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}

	//18
	data, err = base64.StdEncoding.DecodeString("PCUgb3V0LnByaW50KCI0ZDAyMDcwZWZmZGQ3ZTMxOSIgKyAiY2E1NjFiYzY2NjE3YThhIik7ICU+")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".jsp", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}
	//19
	data, err = base64.StdEncoding.DecodeString("/9j/4AAQSkZJRgABAQEASABIAAD//gAyPD9waHAgZWNobyhtZDUoJ2FjdW5ldGl4LWZpbGUtdXBsb2FkLXRlc3QnKSk7ID8+/9sAQwAFAwQEBAMFBAQEBQUFBgcMCAcHBwcPCwsJDBEPEhIRDxERExYcFxMUGhURERghGBodHR8fHxMXIiQiHiQcHh8e/9sAQwEFBQUHBgcOCAgOHhQRFB4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4e/8AAEQgAAQABAwEiAAIRAQMRAf/EABUAAQEAAAAAAAAAAAAAAAAAAAAI/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/EABQBAQAAAAAAAAAAAAAAAAAAAAD/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwCywAf/2Q==")
	if err != nil {
		return false
	}
	if uf.TestFileUpload(foundfile_index, "ZZZTest"+util.RandLetters(8)+".jpg", "image/jpeg", data, "4d02070effdd7e319ca561bc66617a8a", "", "") {
		uf.TrueFeatures = uf.lastJob.Features
		return true
	}

	return false
}

func UpfileVaild(args *plugin.GroupData) (*util.ScanResult, bool, error) {
	var variations *util.Variations
	var CUPFile classUPFile
	//var hostid int64
	gd := args
	// var blastIters interface{}
	util.Setup()
	var Param layers.PluginParam
	// layers.Init()
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

	CUPFile.lastJob.Init(Param)
	// variations, err = util.ParseUri(url)
	// BlindSQL.variations =

	variations, err := util.ParseUri(Param.Url, []byte(Param.Body), Param.Method, Param.ContentType, Param.Headers)
	if err != nil {
		// logger.Error(err.Error())
		return nil, false, errors.New("not found")
	}
	//赋值
	CUPFile.variations = variations
	CUPFile.lastJob.Layer.Sess = sess
	CUPFile.TargetUrl = Param.Url
	CUPFile.lastJob.Layer.Method = Param.Method
	CUPFile.lastJob.Layer.ContentType = Param.ContentType
	CUPFile.lastJob.Layer.Headers = Param.Headers
	CUPFile.lastJob.Layer.Body = []byte(Param.Body)

	//fmt.Println(variations.Params)

	//先搜索回复里面的文件
	if CUPFile.StartTesting() {
		Result := util.VulnerableTcpOrUdpResult(Param.Url,
			"UpFile Vulnerable",
			[]string{string(CUPFile.TrueFeatures.Request.String())},
			[]string{string(CUPFile.TrueFeatures.Response.String())},
			"high",
			Param.Hostid, string(plugin.UPFile))
		gd.Alert(Result)
		return Result, true, nil
	}

	return nil, false, errors.New("not found")

}
