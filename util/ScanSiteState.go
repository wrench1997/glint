package util

import "github.com/valyala/fasthttp"

type ScanSiteState struct {
	PageState []PageState
}

func (s *ScanSiteState) GetFile(idx int) PageState {
	return s.PageState[idx]
}

type PageState struct {
	Filename     string
	NotFound     bool
	Ignored      bool
	ScanSiteFile bool
	IsFile       bool
	Count        int
	Url          string
	FileContent  string //base64 encoded
}

type Reply struct {
	Idx         int // index of
	Req         *fasthttp.Request
	Resp        *fasthttp.Response
	Hostid      int64
	Url         string
	ContentType string
}
