package cel

import (
	"glint/logger"
	"strconv"
)

type HandlerFunc func(ctx controllerContext)

var Handles map[string][]HandlerFunc

func ExecExpressionHandle(ctx controllerContext) {
	var result bool
	var err error

	poc := ctx.GetPoc()
	if poc == nil {
		logger.Error("[rule/handle.go:ExecExpressionHandle error] ", "poc is nil")
		return
	}
	if poc.Groups != nil {
		result, err = ctx.Groups(ctx.IsDebug())
	} else {
		result, err = ctx.Rules(poc.Rules, ctx.IsDebug())
	}
	if err != nil {
		logger.Error("[rule/handle.go:ExecExpressionHandle error] ", err)
		return
	}
	if result {
		ctx.Abort()
	}
	return
}

func ExecScriptHandle(ctx controllerContext) {
	pocName := ctx.GetPocName()
	scanFunc := GetScriptFunc(pocName)
	if scanFunc == nil {
		logger.Error("[rule/handle.go:ExecScriptHandle error] ", "scan func is nil")
		ctx.Abort()
		return
	}
	logger.Info("[rule/handle.go:ExecScriptHandle script start]" + pocName)

	var isHTTPS bool
	// 处理端口
	defaultPort := 80
	originalReq := ctx.GetOriginalReq()
	if originalReq == nil {
		logger.Error("[rule/handle.go:ExecScriptHandle error] ", "original request is nil")
		ctx.Abort()
		return
	}

	if originalReq.URL.Scheme == "https" {
		isHTTPS = true
		defaultPort = 443
	}

	if originalReq.URL.Port() != "" {
		port, err := strconv.ParseUint(originalReq.URL.Port(), 10, 16)
		if err != nil {
			ctx.Abort()
			return
		}
		defaultPort = int(port)
	}

	args := &ScriptScanArgs{
		Host:    originalReq.URL.Hostname(),
		Port:    uint16(defaultPort),
		IsHTTPS: isHTTPS,
	}
	result, err := scanFunc(args)
	if err != nil {
		logger.Error("[rule/handle.go:ExecScriptHandle error] ", err)
		ctx.Abort()
		return
	}
	ctx.SetResult(result)
	ctx.Abort()
}

func Setup() {
	Handles = make(map[string][]HandlerFunc)
	Handles[AffectScript] = []HandlerFunc{ExecScriptHandle}
	Handles[AffectAppendParameter] = []HandlerFunc{ExecExpressionHandle}
	Handles[AffectReplaceParameter] = []HandlerFunc{ExecExpressionHandle}
	// InitTaskChannel()
}

func getHandles(affect string) []HandlerFunc {
	defaultHandlers := []HandlerFunc{ExecExpressionHandle}
	if handles, exists := Handles[affect]; exists {
		return handles
	}
	return defaultHandlers
}
