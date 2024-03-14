package util

import (
	"fmt"
	"glint/logger"
	"net/url"
)

func UriResolve(uri string, __url string) (*url.URL, error) {
	//"../../..//search?q=dotnet"
	u, err := url.Parse(uri)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}
	//"http://example.com/directory/"
	base, err := url.Parse(__url)
	if err != nil {
		logger.Error(err.Error())
		return nil, err
	}

	fmt.Println(base.ResolveReference(u))

	return base.ResolveReference(u), nil
}
