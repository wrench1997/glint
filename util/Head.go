package util

import (
	"net"
	"net/http"
	"time"
)

func PageExists(url string) bool {
	// 1. 定义一个Client对象，并自定义传输，以设置超时处理。
	c := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				timeout := time.Second * 3
				return net.DialTimeout(network, addr, timeout)
			},
		},
	}

	// 2.  发送Head请求。
	resp, err := c.Head(url)
	if err != nil {
		return false
	}
	if resp.StatusCode == http.StatusOK {
		return true
	}

	return false
}
