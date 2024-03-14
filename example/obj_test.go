package mydemo

import (
	"fmt"
	"net"
	"net/http"
	"runtime"
	"testing"
	"time"
)

func Test_OBJ(t *testing.T) {

	ch := make(chan map[string]string, 1)
	stopch := make(chan struct{})
	fmt.Println("NumGoroutine:", runtime.NumGoroutine())

	//监控
	for i := 0; i < 100; i++ {
		go func() {

			obj := make(map[string]string)
			obj["obj"] = "sasdsa"

			select {
			case ch <- obj:
			case <-stopch:
				_, ok := <-ch
				if !ok {
					fmt.Println("channel is closed")
					return
				} else {
					close(ch)
				}
				return
			}

		}()
	}

	select {
	case obj := <-ch:
		// do something with obj
		fmt.Println(obj)
	case <-time.After(time.Second):
		// time out
	}
	close(stopch)
	time.Sleep(time.Second * 20) // 等待 goroutine 执行，防止过早输出结果

	fmt.Println("NumGoroutine:", runtime.NumGoroutine())

}

func Test_Head_request(t *testing.T) {

	url := "https://192.168.166.44"

	// 1. 定义一个Client对象，并自定义传输，以设置超时处理。
	c := http.Client{
		Transport: &http.Transport{
			Dial: func(network, addr string) (net.Conn, error) {
				timeout := time.Second * 2
				return net.DialTimeout(network, addr, timeout)
			},
		},
	}

	// 2.  发送Head请求。
	resp, err := c.Head(url)
	if err != nil {
		fmt.Printf("head %s failed, err:%v\n", url, err)
	} else {
		fmt.Printf("%s head success, status:%v\n", url, resp.Status)
	}
}
