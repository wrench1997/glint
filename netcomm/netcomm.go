package netcomm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"glint/logger"
	"net"
	"strconv"
	"sync"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

//网络发包集成，这个不能包含logger包函数，他们属于上下关系

var SOCKETCONN []*net.Conn

var ServerType string

var Socketinfo []*WebSoketinfo__

type WebSoketinfo__ struct {
	Conn *websocket.Conn
	Ctx  context.Context
}

var Reponse map[string]interface{}

func Sendmsg(status int, message interface{}, taskid int) error {
	var err error
	var lock sync.Mutex
	lock.Lock()
	defer lock.Unlock()
	if Reponse == nil {
		Reponse = make(map[string]interface{}, 0)
	}

	Reponse["status"] = status
	Reponse["msg"] = message
	Reponse["taskid"] = strconv.Itoa(taskid)
	//wbi := 0

	// logger.Info("%v", reponse)
	if ServerType == "websocket" {
		for idx, info := range Socketinfo {
			if CHECKWEBSOKETTIMES() {
				return fmt.Errorf("没有websocket连接上")
			}
			if _, ok := info.Ctx.Deadline(); ok {
				Socketinfo = append(Socketinfo[:idx], Socketinfo[(idx+1):]...)
				continue
			} else {
				ctx, cancel := context.WithTimeout(info.Ctx, time.Second*3)
				defer cancel()
				err = wsjson.Write(ctx, info.Conn, Reponse)
				if err != nil {
					defer info.Conn.Close(websocket.StatusInternalError, err.Error())
				}
			}
		}
	} else {
		data, err := json.Marshal(Reponse)
		bs := make([]byte, len(data)+4)
		//大端通讯
		binary.BigEndian.PutUint32(bs, uint32(len(data)))
		copy(bs[4:], data)
		// si := 0
		//length = len(SOCKETCONN)
		var toDelete []int
		logger.Info("sendmsg: %v", message)
		for idx, conn := range SOCKETCONN {
			if CHECKSOKETTIMES() {
				return fmt.Errorf("没有socket连接上")
			}
			if len(data) > 0 {
				_, err = (*conn).Write(bs)
				if err != nil {
					// logger.Error(err.Error())
					// 将要删除的元素的索引添加到临时切片中
					toDelete = append(toDelete, idx)
					Reponse = make(map[string]interface{}, 1)
					continue
				}
			}
		}
		// 根据临时切片中的索引删除元素
		for i := len(toDelete) - 1; i >= 0; i-- {
			idx := toDelete[i]
			SOCKETCONN = append(SOCKETCONN[:idx], SOCKETCONN[idx+1:]...)
		}
		bs = bs[:0]
	}

	return err
}

func CHECKSOKETTIMES() bool {
	if !(len(SOCKETCONN) > 0) {
		return true
	} else {
		return false
	}
}

func CHECKWEBSOKETTIMES() bool {
	if !(len(Socketinfo) > 0) {
		return true
	} else {
		return false
	}
}
