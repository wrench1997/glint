package util

import (
	"glint/logger"
	"time"
)

func SendToSocket(SocketMsg *chan map[string]interface{}, status int, key string, Value interface{}) {
	if SocketMsg == nil {
		logger.Error("socketmsg chan is nil , status = %v", status)
		return
	}
	Element := make(map[string]interface{}, 1)
	Element["status"] = status
	Element[key] = Value
	select {
	case (*SocketMsg) <- Element:
	case <-time.After(time.Second * 5):
	}
}
