package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"glint/logger"
	"io"
	"log"
	"net"
)

type ConnCallback func(ctx context.Context, mjson map[string]interface{}) error

type MConn struct {
	CallbackFunc ConnCallback
	Signal       chan string
}

func (m *MConn) Init() error {
	m.Signal = make(chan string, 1)
	return nil
}

// 此框架我准备设计成一对多的形式模块处理业务，方便自己以后二次开发。
func (m *MConn) handle(ctx context.Context, data []byte) error {
	mjson := make(map[string]interface{})
	err := json.Unmarshal(data, &mjson)
	if err != nil {
		log.Println(err.Error())
		return err
	}
	//logger.Info("json: %v", mjson)
	err = m.CallbackFunc(ctx, mjson)
	return err
}

func (m *MConn) Listen(con net.Conn) {
	defer con.Close()
	reader := bufio.NewReader(con)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for {
		peek, err := reader.Peek(4)
		if err != nil {
			if err != io.EOF {
				logger.Error("reader error %s", err.Error())
				break
			} else {
				break
			}
		}
		var length uint32
		buffer := bytes.NewBuffer(peek)
		err = binary.Read(buffer, binary.BigEndian, &length)
		if err != nil {
			log.Println(err.Error())
		}

		if uint32(reader.Buffered()) < length+4 {
			continue
		}
		data := make([]byte, length+4)
		_, err = reader.Read(data)
		if err != nil {
			logger.Error("received data error :%s", err.Error())
			continue
		}
		log.Println("received msg", string(data[4:]))
		go m.handle(ctx, data[4:])
		buffer.Reset()
	}

	// ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	// defer cancel()

	// s.Shutdown(ctx)

}
