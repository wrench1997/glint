package mydemo

import (
	"context"
	"encoding/json"
	"fmt"
	"glint/logger"
	pb "glint/mesonrpc"
	"glint/util"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

func Test_customjs_2(t *testing.T) {
	const (
		port = "50051"
	)

	//测试超时
	timeout := time.After(20 * time.Second)
	//done := make(chan error, 1)

	file, err := os.Open("../json_testfile/php_deserialization.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	// 读取JSON数据
	decoder := json.NewDecoder(file)
	originUrls := make(map[string]interface{})
	if err := decoder.Decode(&originUrls); err != nil {
		panic(err)
	}

	//var WG sync.WaitGroup //当前与jackdaw等待同步计数
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	address := "127.0.0.1:" + port
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		logger.Error("fail to dial: %v", err)
	}

	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	stream, err := client.RouteChat(ctx)
	if err != nil {
		logger.Error("%s", err.Error())
		return
	}
	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				close(waitc)
				return
			}
			if err != nil {
				close(waitc)
				return
			}
			if in.Report == nil {
				continue
			}
			//log.Printf("Got Taskid %d Targetid:%d Report:%v", in.GetTaskid(), in.GetTargetid(), in.GetReport().Fields)
			if _, ok := in.GetReport().Fields["vuln"]; ok {
				logger.Success("发现漏洞!")
				PluginId := in.GetReport().Fields["vuln"].GetStringValue()
				__url := in.GetReport().Fields["url"].GetStringValue()
				body := in.GetReport().Fields["body"].GetStringValue()
				hostid := in.GetReport().Fields["hostid"].GetNumberValue()
				//保存数据库
				// Result_id, err := t.Dm.SaveScanResult(
				// 	t.TaskId,
				// 	PluginId,
				// 	true,
				// 	__url,
				// 	base64.StdEncoding.EncodeToString([]byte("")),
				// 	base64.StdEncoding.EncodeToString([]byte(body)),
				// 	int(hostid),
				// )
				// if err != nil {
				// 	logger.Error("plugin::error %s", err.Error())
				// 	return
				// }
				// 存在漏洞信息,打印到漏洞信息
				Element := make(map[string]interface{}, 1)
				Element["status"] = 3
				Element["vul"] = PluginId
				Element["request"] = ""    //base64.StdEncoding.EncodeToString([]byte())
				Element["response"] = body //base64.StdEncoding.EncodeToString([]byte())
				Element["deail"] = in.GetReport().Fields["payload"].GetStringValue()
				Element["url"] = __url
				Element["vul_level"] = in.GetReport().Fields["level"].GetStringValue()
				Element["result_id"] = hostid
				//通知socket消息
				//t.PliuginsMsg <- Element

			} else if _, ok := in.GetReport().Fields["state"]; ok {
				// WG.Done()
			}
		}
	}()

	var length = 0
	//对于目标链接传递
	for _, v := range originUrls {
		if value_list, ok := v.([]interface{}); ok {
			for _, v := range value_list {
				logger.Debug("%v", v)
				length++
			}
		}
	}

	//对于目标链接传递
	for _, v := range originUrls {
		if value_list, ok := v.([]interface{}); ok {
			for _, v := range value_list {
				if value, ok := v.(map[string]interface{}); ok {
					value["isFile"] = false
					value["taskid"] = 1
					value["targetLength"] = length
					m, err := structpb.NewValue(value)
					if err != nil {
						logger.Error("client.RouteChat NewValue m failed: %v", err)
					}
					//WG.Add(1)
					data := pb.JsonRequest{Details: m.GetStructValue()}
					if err := stream.Send(&data); err != nil {
						logger.Error("client.RouteChat JsonRequest failed: %v", err)
					}
				}
			}
		}
	}
	//<-waitc
	//stream.CloseSend()

	<-timeout
	stream.CloseSend()

	fmt.Println("finish")

}

type crawSiteList struct {
	taskid   int
	hostid   int
	FileInfo util.SiteFile
}

func Test_customjs_file(t *testing.T) {
	const (
		port = "50051"
	)

	//测试超时
	timeout := time.After(20 * time.Second)

	//var WG sync.WaitGroup //当前与jackdaw等待同步计数
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	address := "127.0.0.1:" + port
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		logger.Error("fail to dial: %v", err)
	}

	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	stream, err := client.RouteChat(ctx)
	if err != nil {
		logger.Error("%s", err.Error())
		return
	}
	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				close(waitc)
				return
			}
			if err != nil {
				close(waitc)
				return
			}
			if in.Report == nil {
				continue
			}
			//log.Printf("Got Taskid %d Targetid:%d Report:%v", in.GetTaskid(), in.GetTargetid(), in.GetReport().Fields)
			if _, ok := in.GetReport().Fields["vuln"]; ok {
				logger.Success("发现漏洞!")
				PluginId := in.GetReport().Fields["vuln"].GetStringValue()
				__url := in.GetReport().Fields["url"].GetStringValue()
				body := in.GetReport().Fields["body"].GetStringValue()
				hostid := in.GetReport().Fields["hostid"].GetNumberValue()
				Element := make(map[string]interface{}, 1)
				Element["status"] = 3
				Element["vul"] = PluginId
				Element["request"] = ""    //base64.StdEncoding.EncodeToString([]byte())
				Element["response"] = body //base64.StdEncoding.EncodeToString([]byte())
				Element["deail"] = in.GetReport().Fields["payload"].GetStringValue()
				Element["url"] = __url
				Element["vul_level"] = in.GetReport().Fields["level"].GetStringValue()
				Element["result_id"] = hostid
				//通知socket消息
				//t.PliuginsMsg <- Element

			} else if _, ok := in.GetReport().Fields["state"]; ok {
				// WG.Done()
			}
		}
	}()

	url := "http://xyzwfw.gov.cn/zwdt/xyzwdt/pages/gjjseach/js/jquery-1.12.min.js"

	// 发起HTTP GET请求
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("请求失败：%s\n", err)
		return
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("读取响应失败：%s\n", err)
		return
	}

	var length = 0
	//var file = { isFile: true, name: "jquery-1.12.min.js", fullPath: "http://xyzwfw.gov.cn/zwdt/xyzwdt/pages/gjjseach/js/jquery-1.12.min.js", response: { body: filecontent } }
	FileList := []crawSiteList{
		{taskid: 1,
			hostid: 1997,
			FileInfo: util.SiteFile{Filename: "jquery-1.12.min.js",
				Url: "http://xyzwfw.gov.cn/zwdt/xyzwdt/pages/gjjseach/js/jquery-1.12.min.js", Filecontent: body}}}

	for _, Files := range FileList {
		m, _ := structpb.NewValue(map[string]interface{}{
			"url":          Files.FileInfo.Url,
			"FileName":     Files.FileInfo.Filename,
			"Hash":         Files.FileInfo.Hash,
			"FileContent":  Files.FileInfo.Filecontent,
			"isFile":       true,
			"taskid":       1,
			"hostid":       Files.hostid,
			"targetLength": length,
		})
		data := pb.JsonRequest{Details: m.GetStructValue()}
		if err := stream.Send(&data); err != nil {
			logger.Error("client.RouteChat JsonRequest failed: %v", err)
		}
	}
	//<-waitc
	//stream.CloseSend()

	<-timeout
	stream.CloseSend()

	fmt.Println("finish")

}
