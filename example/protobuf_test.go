package mydemo

import (
	"context"
	"fmt"
	"io"
	"log"
	"testing"
	"time"

	"glint/logger"
	pb "glint/mesonrpc"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

// {
// 	"url": "http://192.168.166.2/pikachu/vul/unserilization/unser.php",
// 	"method": "POST",
// 	"headers": {
// 		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
// 		"Cookie": "PHPSESSID=ofl9dchd22r5s46qa8cs0bcanp",
// 		"Referer": "http://192.168.166.2/pikachu/",
// 		"Content-Type": "application/x-www-form-urlencoded",
// 		"Upgrade-Insecure-Requests": "1",
// 		"User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"
// 	},
// 	"data": "o=sss",
// 	"source": "Document",
// 	"hostid": 0
// }

func Test_structpb(t *testing.T) {
	m, err := structpb.NewValue(map[string]interface{}{
		"url":    "http://192.168.166.2/pikachu/vul/unserilization/unser.php",
		"method": "POST",
		"headers": map[string]interface{}{
			"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
			"Cookie":                    "PHPSESSID=ofl9dchd22r5s46qa8cs0bcanp",
			"Referer":                   "http://192.168.166.2/pikachu/",
			"Content-Type":              "application/x-www-form-urlencoded",
			"Upgrade-Insecure-Requests": "1",
			"User-Agent":                "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36",
		},
		"data":   "o=sss",
		"source": "Document",
		"hostid": 0,
	})
	if err != nil {
		logger.Error("rpc error %s", err.Error())
	}
	fmt.Println(m.String())

	const (
		port = "50051"
	)

	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	// lis, err := net.Listen("tcp", "127.0.0.1:"+port)
	// if err != nil {
	// 	log.Fatalf("failed to listen: %v", err)
	// }

	address := "127.0.0.1:" + port
	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}

	defer conn.Close()
	client := pb.NewRouteGuideClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	stream, err := client.RouteChat(ctx)
	if err != nil {
		logger.Error("%s", err.Error())
	}

	// fmt.Println(stream.Recv())
	waitc := make(chan struct{})
	go func() {
		for {
			in, err := stream.Recv()
			if err == io.EOF {
				// read done.
				close(waitc)
				return
			}
			if err != nil {
				log.Fatalf("client.RouteChat failed: %v", err)
			}
			log.Printf("Got Taskid %d Targetid:%d Report:%v", in.GetTaskid(), in.GetTargetid(), in.GetReport().Fields)
			in.GetReport().Fields["Name"].GetStringValue()

		}
	}()

	data := pb.JsonRequest{Details: m.GetStructValue()}
	//for _, note := range notes {
	if err := stream.Send(&data); err != nil {
		log.Fatalf("client.RouteChat: stream.Send(%v) failed: %v", data, err)
	}
	//}

	stream.CloseSend()
	<-waitc

}
