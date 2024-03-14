package customjs

import (
	"context"
	"glint/logger"
	pb "glint/mesonrpc"
	"io"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
)

func JSRPC(urlinfo map[string]interface{}) {

	m, err := structpb.NewValue(urlinfo)
	if err != nil {
		logger.Error("rpc error %s", err.Error())
	}
	//fmt.Println(m.String())

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

	//test3 test1
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
			log.Printf("Got message %v at point(%v, %v)", in.GetTaskid(), in.GetTargetid(), in.GetReport())
		}
	}()

	data := pb.JsonRequest{Details: m.GetStructValue()}

	if err := stream.Send(&data); err != nil {
		log.Fatalf("client.RouteChat: stream.Send(%v) failed: %v", data, err)
	}

	stream.CloseSend()
	<-waitc
}
