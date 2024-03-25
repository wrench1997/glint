package main

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"glint/global"
	"glint/logger"
	"glint/proxy"
	"glint/util"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/google/martian/v3"
	mapi "github.com/google/martian/v3/api"
	"github.com/google/martian/v3/cors"
	"github.com/google/martian/v3/fifo"
	"github.com/google/martian/v3/httpspec"
	mlog "github.com/google/martian/v3/log"
	"github.com/google/martian/v3/martianhttp"
	"github.com/google/martian/v3/mitm"
	"github.com/google/martian/v3/servemux"
)

type SProxy struct {
	Port         int
	CallbackFunc SProxyCallback
}

type SProxyCallback func(args *proxy.PassiveProxy)

var Cert string
var PrivateKey string

var (
	en = flag.Bool("passiveproxy", true, "start proxy")

	addr       = flag.String("addr", ":8080", "host:port of the proxy")
	apiAddr    = flag.String("api-addr", ":8181", "host:port of the configuration API")
	tlsAddr    = flag.String("tls-addr", ":4443", "host:port of the proxy over TLS")
	api        = flag.String("api", "martian.proxy", "hostname for the API")
	generateCA = flag.Bool("generate-ca-cert", false, "generate CA certificate and private key for MITM")
	// cert = flag.String("cert", "", "filepath to the CA certificate used to sign MITM certificates")
	// key  = flag.String("key", "", "filepath to the private key of the CA used to sign MITM certificates")

	organization = flag.String("organization", "Martian Proxy", "organization name for MITM certificates")
	validity     = flag.Duration("validity", time.Hour, "window of time that MITM certificates are valid")
	allowCORS    = flag.Bool("cors", false, "allow CORS requests to configure the proxy")
	//harLogging     = flag.Bool("har", true, "enable HAR logging API")
	//marblLogging   = flag.Bool("marbl", false, "enable MARBL logging API")
	//trafficShaping = flag.Bool("traffic-shaping", false, "enable traffic shaping API")
	skipTLSVerify = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
	dsProxyURL    = flag.String("downstream-proxy-url", "", "URL of downstream proxy")
)

func configure(pattern string, handler http.Handler, mux *http.ServeMux) {
	if *allowCORS {
		handler = cors.NewHandler(handler)
	}

	// register handler for martian.proxy to be forwarded to
	// local API server
	mux.Handle(path.Join(*api, pattern), handler)

	// register handler for local API server
	p := path.Join("localhost"+*apiAddr, pattern)

	mux.Handle(p, handler)
}

func (s *SProxy) Run() error {
	//martian.Init()
	mlog.SetLevel(0)
	p := martian.NewProxy()
	defer p.Close()

	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	lAPI, err := net.Listen("tcp", *apiAddr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("martian: starting proxy on %s and api on %s", l.Addr().String(), lAPI.Addr().String())

	tr := &http.Transport{
		Dial: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: *skipTLSVerify,
		},
	}

	p.SetRoundTripper(tr)

	if *dsProxyURL != "" {
		u, err := url.Parse(*dsProxyURL)
		if err != nil {
			log.Fatal(err)
		}
		p.SetDownstreamProxy(u)
	}

	mux := http.NewServeMux()

	var x509c *x509.Certificate
	var priv interface{}

	if GenerateCA {
		var err error
		x509c, priv, err = mitm.NewAuthority("martian.proxy", "Martian Authority", 9999*24*time.Hour)
		if err != nil {
			log.Fatal(err)
		}

		//保存公钥私钥到当前目录上
		certOut, _ := os.Create("./server.pem")
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: x509c.Raw})
		certOut.Close()

		keyOut, _ := os.Create("./server.key")
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))})
		keyOut.Close()

		logger.Info("The Complete from Generating Certificat ")

		return nil

	} else if Cert != "" && PrivateKey != "" {

		tlsc, err := tls.LoadX509KeyPair(Cert, PrivateKey)
		if err != nil {
			log.Fatal(err)
		}
		priv = tlsc.PrivateKey

		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	if x509c != nil && priv != nil {

		mc, err := mitm.NewConfig(x509c, priv)
		if err != nil {
			log.Fatal(err)
		}

		mc.SetValidity(*validity)
		mc.SetOrganization(*organization)
		mc.SkipTLSVerify(*skipTLSVerify)

		p.SetMITM(mc)

		// Expose certificate authority.
		ah := martianhttp.NewAuthorityHandler(x509c)
		configure("/authority.cer", ah, mux)

		// Start TLS listener for transparent MITM.
		tl, err := net.Listen("tcp", *tlsAddr)
		if err != nil {
			log.Fatal(err)
		}

		go p.Serve(tls.NewListener(tl, mc.TLS()))
	}

	stack, fg := httpspec.NewStack("martian")

	// wrap stack in a group so that we can forward API requests to the API port
	// before the httpspec modifiers which include the via modifier which will
	// trip loop detection
	topg := fifo.NewGroup()

	// Redirect API traffic to API server.
	if *apiAddr != "" {
		addrParts := strings.Split(lAPI.Addr().String(), ":")
		apip := addrParts[len(addrParts)-1]
		port, err := strconv.Atoi(apip)
		if err != nil {
			log.Fatal(err)
		}
		host := strings.Join(addrParts[:len(addrParts)-1], ":")

		//
		apif := servemux.NewFilter(mux)
		apif.SetRequestModifier(mapi.NewForwarder(host, port))
		topg.AddRequestModifier(apif)
	}
	topg.AddRequestModifier(stack)
	topg.AddResponseModifier(stack)

	p.SetRequestModifier(topg)
	p.SetResponseModifier(topg)

	m := martianhttp.NewModifier()
	fg.AddRequestModifier(m)
	fg.AddResponseModifier(m)

	//////////////////////////////////////////////////////////////
	PProxy := proxy.NewPassiveProxy()

	muxf := servemux.NewFilter(mux)

	muxf.RequestWhenFalse(PProxy)
	stack.AddRequestModifier(muxf)

	s.CallbackFunc(PProxy)

	//////////////////////////////////////////////////////////////
	configure("/configure", m, mux)

	go p.Serve(l)

	go http.Serve(lAPI, mux)

	// go func(
	// 	PProxy
	// ) {}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt)

	<-sigc

	log.Println("martian: shutting down")
	EndTime := time.Now()
	layout := "2006-01-02 15:04:05"
	t, err := time.ParseInLocation(layout, global.VulnResultReporter.Exweb_task_info.Start_time, time.Local)
	if err != nil {
		log.Fatal(err)
	}
	otime := time.Since(t)
	over_time := util.FmtDuration(otime)
	global.VulnResultReporter.Exweb_task_info.Scan_time = over_time
	global.VulnResultReporter.Exweb_task_info.End_time = EndTime.Local().Format("2006-01-02 15:04:05")
	// global.VulnResultReporter.Exweb_task_info.End_time =
	// Export ScanReport
	data, err := json.Marshal(global.VulnResultReporter)
	if err != nil {
		log.Fatal(err)
	}
	util.JsonWrite("report.json", data)

	os.Exit(0)
	return nil
}
