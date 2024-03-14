package mydemo

import (
	"bytes"
	"context"
	"fmt"
	"glint/util"
	"log"
	"testing"
	"time"

	"github.com/Ullaakut/nmap/v2"
)

func Test_nmap(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Equivalent to `/usr/local/bin/nmap -p 80,443,843 google.com facebook.com youtube.com`,
	// with a 5 minute timeout.
	scanner, err := nmap.NewScanner(
		nmap.WithTargets("bilibili.com"),
		nmap.WithPorts("443"),
		nmap.WithScripts("ssl-enum-ciphers"),
		nmap.WithContext(ctx),
	)

	if err != nil {
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf("Warnings: \n %v", warnings)
	}
	var buf bytes.Buffer

	// Use the results to print an example output
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		fmt.Printf("Host %q:\n", host.Addresses[0])
		for _, port := range host.Ports {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
		rawXml := result.ToReader()
		buf.ReadFrom(rawXml)
		fmt.Printf("raw XMl:%s", buf.String())
	}

	fmt.Printf("Nmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}

func Test_online(t *testing.T) {
	if !util.Isdomainonline("https://www.bilibili.com") {
		fmt.Printf("不在线")
	}
}
