package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
)

const (
	updateDir = "updates"
)

func makeDir() {
	if _, err := os.Stat(updateDir); os.IsNotExist(err) {
		err := os.Mkdir(updateDir, 0750)
		if err != nil {
			log.Fatalf("Error creating folder %s: %v", updateDir, err)
		}
		fmt.Println("Folder created:", updateDir)
	}
}

func main() {
	certDir := "certs"
	keyDir := "keys"
	port := ":443"

	fmt.Println("Update Server by Lirprocs")
	fmt.Println("https://github.com/lirprocs")
	fmt.Println("============================")

	cg := NewCertGenerator(certDir, keyDir)
	if _, err := os.Stat(filepath.Join(certDir, "wildcard.crt")); os.IsNotExist(err) {
		if err := cg.GenerateAllCerts(); err != nil {
			log.Fatalf("Error generating certificates: %v", err)
		}
	}

	makeDir()
	fmt.Printf("Place the files in a folder %s \n", updateDir)
	for {
		fmt.Printf("Press Enter to continue \n")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		file, _ := os.ReadDir("./" + updateDir)
		if len(file) != 0 {
			break
		}
		fmt.Printf("Put the files in a folder \n")
	}

	http.Handle("/updates/", http.StripPrefix("/updates/", http.FileServer(http.Dir(updateDir))))

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	server := &http.Server{
		Addr:      "[::]" + port,
		TLSConfig: tlsConfig,
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateActive {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					state := tlsConn.ConnectionState()
					remote := conn.RemoteAddr().String()
					host, _, _ := net.SplitHostPort(remote)
					ip := net.ParseIP(host)
					ipFamily := "unknown"
					if ip != nil {
						if ip.To4() != nil {
							ipFamily = "IPv4"
						} else {
							ipFamily = "IPv6"
						}
					}
					version := "unknown"
					switch state.Version {
					case tls.VersionTLS10:
						version = "TLS 1.0"
					case tls.VersionTLS11:
						version = "TLS 1.1"
					case tls.VersionTLS12:
						version = "TLS 1.2"
					case tls.VersionTLS13:
						version = "TLS 1.3"
					}
					cipherSuite := tls.CipherSuiteName(state.CipherSuite)
					log.Printf("TLS connection: version=%s, cipher=%s, family=%s, от %s", version, cipherSuite, ipFamily, conn.RemoteAddr())
				}
			}
		},
	}

	log.Printf("HTTPS update server started on  https://[::1]%s", port)
	log.Printf("Files are available at: https://[::1]%s/updates/", port)

	certFile := filepath.Join(certDir, "wildcard.crt")
	keyFile := filepath.Join(keyDir, "wildcard.key")
	// Listen only on IPv6 to prevent IPv4 access
	ln, err := net.Listen("tcp6", "[::]"+port)
	if err != nil {
		log.Fatalf("Failed to bind IPv6 listener: %v", err)
	}
	log.Fatal(server.ServeTLS(ln, certFile, keyFile))
}
