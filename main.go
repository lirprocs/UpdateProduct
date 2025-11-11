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

func makeDir(updateDir string) {
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
	cfg := MustLoad()

	fmt.Println("Update Server by Lirprocs")
	fmt.Println("https://github.com/lirprocs")
	fmt.Println("============================")

	cg := NewCertGenerator(certDir, keyDir)
	if _, err := os.Stat(filepath.Join(certDir, "wildcard.crt")); os.IsNotExist(err) {
		if err := cg.GenerateAllCerts(); err != nil {
			log.Fatalf("Error generating certificates: %v", err)
		}
	}

	makeDir(cfg.Server.UpdateDir)
	fmt.Printf("Place the files in a folder %s \n", cfg.Server.UpdateDir)
	for {
		fmt.Printf("Press Enter to continue \n")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
		file, _ := os.ReadDir("./" + cfg.Server.UpdateDir)
		if len(file) != 0 {
			break
		}
		fmt.Printf("Put the files in a folder \n")
	}

	http.Handle("/updates/", http.StripPrefix("/updates/", http.FileServer(http.Dir(cfg.Server.UpdateDir))))

	tlsConfig := &tls.Config{
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	server := &http.Server{
		Addr:      cfg.Server.Address + cfg.Server.Port,
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

	log.Printf("HTTPS update server started on  https://[::1]%s", cfg.Server.Port)
	log.Printf("Files are available at: https://[::1]%s/updates/", cfg.Server.Port)

	certFile := filepath.Join(certDir, "wildcard.crt")
	keyFile := filepath.Join(keyDir, "wildcard.key")
	ln, err := net.Listen("tcp6", cfg.Server.Address+cfg.Server.Port)
	if err != nil {
		log.Fatalf("Failed to bind IPv6 listener: %v", err)
	}
	log.Fatal(server.ServeTLS(ln, certFile, keyFile))
}
