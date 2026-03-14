package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var version = "0.1.0"

type enrollResponse struct {
	RelayID string `json:"relayId"`
	Label   string `json:"label"`
	Token   string `json:"token"`
}

type relayClient struct {
	httpClient      *http.Client
	serverURL       string
	relayID         string
	label           string
	relayVersion    string
	enrollSecret    string
	enrollmentToken string
	certificate     string
	activeConns     *atomic.Int64
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	server := flag.String("server", "", "URL du bastion EndoriumFort (ex: https://bastion.example.com)")
	relayID := flag.String("relay-id", "", "Identifiant unique du relais")
	label := flag.String("label", "", "Label lisible du relais")
	listenAddr := flag.String("listen", ":18080", "Adresse d'écoute du proxy CONNECT")
	enrollSecret := flag.String("enroll-secret", "", "Secret d'enrollment partagé")
	enrollmentToken := flag.String("enrollment-token", "", "Token d'enrollment one-shot")
	certificate := flag.String("certificate", "", "Certificat relais (header X-EndoriumFort-Relay-Certificate)")
	heartbeatInterval := flag.Duration("heartbeat-interval", 20*time.Second, "Intervalle heartbeat")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "Timeout de connexion cible")
	insecureTLS := flag.Bool("insecure", false, "Ignore la validation TLS (lab uniquement)")
	allowHTTP := flag.Bool("allow-http", false, "Autorise server en HTTP (lab uniquement)")
	showVersion := flag.Bool("version", false, "Affiche la version")
	flag.Parse()

	if *showVersion {
		fmt.Printf("EndoriumFortRelay v%s\n", version)
		return
	}
	if *server == "" {
		fatal("--server est requis")
	}
	if *relayID == "" {
		fatal("--relay-id est requis")
	}
	if *label == "" {
		*label = *relayID
	}
	if *enrollSecret == "" && *enrollmentToken == "" {
		fatal("--enroll-secret ou --enrollment-token est requis")
	}
	if strings.HasPrefix(*server, "http://") && !*allowHTTP {
		fatal("server en HTTP refusé. Utilise HTTPS ou --allow-http pour lab")
	}

	transport := &http.Transport{}
	if *insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	activeConns := &atomic.Int64{}
	client := &relayClient{
		httpClient:      &http.Client{Transport: transport, Timeout: 20 * time.Second},
		serverURL:       strings.TrimRight(*server, "/"),
		relayID:         *relayID,
		label:           *label,
		relayVersion:    version,
		enrollSecret:    *enrollSecret,
		enrollmentToken: *enrollmentToken,
		certificate:     *certificate,
		activeConns:     activeConns,
	}

	token, err := client.enroll(context.Background())
	if err != nil {
		fatal("enrollment relay échoué: %v", err)
	}
	log.Printf("[relay] enrolled relayId=%s", *relayID)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go client.heartbeatLoop(ctx, token, *heartbeatInterval)

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		fatal("impossible de démarrer le listener proxy: %v", err)
	}
	defer listener.Close()
	log.Printf("[relay] proxy CONNECT en écoute sur %s", *listenAddr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				continue
			}
			log.Printf("[relay] accept error: %v", err)
			continue
		}
		go handleConnectProxyConn(conn, *dialTimeout, activeConns)
	}
}

func (c *relayClient) enroll(ctx context.Context) (string, error) {
	body := map[string]interface{}{
		"relayId":      c.relayID,
		"label":        c.label,
		"version":      c.relayVersion,
		"capabilities": []string{"tcp-connect-proxy"},
	}
	payload, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/relays/enroll", strings.NewReader(string(payload)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.enrollSecret != "" {
		req.Header.Set("X-EndoriumFort-Relay-Secret", c.enrollSecret)
	}
	if c.enrollmentToken != "" {
		req.Header.Set("X-EndoriumFort-Relay-Enrollment-Token", c.enrollmentToken)
	}
	if c.certificate != "" {
		req.Header.Set("X-EndoriumFort-Relay-Certificate", c.certificate)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.Token) == "" {
		return "", fmt.Errorf("réponse enrollment sans token")
	}
	return out.Token, nil
}

func (c *relayClient) heartbeatLoop(ctx context.Context, initialToken string, interval time.Duration) {
	if interval < 5*time.Second {
		interval = 5 * time.Second
	}
	token := initialToken
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	send := func() error {
		body := map[string]interface{}{"managedResourceCount": int(c.activeConns.Load())}
		payload, _ := json.Marshal(body)

		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL+"/api/relays/heartbeat", strings.NewReader(string(payload)))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-EndoriumFort-Relay-Token", token)
		if c.certificate != "" {
			req.Header.Set("X-EndoriumFort-Relay-Certificate", c.certificate)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			newToken, enrollErr := c.enroll(ctx)
			if enrollErr != nil {
				return fmt.Errorf("heartbeat auth failed and re-enroll failed: %w", enrollErr)
			}
			token = newToken
			return nil
		}
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			return fmt.Errorf("heartbeat status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(raw)))
		}
		return nil
	}

	if err := send(); err != nil {
		log.Printf("[relay] heartbeat initial error: %v", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := send(); err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("[relay] heartbeat error: %v", err)
			}
		}
	}
}

func handleConnectProxyConn(clientConn net.Conn, dialTimeout time.Duration, activeConns *atomic.Int64) {
	defer clientConn.Close()
	_ = clientConn.SetDeadline(time.Now().Add(20 * time.Second))

	br := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(br)
	if err != nil {
		writeHTTPError(clientConn, http.StatusBadRequest, "invalid request")
		return
	}
	defer req.Body.Close()

	if req.Method != http.MethodConnect {
		writeHTTPError(clientConn, http.StatusMethodNotAllowed, "CONNECT only")
		return
	}

	target := strings.TrimSpace(req.Host)
	if target == "" {
		writeHTTPError(clientConn, http.StatusBadRequest, "missing target")
		return
	}
	if !strings.Contains(target, ":") {
		target += ":443"
	}

	targetConn, err := net.DialTimeout("tcp", target, dialTimeout)
	if err != nil {
		writeHTTPError(clientConn, http.StatusBadGateway, "cannot reach target")
		return
	}
	defer targetConn.Close()

	_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = clientConn.SetDeadline(time.Time{})

	activeConns.Add(1)
	defer activeConns.Add(-1)

	leftErr := make(chan error, 1)
	rightErr := make(chan error, 1)

	go func() {
		_, err := io.Copy(targetConn, br)
		leftErr <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, targetConn)
		rightErr <- err
	}()

	select {
	case <-leftErr:
	case <-rightErr:
	}
}

func writeHTTPError(w io.Writer, status int, msg string) {
	reason := http.StatusText(status)
	body := msg + "\n"
	_, _ = io.WriteString(w,
		"HTTP/1.1 "+strconv.Itoa(status)+" "+reason+"\r\n"+
			"Content-Type: text/plain; charset=utf-8\r\n"+
			"Content-Length: "+strconv.Itoa(len(body))+"\r\n"+
			"Connection: close\r\n\r\n"+
			body)
}

func fatal(format string, args ...interface{}) {
	log.Printf("[fatal] "+format, args...)
	os.Exit(1)
}
