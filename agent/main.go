package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// version is set at build time via: go build -ldflags "-X main.version=x.y.z"
var version = "0.3.0"
var useJSONLogs bool

func agentUserAgent() string {
	return "EndoriumFortAgent/" + version
}

// ─── Types ──────────────────────────────────────────────────────────────

type Resource struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
}

type TunnelSpec struct {
	ResourceID int
	LocalPort  int
}

type TunnelBinding struct {
	Resource  Resource
	LocalPort int
}

type tunnelRuntime struct {
	binding TunnelBinding
	stop    chan struct{}
	done    chan struct{}
	stats   tunnelStats
}

type tunnelStats struct {
	state       atomic.Value // string: starting/healthy/degraded/down/stopped
	activeConns atomic.Int64
	totalConns  atomic.Int64
	txBytes     atomic.Int64
	rxBytes     atomic.Int64
	lastError   atomic.Value // string
	startedAt   time.Time
}

type tunnelSnapshot struct {
	ResourceID  int
	Resource    string
	LocalPort   int
	State       string
	ActiveConns int64
	TotalConns  int64
	TxBytes     int64
	RxBytes     int64
	LastError   string
}

type TunnelManager struct {
	serverURL   string
	token       string
	insecureTLS bool

	mu      sync.Mutex
	tunnels map[int]*tunnelRuntime
}

func logEvent(level, event string, fields map[string]interface{}) {
	if fields == nil {
		fields = map[string]interface{}{}
	}
	fields["level"] = level
	fields["event"] = event
	fields["ts"] = time.Now().UTC().Format(time.RFC3339)
	if useJSONLogs {
		b, _ := json.Marshal(fields)
		log.Println(string(b))
		return
	}
	log.Printf("[%s] %s %+v", strings.ToUpper(level), event, fields)
}

type tunnelFlag []string

func (t *tunnelFlag) String() string {
	return strings.Join(*t, ",")
}

func (t *tunnelFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("tunnel spec vide")
	}
	*t = append(*t, value)
	return nil
}

// ─── CLI entrypoint ─────────────────────────────────────────────────────

func main() {
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	// No args or "start" → interactive mode
	if len(os.Args) < 2 || os.Args[1] == "start" {
		interactiveMode()
		return
	}

	switch os.Args[1] {
	case "login":
		cmdLogin(os.Args[2:])
	case "list":
		cmdList(os.Args[2:])
	case "connect":
		cmdConnect(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("EndoriumFortAgent v%s\n", version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "Commande inconnue: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`EndoriumFortAgent - Agent tunnel pour EndoriumFort PAM

Usage:
  endoriumfort-agent                  Mode interactif (recommandé)
  endoriumfort-agent <commande> [opts] Mode CLI

Commandes:
  (aucune)  Lancer le mode interactif guidé
  login     S'authentifier et obtenir un token
  list      Lister les ressources disponibles
  connect   Ouvrir un tunnel vers une ressource
  version   Afficher la version
  help      Afficher cette aide

Exemples CLI:
  endoriumfort-agent login   --server http://bastion:8080 --user admin --password secret
  endoriumfort-agent list    --server http://bastion:8080 --token eft_xxxx
	endoriumfort-agent connect --server http://bastion:8080 --token eft_xxxx --resource 3 --local-port 8888
	endoriumfort-agent connect --server http://bastion:8080 --token eft_xxxx --tunnel 3:8888 --tunnel 7:8890
	endoriumfort-agent connect --server http://bastion:8080 --token eft_xxxx --tunnel 3:8888 --manage
	endoriumfort-agent connect --server http://bastion:8080 --token eft_xxxx --tunnel 3:8888 --tui --log-json

Options TLS:
	--insecure   Ignore la validation TLS (certificat auto-signé, lab uniquement)
	--allow-http Autorise HTTP non chiffré (lab uniquement)
	EF_INSECURE_TLS=1  Active aussi le mode insecure en interactif
	EF_ALLOW_INSECURE_HTTP=1  Autorise HTTP non chiffré en interactif/lab

Options multi-tunnel (commande connect):
	--tunnel <resource_id>:<local_port>   Répéter l'option pour plusieurs tunnels
	--manage                              Mode gestion à chaud (add/remove/list/quit)
	--tui                                 Tableau live state/TX/RX
	--log-json                            Logs structurés JSON`)
}

// ─── INTERACTIVE MODE ───────────────────────────────────────────────────

func interactiveMode() {
	reader := bufio.NewReader(os.Stdin)
	insecureTLS := envBool("EF_INSECURE_TLS")
	allowInsecureHTTP := envBool("EF_ALLOW_INSECURE_HTTP")

	printBanner()

	// Step 1: Server URL
	serverURL := promptWithDefault(reader, "Adresse du serveur EndoriumFort", "http://localhost:8080")
	serverURL = strings.TrimRight(serverURL, "/")
	if err := enforceTransportSecurity(serverURL, insecureTLS, allowInsecureHTTP); err != nil {
		log.Fatalf("  %v", err)
	}

	// Verify server is reachable
	fmt.Printf("\n  Vérification du serveur... ")
	healthURL := serverURL + "/api/health"
	healthResp, err := httpClient(insecureTLS).Get(healthURL)
	if err != nil {
		fmt.Printf("✗\n")
		log.Fatalf("  Impossible de contacter le serveur: %v", err)
	}
	defer healthResp.Body.Close()
	var healthData map[string]interface{}
	json.NewDecoder(healthResp.Body).Decode(&healthData)
	ver, _ := healthData["version"].(string)
	fmt.Printf("✓ (v%s)\n\n", ver)

	// Step 2: Login
	username := prompt(reader, "Nom d'utilisateur")
	passwordBytes := promptPasswordBytes(reader, "Mot de passe")
	password := string(passwordBytes)
	defer zeroBytes(passwordBytes)
	if insecureTLS {
		warnTLSBypass()
	}

	fmt.Printf("\n  Authentification... ")
	token, role, err := apiLogin(serverURL, username, password, insecureTLS)
	if err != nil {
		fmt.Printf("✗\n")
		log.Fatalf("  Échec: %v", err)
	}
	fmt.Printf("✓\n")
	fmt.Printf("  Connecté en tant que %s (rôle: %s)\n\n", username, role)

	// Step 3: List resources
	fmt.Printf("  Chargement des ressources... ")
	resources, err := apiListResources(serverURL, token, insecureTLS)
	if err != nil {
		fmt.Printf("✗\n")
		log.Fatalf("  Échec: %v", err)
	}
	fmt.Printf("✓\n\n")

	if len(resources) == 0 {
		fmt.Println("  Aucune ressource disponible.")
		fmt.Println("  Contactez votre administrateur pour obtenir des accès.")
		return
	}

	// Display resources
	fmt.Println("  Ressources disponibles:")
	fmt.Println()
	fmt.Printf("    %-4s %-25s %-10s %-25s %s\n", "N°", "Nom", "Protocole", "Cible", "Port")
	fmt.Printf("    %-4s %-25s %-10s %-25s %s\n", "──", "─────────────────────────", "──────────", "─────────────────────────", "────")
	for i, r := range resources {
		fmt.Printf("    %-4d %-25s %-10s %-25s %d\n", i+1, truncStr(r.Name, 25), r.Protocol, truncStr(r.Target, 25), r.Port)
	}
	fmt.Println()

	// Step 4: Choose resource
	var selected Resource
	if len(resources) == 1 {
		selected = resources[0]
		fmt.Printf("  → Ressource unique sélectionnée: %s\n", selected.Name)
	} else {
		for {
			choiceStr := prompt(reader, fmt.Sprintf("Choisir une ressource (1-%d)", len(resources)))
			choice, err := strconv.Atoi(choiceStr)
			if err != nil || choice < 1 || choice > len(resources) {
				fmt.Printf("  ⚠ Choix invalide. Entrez un nombre entre 1 et %d.\n", len(resources))
				continue
			}
			selected = resources[choice-1]
			break
		}
	}

	// Step 5: Choose local port
	defaultPort := suggestLocalPort(selected.Port)
	portStr := promptWithDefault(reader, "Port local", strconv.Itoa(defaultPort))
	localPort, err := strconv.Atoi(portStr)
	if err != nil || localPort < 1 || localPort > 65535 {
		log.Fatalf("  Port invalide: %s", portStr)
	}

	fmt.Println()
	fmt.Printf("  ┌─────────────────────────────────────────────────┐\n")
	fmt.Printf("  │  Ressource: %-36s │\n", selected.Name)
	fmt.Printf("  │  Cible:     %-36s │\n", fmt.Sprintf("%s:%d", selected.Target, selected.Port))
	fmt.Printf("  │  Tunnel:    %-36s │\n", fmt.Sprintf("127.0.0.1:%d → %s:%d", localPort, selected.Target, selected.Port))
	fmt.Printf("  └─────────────────────────────────────────────────┘\n")
	fmt.Println()

	confirm := promptWithDefault(reader, "Lancer le tunnel ? (O/n)", "O")
	if strings.ToLower(strings.TrimSpace(confirm)) == "n" {
		fmt.Println("  Annulé.")
		return
	}

	// Step 6: Start tunnel
	fmt.Println()
	startTunnels(serverURL, token, []TunnelBinding{{
		Resource: Resource{
			ID:       selected.ID,
			Name:     selected.Name,
			Protocol: selected.Protocol,
			Target:   selected.Target,
			Port:     selected.Port,
		},
		LocalPort: localPort,
	}}, insecureTLS, false, false)
}

// ─── Security helpers ───────────────────────────────────────────────────

func warnIfInsecure(serverURL string) {
	if strings.HasPrefix(serverURL, "http://") {
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "⚠️  ATTENTION: Connexion non chiffrée (HTTP)")
		fmt.Fprintln(os.Stderr, "   Les credentials et tokens transitent en clair.")
		fmt.Fprintln(os.Stderr, "   Utilisez HTTPS en production.")
		fmt.Fprintln(os.Stderr, "")
	}
}

func warnTLSBypass() {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "⚠️  ATTENTION: Vérification TLS désactivée (--insecure)")
	fmt.Fprintln(os.Stderr, "   Utiliser uniquement en environnement de test/lab.")
	fmt.Fprintln(os.Stderr, "")
}

func envBool(name string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	return v == "1" || v == "true" || v == "yes" || v == "on"
}

func tokenFilePath() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".endoriumfort_token")
}

func loadTokenFromFile() (string, error) {
	path := tokenFilePath()
	if path == "" {
		return "", fmt.Errorf("home directory introuvable")
	}
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("permissions trop larges sur %s (attendu 600)", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func saveTokenSecure(token string) error {
	path := tokenFilePath()
	if path == "" {
		return fmt.Errorf("home directory introuvable")
	}
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func enforceTransportSecurity(serverURL string, insecureTLS bool, allowInsecureHTTP bool) error {
	u, err := url.Parse(serverURL)
	if err != nil {
		return fmt.Errorf("URL serveur invalide: %v", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "" {
		return fmt.Errorf("URL serveur invalide: schéma manquant (https:// requis)")
	}
	if scheme == "http" && !allowInsecureHTTP {
		return fmt.Errorf("transport HTTP refusé: utilisez HTTPS (ou EF_ALLOW_INSECURE_HTTP=1 / --allow-http en lab)")
	}
	if insecureTLS && scheme != "https" {
		return fmt.Errorf("--insecure requiert un endpoint HTTPS (pas HTTP)")
	}
	return nil
}

func httpClient(insecureTLS bool) *http.Client {
	if !insecureTLS {
		return http.DefaultClient
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}
}

func wsDialer(insecureTLS bool) *websocket.Dialer {
	return &websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   16384,
		WriteBufferSize:  16384,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureTLS},
	}
}

// ─── API helpers ────────────────────────────────────────────────────────

func apiLogin(serverURL, user, password string, insecureTLS bool) (token, role string, err error) {
	body, _ := json.Marshal(map[string]string{
		"user":     user,
		"password": password,
	})

	resp, err := httpClient(insecureTLS).Post(
		serverURL+"/api/auth/login",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return "", "", fmt.Errorf("connexion impossible: %v", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("réponse invalide: %v", err)
	}

	if resp.StatusCode != 200 {
		msg, _ := result["error"].(string)
		if msg == "" {
			msg = fmt.Sprintf("HTTP %d", resp.StatusCode)
		}
		return "", "", fmt.Errorf("%s", msg)
	}

	token, _ = result["token"].(string)
	role, _ = result["role"].(string)
	return token, role, nil
}

func apiListResources(serverURL, token string, insecureTLS bool) ([]Resource, error) {
	req, _ := http.NewRequest("GET", serverURL+"/api/resources", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := httpClient(insecureTLS).Do(req)
	if err != nil {
		return nil, fmt.Errorf("connexion impossible: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}

	var result struct {
		Items []Resource `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("réponse invalide: %v", err)
	}
	return result.Items, nil
}

// ─── Tunnel ─────────────────────────────────────────────────────────────

func runTunnelListener(manager *TunnelManager, rt *tunnelRuntime, wg *sync.WaitGroup) {
	defer wg.Done()
	resource := rt.binding.Resource
	localPort := rt.binding.LocalPort

	listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)

	// Preflight: validate auth + resource access by issuing a one-time tunnel ticket.
	if _, _, _, _, _, _, _, err := apiIssueTunnelTicket(manager.serverURL, manager.currentToken(), resource.ID, manager.insecureTLS); err != nil {
		rt.stats.state.Store("degraded")
		rt.stats.lastError.Store(err.Error())
		if strings.Contains(err.Error(), "HTTP 401") && manager.refreshTokenFromSources() {
			_, _, _, _, _, _, _, err = apiIssueTunnelTicket(manager.serverURL, manager.currentToken(), resource.ID, manager.insecureTLS)
		}
		if err != nil {
			logEvent("error", "tunnel.preflight.failed", map[string]interface{}{"resourceId": resource.ID, "localPort": localPort, "error": err.Error()})
			return
		}
	}
	rt.stats.state.Store("healthy")
	rt.stats.lastError.Store("")

	// Listen
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		rt.stats.state.Store("down")
		rt.stats.lastError.Store(err.Error())
		logEvent("error", "tunnel.listen.failed", map[string]interface{}{"resourceId": resource.ID, "localPort": localPort, "error": err.Error()})
		return
	}
	defer listener.Close()

	// Stop watcher
	go func() {
		<-rt.stop
		_ = listener.Close()
	}()

	logEvent("info", "tunnel.listen.ready", map[string]interface{}{"resourceId": resource.ID, "resource": resource.Name, "localPort": localPort})
	targetLabel := "résolue par le backend"
	if strings.TrimSpace(resource.Target) != "" && resource.Port > 0 {
		targetLabel = fmt.Sprintf("%s:%d", resource.Target, resource.Port)
	}
	logEvent("info", "tunnel.target", map[string]interface{}{"resourceId": resource.ID, "target": targetLabel, "localPort": localPort})

	var connID int
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				break
			}
			select {
			case <-rt.stop:
				return
			default:
			}
			rt.stats.state.Store("degraded")
			rt.stats.lastError.Store(err.Error())
			logEvent("warn", "tunnel.accept.failed", map[string]interface{}{"resourceId": resource.ID, "localPort": localPort, "error": err.Error()})
			continue
		}
		connID++
		rt.stats.activeConns.Add(1)
		rt.stats.totalConns.Add(1)
		go handleTunnelConnection(tcpConn, manager, rt, resource.ID, connID)
	}
}

func newTunnelManager(serverURL, token string, insecureTLS bool) *TunnelManager {
	return &TunnelManager{
		serverURL:   serverURL,
		token:       token,
		insecureTLS: insecureTLS,
		tunnels:     make(map[int]*tunnelRuntime),
	}
}

func (m *TunnelManager) currentToken() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.token
}

func (m *TunnelManager) refreshTokenFromSources() bool {
	tok := strings.TrimSpace(os.Getenv("EF_TOKEN"))
	if tok == "" {
		fileTok, err := loadTokenFromFile()
		if err == nil {
			tok = fileTok
		}
	}
	if tok == "" {
		return false
	}
	m.mu.Lock()
	m.token = tok
	m.mu.Unlock()
	return true
}

func (m *TunnelManager) Start(binding TunnelBinding) error {
	if binding.LocalPort < 1 || binding.LocalPort > 65535 {
		return fmt.Errorf("port local invalide: %d", binding.LocalPort)
	}

	m.mu.Lock()
	if _, exists := m.tunnels[binding.LocalPort]; exists {
		m.mu.Unlock()
		return fmt.Errorf("port local déjà utilisé: %d", binding.LocalPort)
	}
	rt := &tunnelRuntime{
		binding: binding,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	rt.stats.state.Store("starting")
	rt.stats.lastError.Store("")
	rt.stats.startedAt = time.Now()
	m.tunnels[binding.LocalPort] = rt
	m.mu.Unlock()

	go func() {
		var wg sync.WaitGroup
		wg.Add(1)
		runTunnelListener(m, rt, &wg)
		wg.Wait()
		rt.stats.state.Store("stopped")
		close(rt.done)
		m.mu.Lock()
		delete(m.tunnels, binding.LocalPort)
		m.mu.Unlock()
	}()

	return nil
}

func (m *TunnelManager) Stop(localPort int) error {
	m.mu.Lock()
	rt, exists := m.tunnels[localPort]
	m.mu.Unlock()
	if !exists {
		return fmt.Errorf("aucun tunnel sur le port %d", localPort)
	}
	rt.stats.state.Store("stopped")
	close(rt.stop)
	<-rt.done
	return nil
}

func (m *TunnelManager) StopAll() {
	m.mu.Lock()
	runtimes := make([]*tunnelRuntime, 0, len(m.tunnels))
	for _, rt := range m.tunnels {
		runtimes = append(runtimes, rt)
	}
	m.mu.Unlock()

	for _, rt := range runtimes {
		rt.stats.state.Store("stopped")
		close(rt.stop)
	}
	for _, rt := range runtimes {
		<-rt.done
	}
}

func (m *TunnelManager) Snapshot() []TunnelBinding {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TunnelBinding, 0, len(m.tunnels))
	for _, rt := range m.tunnels {
		out = append(out, rt.binding)
	}
	return out
}

func (m *TunnelManager) StatsSnapshot() []tunnelSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]tunnelSnapshot, 0, len(m.tunnels))
	for _, rt := range m.tunnels {
		state, _ := rt.stats.state.Load().(string)
		lastErr, _ := rt.stats.lastError.Load().(string)
		out = append(out, tunnelSnapshot{
			ResourceID:  rt.binding.Resource.ID,
			Resource:    rt.binding.Resource.Name,
			LocalPort:   rt.binding.LocalPort,
			State:       state,
			ActiveConns: rt.stats.activeConns.Load(),
			TotalConns:  rt.stats.totalConns.Load(),
			TxBytes:     rt.stats.txBytes.Load(),
			RxBytes:     rt.stats.rxBytes.Load(),
			LastError:   lastErr,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LocalPort < out[j].LocalPort })
	return out
}

func renderStatsTable(items []tunnelSnapshot) {
	fmt.Print("\033[2J\033[H")
	fmt.Println("EndoriumFort Agent - Tunnels")
	fmt.Println("resource  local          state     conns  tx(bytes)   rx(bytes)   last_error")
	fmt.Println("--------  -------------  --------  -----  ----------  ----------  ----------")
	if len(items) == 0 {
		fmt.Println("(aucun tunnel actif)")
		return
	}
	for _, it := range items {
		errText := truncStr(it.LastError, 40)
		fmt.Printf("%-8d  127.0.0.1:%-6d %-8s  %-5d  %-10d  %-10d  %s\n",
			it.ResourceID, it.LocalPort, it.State, it.ActiveConns, it.TxBytes, it.RxBytes, errText)
	}
}

func runTUI(manager *TunnelManager, quit <-chan struct{}) {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			renderStatsTable(manager.StatsSnapshot())
			fmt.Println()
			fmt.Println("Ctrl+C pour arrêter")
		case <-quit:
			return
		}
	}
}

func runManageLoop(manager *TunnelManager, quit chan struct{}) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("Mode manage actif: add <resource:port> | remove <port> | list | stats | quit")
	for {
		fmt.Print("agent> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			close(quit)
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		switch strings.ToLower(fields[0]) {
		case "add":
			if len(fields) != 2 {
				fmt.Println("usage: add <resource_id>:<local_port>")
				continue
			}
			specs, err := parseTunnelSpecs([]string{fields[1]})
			if err != nil || len(specs) != 1 {
				fmt.Printf("erreur: %v\n", err)
				continue
			}
			binding := TunnelBinding{
				Resource: Resource{ID: specs[0].ResourceID, Name: fmt.Sprintf("resource-%d", specs[0].ResourceID)},
				LocalPort: specs[0].LocalPort,
			}
			if err := manager.Start(binding); err != nil {
				fmt.Printf("erreur: %v\n", err)
				continue
			}
			fmt.Printf("ok: tunnel ajouté resource=%d port=%d\n", specs[0].ResourceID, specs[0].LocalPort)
		case "remove", "rm":
			if len(fields) != 2 {
				fmt.Println("usage: remove <local_port>")
				continue
			}
			port, err := strconv.Atoi(fields[1])
			if err != nil || port < 1 || port > 65535 {
				fmt.Println("erreur: port invalide")
				continue
			}
			if err := manager.Stop(port); err != nil {
				fmt.Printf("erreur: %v\n", err)
				continue
			}
			fmt.Printf("ok: tunnel arrêté port=%d\n", port)
		case "list", "ls", "stats":
			items := manager.StatsSnapshot()
			if len(items) == 0 {
				fmt.Println("aucun tunnel actif")
				continue
			}
			fmt.Println("tunnels actifs:")
			for _, it := range items {
				fmt.Printf("- resource=%d local=127.0.0.1:%d state=%s conns=%d tx=%d rx=%d\n",
					it.ResourceID, it.LocalPort, it.State, it.ActiveConns, it.TxBytes, it.RxBytes)
			}
		case "quit", "exit":
			close(quit)
			return
		case "help":
			fmt.Println("commandes: add <resource:port> | remove <port> | list | stats | quit")
		default:
			fmt.Println("commande inconnue. tapez 'help'.")
		}
	}
}

func startTunnels(serverURL, token string, bindings []TunnelBinding, insecureTLS bool, manage bool, tui bool) {
	if len(bindings) == 0 {
		log.Fatal("Aucun tunnel à démarrer")
	}

	manager := newTunnelManager(serverURL, token, insecureTLS)
	for _, binding := range bindings {
		if err := manager.Start(binding); err != nil {
			log.Printf("Échec démarrage tunnel resource=%d port=%d: %v", binding.Resource.ID, binding.LocalPort, err)
		}
	}

	quitManage := make(chan struct{})
	var quitOnce sync.Once
	closeQuit := func() {
		quitOnce.Do(func() { close(quitManage) })
	}
	if manage {
		go runManageLoop(manager, quitManage)
	}
	if tui {
		go runTUI(manager, quitManage)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if manage || tui {
		select {
		case <-sigCh:
			log.Println("Arrêt des tunnels (signal)...")
			closeQuit()
		case <-quitManage:
			log.Println("Arrêt des tunnels (commande quit)...")
		}
	} else {
		<-sigCh
		log.Println("Arrêt des tunnels...")
	}
	closeQuit()
	manager.StopAll()
}

func parseTunnelSpecs(rawSpecs []string) ([]TunnelSpec, error) {
	if len(rawSpecs) == 0 {
		return nil, nil
	}

	seen := make(map[int]struct{})
	var specs []TunnelSpec
	for _, item := range rawSpecs {
		parts := strings.Split(strings.TrimSpace(item), ":")
		if len(parts) != 2 {
			return nil, fmt.Errorf("format tunnel invalide '%s' (attendu: resource_id:local_port)", item)
		}

		resourceID, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil || resourceID <= 0 {
			return nil, fmt.Errorf("resource_id invalide dans '%s'", item)
		}
		localPort, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil || localPort < 1 || localPort > 65535 {
			return nil, fmt.Errorf("local_port invalide dans '%s'", item)
		}
		if _, exists := seen[localPort]; exists {
			return nil, fmt.Errorf("port local dupliqué: %d", localPort)
		}
		seen[localPort] = struct{}{}
		specs = append(specs, TunnelSpec{ResourceID: resourceID, LocalPort: localPort})
	}
	return specs, nil
}

// ─── CLI commands (kept for scripting / automation) ─────────────────────

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "Backend URL (ex: http://bastion:8080)")
	user := fs.String("user", "", "Nom d'utilisateur")
	password := fs.String("password", "", "Mot de passe (prefer EF_PASSWORD env var)")
	insecure := fs.Bool("insecure", false, "Ignorer la validation TLS (certificat auto-signé)")
	allowHTTP := fs.Bool("allow-http", false, "Autoriser HTTP non chiffré (lab seulement)")
	fs.Parse(args)

	// Allow password from env var for security (avoids ps aux leak)
	if *password == "" {
		*password = os.Getenv("EF_PASSWORD")
	}

	if *server == "" || *user == "" || *password == "" {
		fmt.Fprintln(os.Stderr, "Erreur: --server, --user et --password sont requis")
		fmt.Fprintln(os.Stderr, "Astuce: vous pouvez passer le mot de passe via EF_PASSWORD")
		fs.Usage()
		os.Exit(1)
	}
	allowInsecureHTTP := *allowHTTP || envBool("EF_ALLOW_INSECURE_HTTP")
	if err := enforceTransportSecurity(strings.TrimRight(*server, "/"), *insecure, allowInsecureHTTP); err != nil {
		log.Fatalf("Échec politique transport: %v", err)
	}

	warnIfInsecure(*server)
	if *insecure {
		warnTLSBypass()
	}

	token, role, err := apiLogin(strings.TrimRight(*server, "/"), *user, *password, *insecure)
	if err != nil {
		log.Fatalf("Échec de connexion: %v", err)
	}

	// Mask token in output (show only first 12 chars)
	maskedToken := token
	if len(token) > 12 {
		maskedToken = token[:12] + "..."
	}

	fmt.Println("✓ Connexion réussie")
	fmt.Printf("  Utilisateur: %s\n", *user)
	fmt.Printf("  Rôle:        %s\n", role)
	fmt.Printf("  Token:       %s\n", maskedToken)
	if *password != "" && os.Getenv("EF_PASSWORD") == "" {
		fmt.Println("  Note sécurité: éviter --password en clair, préférez EF_PASSWORD ou saisie interactive.")
	}

	// Save token to file with restricted permissions
	if err := saveTokenSecure(token); err == nil {
		fmt.Printf("  Token complet sauvegardé dans: %s\n", tokenFilePath())
	} else {
		fmt.Printf("  Warning: impossible de sauvegarder le token localement: %v\n", err)
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	server := fs.String("server", "", "Backend URL")
	token := fs.String("token", "", "Token d'authentification (prefer EF_TOKEN env var)")
	insecure := fs.Bool("insecure", false, "Ignorer la validation TLS (certificat auto-signé)")
	allowHTTP := fs.Bool("allow-http", false, "Autoriser HTTP non chiffré (lab seulement)")
	fs.Parse(args)

	// Allow token from env var or saved file
	if *token == "" {
		*token = os.Getenv("EF_TOKEN")
	}
	if *token == "" {
		if tok, err := loadTokenFromFile(); err == nil {
			*token = tok
		}
	}

	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "Erreur: --server et --token sont requis")
		fmt.Fprintln(os.Stderr, "Astuce: EF_TOKEN env var ou ~/.endoriumfort_token")
		fs.Usage()
		os.Exit(1)
	}
	allowInsecureHTTP := *allowHTTP || envBool("EF_ALLOW_INSECURE_HTTP")
	if err := enforceTransportSecurity(strings.TrimRight(*server, "/"), *insecure, allowInsecureHTTP); err != nil {
		log.Fatalf("Échec politique transport: %v", err)
	}

	if *insecure {
		warnTLSBypass()
	}

	resources, err := apiListResources(strings.TrimRight(*server, "/"), *token, *insecure)
	if err != nil {
		log.Fatalf("Échec: %v", err)
	}

	fmt.Printf("Ressources disponibles (%d):\n\n", len(resources))
	fmt.Printf("  %-4s %-25s %-10s %-25s %s\n", "ID", "Nom", "Protocole", "Cible", "Port")
	fmt.Printf("  %-4s %-25s %-10s %-25s %s\n", "──", "─────────────────────────", "──────────", "─────────────────────────", "────")
	for _, r := range resources {
		fmt.Printf("  %-4d %-25s %-10s %-25s %d\n", r.ID, r.Name, r.Protocol, r.Target, r.Port)
	}
}

func cmdConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	server := fs.String("server", "", "Backend URL")
	token := fs.String("token", "", "Token d'authentification (prefer EF_TOKEN env var)")
	resourceID := fs.Int("resource", 0, "ID de la ressource")
	localPort := fs.Int("local-port", 0, "Port local d'écoute")
	var rawTunnels tunnelFlag
	fs.Var(&rawTunnels, "tunnel", "Tunnel multi-instance au format resource_id:local_port (option répétable)")
	manage := fs.Bool("manage", false, "Activer la gestion à chaud des tunnels (add/remove/list/quit)")
	tui := fs.Bool("tui", false, "Afficher un tableau live des tunnels (state/TX/RX)")
	jsonLogs := fs.Bool("log-json", false, "Activer les logs structurés JSON")
	insecure := fs.Bool("insecure", false, "Ignorer la validation TLS (certificat auto-signé)")
	allowHTTP := fs.Bool("allow-http", false, "Autoriser HTTP non chiffré (lab seulement)")
	fs.Parse(args)

	// Allow token from env var or saved file
	if *token == "" {
		*token = os.Getenv("EF_TOKEN")
	}
	if *token == "" {
		if tok, err := loadTokenFromFile(); err == nil {
			*token = tok
		}
	}

	tunnelSpecs, specErr := parseTunnelSpecs(rawTunnels)
	if specErr != nil {
		log.Fatalf("Erreur --tunnel: %v", specErr)
	}

	if *server == "" || *token == "" || (len(tunnelSpecs) == 0 && (*resourceID == 0 || *localPort == 0)) {
		fmt.Fprintln(os.Stderr, "Erreur: --server, --token et (--resource+--local-port ou --tunnel) sont requis")
		fmt.Fprintln(os.Stderr, "Astuce: EF_TOKEN env var ou ~/.endoriumfort_token")
		fs.Usage()
		os.Exit(1)
	}
	allowInsecureHTTP := *allowHTTP || envBool("EF_ALLOW_INSECURE_HTTP")
	if err := enforceTransportSecurity(strings.TrimRight(*server, "/"), *insecure, allowInsecureHTTP); err != nil {
		log.Fatalf("Échec politique transport: %v", err)
	}

	var bindings []TunnelBinding
	if len(tunnelSpecs) > 0 {
		bindings = make([]TunnelBinding, 0, len(tunnelSpecs))
		for _, spec := range tunnelSpecs {
			bindings = append(bindings, TunnelBinding{
				Resource: Resource{
					ID:   spec.ResourceID,
					Name: fmt.Sprintf("resource-%d", spec.ResourceID),
				},
				LocalPort: spec.LocalPort,
			})
		}
	} else {
		bindings = []TunnelBinding{{
			Resource: Resource{
				ID:   *resourceID,
				Name: fmt.Sprintf("resource-%d", *resourceID),
			},
			LocalPort: *localPort,
		}}
	}

	if *insecure {
		warnTLSBypass()
	}
	useJSONLogs = *jsonLogs
	startTunnels(strings.TrimRight(*server, "/"), *token, bindings, *insecure, *manage, *tui)
}

// ─── Connection handler ─────────────────────────────────────────────────

func handleTunnelConnection(tcpConn net.Conn, manager *TunnelManager, rt *tunnelRuntime, resourceID, id int) {
	defer tcpConn.Close()
	defer rt.stats.activeConns.Add(-1)

	logEvent("info", "tunnel.connection.accepted", map[string]interface{}{"connId": id, "resourceId": resourceID, "remote": tcpConn.RemoteAddr().String(), "localPort": rt.binding.LocalPort})

	var wsConn *websocket.Conn
	var err error
	for attempt := 1; attempt <= 4; attempt++ {
		token := manager.currentToken()
		ticket, proof, challenge, signingKeyID, serverAttestation, sourceIP, _, ticketErr := apiIssueTunnelTicket(manager.serverURL, token, resourceID, manager.insecureTLS)
		if ticketErr != nil && strings.Contains(ticketErr.Error(), "HTTP 401") && manager.refreshTokenFromSources() {
			token = manager.currentToken()
			ticket, proof, challenge, signingKeyID, serverAttestation, sourceIP, _, ticketErr = apiIssueTunnelTicket(manager.serverURL, token, resourceID, manager.insecureTLS)
		}
		if ticketErr != nil {
			err = ticketErr
			rt.stats.state.Store("degraded")
			rt.stats.lastError.Store(ticketErr.Error())
		} else {
			wsURL := buildWSURL(manager.serverURL, resourceID, ticket)
			timestamp := strconv.FormatInt(time.Now().Unix(), 10)
			nonce, nonceErr := cryptoRandomHex(16)
			if nonceErr != nil {
				err = nonceErr
				rt.stats.lastError.Store(nonceErr.Error())
				break
			}
			signature := buildTunnelSignature(proof, ticket, resourceID, sourceIP, agentUserAgent(), challenge, signingKeyID, serverAttestation, timestamp, nonce)
			headers := http.Header{}
			headers.Set("User-Agent", agentUserAgent())
			headers.Set("X-EndoriumFort-Tunnel-Proof", proof)
			headers.Set("X-EndoriumFort-Tunnel-Challenge", challenge)
			headers.Set("X-EndoriumFort-Tunnel-Key-Id", signingKeyID)
			headers.Set("X-EndoriumFort-Tunnel-Attestation", serverAttestation)
			headers.Set("X-EndoriumFort-Tunnel-Timestamp", timestamp)
			headers.Set("X-EndoriumFort-Tunnel-Nonce", nonce)
			headers.Set("X-EndoriumFort-Tunnel-Signature", signature)
			wsConn, _, err = wsDialer(manager.insecureTLS).Dial(wsURL, headers)
			if err == nil {
				rt.stats.state.Store("healthy")
				rt.stats.lastError.Store("")
				break
			}
			rt.stats.state.Store("degraded")
			rt.stats.lastError.Store(err.Error())
		}

		if attempt < 4 {
			backoff := time.Duration(math.Pow(2, float64(attempt-1))) * 250 * time.Millisecond
			jitter := time.Duration(time.Now().UnixNano()%150) * time.Millisecond
			time.Sleep(backoff + jitter)
		}
	}
	if wsConn == nil {
		logEvent("error", "tunnel.connection.failed", map[string]interface{}{"connId": id, "resourceId": resourceID, "error": err.Error()})
		return
	}
	defer wsConn.Close()

	logEvent("info", "tunnel.connection.established", map[string]interface{}{"connId": id, "resourceId": resourceID, "localPort": rt.binding.LocalPort})

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP → WebSocket
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := tcpConn.Read(buf)
			if n > 0 {
				rt.stats.txBytes.Add(int64(n))
				if writeErr := wsConn.WriteMessage(websocket.BinaryMessage, buf[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				wsConn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
		}
	}()

	// WebSocket → TCP
	go func() {
		defer wg.Done()
		for {
			_, message, err := wsConn.ReadMessage()
			if err != nil {
				tcpConn.Close()
				return
			}
			rt.stats.rxBytes.Add(int64(len(message)))
			if _, writeErr := tcpConn.Write(message); writeErr != nil {
				return
			}
		}
	}()

	wg.Wait()
	logEvent("info", "tunnel.connection.closed", map[string]interface{}{"connId": id, "resourceId": resourceID, "localPort": rt.binding.LocalPort})
}

// ─── Prompt helpers ─────────────────────────────────────────────────────

func printBanner() {
	fmt.Println()
	fmt.Println("  ╔══════════════════════════════════════════════╗")
	fmt.Println("  ║       EndoriumFortAgent v" + version + "               ║")
	fmt.Println("  ║       Tunnel sécurisé vers vos ressources    ║")
	fmt.Println("  ╚══════════════════════════════════════════════╝")
	fmt.Println()
}

func prompt(reader *bufio.Reader, label string) string {
	fmt.Printf("  %s: ", label)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func promptWithDefault(reader *bufio.Reader, label, defaultVal string) string {
	fmt.Printf("  %s [%s]: ", label, defaultVal)
	line, _ := reader.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultVal
	}
	return line
}

func promptPasswordBytes(reader *bufio.Reader, label string) []byte {
	fmt.Printf("  %s: ", label)
	// Lire le mot de passe sans affichage (masqué)
	if term.IsTerminal(int(syscall.Stdin)) {
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // retour à la ligne après saisie
		if err != nil {
			log.Fatalf("Erreur de lecture du mot de passe: %v", err)
		}
		trimmed := strings.TrimSpace(string(pwBytes))
		zeroBytes(pwBytes)
		return []byte(trimmed)
	}
	// Fallback pour les entrées non-interactives (pipe, tests)
	line, _ := reader.ReadString('\n')
	return []byte(strings.TrimSpace(line))
}

func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func suggestLocalPort(targetPort int) int {
	if targetPort >= 1024 && targetPort <= 65535 {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", targetPort))
		if err == nil {
			ln.Close()
			return targetPort
		}
	}
	for _, port := range []int{8888, 9090, 8000, 8001, 3000} {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	return 8888
}

// ─── URL / string helpers ───────────────────────────────────────────────

func buildWSURL(server string, resourceID int, ticket string) string {
	u, err := url.Parse(server)
	if err != nil {
		log.Fatalf("URL serveur invalide: %v", err)
	}

	switch u.Scheme {
	case "https":
		u.Scheme = "wss"
	default:
		u.Scheme = "ws"
	}

	u.Path = "/ws/tunnel"
	q := u.Query()
	q.Set("resource_id", fmt.Sprintf("%d", resourceID))
	q.Set("ticket", ticket)
	u.RawQuery = q.Encode()

	return u.String()
}

func apiIssueTunnelTicket(serverURL, token string, resourceID int, insecureTLS bool) (ticket, proof, challenge, signingKeyID, serverAttestation, sourceIP, expiresAt string, err error) {
	body, _ := json.Marshal(map[string]int{"resourceId": resourceID})
	req, _ := http.NewRequest("POST", serverURL+"/api/tunnel/ticket", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", agentUserAgent())

	resp, err := httpClient(insecureTLS).Do(req)
	if err != nil {
		return "", "", "", "", "", "", "", fmt.Errorf("connexion impossible: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(resp.Body)
		return "", "", "", "", "", "", "", fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var result struct {
		Ticket       string `json:"ticket"`
		Proof        string `json:"proof"`
		Challenge    string `json:"challenge"`
		SigningKeyID string `json:"signingKeyId"`
		ServerAttestation string `json:"serverAttestation"`
		SourceIP     string `json:"sourceIp"`
		ExpiresAt    string `json:"expiresAt"`
	}
	if decErr := json.NewDecoder(resp.Body).Decode(&result); decErr != nil {
		return "", "", "", "", "", "", "", fmt.Errorf("réponse invalide: %v", decErr)
	}
	if strings.TrimSpace(result.Ticket) == "" {
		return "", "", "", "", "", "", "", fmt.Errorf("ticket tunnel manquant")
	}
	if strings.TrimSpace(result.Proof) == "" {
		return "", "", "", "", "", "", "", fmt.Errorf("preuve tunnel manquante")
	}
	if strings.TrimSpace(result.Challenge) == "" {
		return "", "", "", "", "", "", "", fmt.Errorf("challenge tunnel manquant")
	}
	if strings.TrimSpace(result.SigningKeyID) == "" {
		return "", "", "", "", "", "", "", fmt.Errorf("signingKeyId tunnel manquant")
	}
	if strings.TrimSpace(result.ServerAttestation) == "" {
		return "", "", "", "", "", "", "", fmt.Errorf("serverAttestation tunnel manquant")
	}
	if strings.TrimSpace(result.SourceIP) == "" {
		return "", "", "", "", "", "", "", fmt.Errorf("sourceIp tunnel manquant")
	}

	return result.Ticket, result.Proof, result.Challenge, result.SigningKeyID, result.ServerAttestation, result.SourceIP, result.ExpiresAt, nil
}

func cryptoRandomHex(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func buildTunnelSignature(proof, ticket string, resourceID int, sourceIP, userAgent, challenge, signingKeyID, serverAttestation, timestamp, nonce string) string {
	payload := fmt.Sprintf("ws_tunnel_v1|%s|%d|%s|%s|%s|%s|%s|%s|%s",
		ticket, resourceID, sourceIP, userAgent, challenge, signingKeyID, serverAttestation, timestamp, nonce)
	mac := hmac.New(sha256.New, []byte(proof))
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
