package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/term"
)

// version is set at build time via: go build -ldflags "-X main.version=x.y.z"
var version = "0.3.0"

// ─── Types ──────────────────────────────────────────────────────────────

type Resource struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Target   string `json:"target"`
	Port     int    `json:"port"`
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
  endoriumfort-agent connect --server http://bastion:8080 --token eft_xxxx --resource 3 --local-port 8888`)
}

// ─── INTERACTIVE MODE ───────────────────────────────────────────────────

func interactiveMode() {
	reader := bufio.NewReader(os.Stdin)

	printBanner()

	// Step 1: Server URL
	serverURL := promptWithDefault(reader, "Adresse du serveur EndoriumFort", "http://localhost:8080")
	serverURL = strings.TrimRight(serverURL, "/")

	// Verify server is reachable
	fmt.Printf("\n  Vérification du serveur... ")
	healthURL := serverURL + "/api/health"
	healthResp, err := http.Get(healthURL)
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
	password := promptPassword(reader, "Mot de passe")

	fmt.Printf("\n  Authentification... ")
	token, role, err := apiLogin(serverURL, username, password)
	if err != nil {
		fmt.Printf("✗\n")
		log.Fatalf("  Échec: %v", err)
	}
	fmt.Printf("✓\n")
	fmt.Printf("  Connecté en tant que %s (rôle: %s)\n\n", username, role)

	// Step 3: List resources
	fmt.Printf("  Chargement des ressources... ")
	resources, err := apiListResources(serverURL, token)
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
	startTunnel(serverURL, token, selected, localPort)
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

// ─── API helpers ────────────────────────────────────────────────────────

func apiLogin(serverURL, user, password string) (token, role string, err error) {
	body, _ := json.Marshal(map[string]string{
		"user":     user,
		"password": password,
	})

	resp, err := http.Post(
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

func apiListResources(serverURL, token string) ([]Resource, error) {
	req, _ := http.NewRequest("GET", serverURL+"/api/resources", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
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

func startTunnel(serverURL, token string, resource Resource, localPort int) {
	listenAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
	wsURL := buildWSURL(serverURL, token, resource.ID)

	// Test connection
	log.Printf("Vérification du tunnel vers %s...", resource.Name)
	testConn, httpResp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		if httpResp != nil {
			body, _ := io.ReadAll(httpResp.Body)
			log.Fatalf("Tunnel impossible: %v (HTTP %d: %s)", err, httpResp.StatusCode, string(body))
		}
		log.Fatalf("Tunnel impossible: %v", err)
	}
	testConn.Close()

	// Listen
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Impossible d'écouter sur %s: %v", listenAddr, err)
	}
	defer listener.Close()

	log.Printf("╔══════════════════════════════════════════════════╗")
	log.Printf("║  EndoriumFortAgent — Tunnel actif                ║")
	log.Printf("║                                                  ║")
	log.Printf("║  Ressource: %-37s║", truncStr(resource.Name, 37))
	log.Printf("║  Adresse:   %-37s║", fmt.Sprintf("http://127.0.0.1:%d", localPort))
	log.Printf("║  Cible:     %-37s║", fmt.Sprintf("%s:%d", resource.Target, resource.Port))
	log.Printf("║                                                  ║")
	log.Printf("║  Ouvrez cette adresse dans votre navigateur.     ║")
	log.Printf("║  Ctrl+C pour arrêter.                            ║")
	log.Printf("╚══════════════════════════════════════════════════╝")

	// Ctrl+C
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Arrêt du tunnel...")
		listener.Close()
		os.Exit(0)
	}()

	var connID int
	for {
		tcpConn, err := listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed") {
				break
			}
			log.Printf("Erreur accept: %v", err)
			continue
		}
		connID++
		go handleTunnelConnection(tcpConn, wsURL, connID)
	}
}

// ─── CLI commands (kept for scripting / automation) ─────────────────────

func cmdLogin(args []string) {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	server := fs.String("server", "", "Backend URL (ex: http://bastion:8080)")
	user := fs.String("user", "", "Nom d'utilisateur")
	password := fs.String("password", "", "Mot de passe (prefer EF_PASSWORD env var)")
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

	warnIfInsecure(*server)

	token, role, err := apiLogin(strings.TrimRight(*server, "/"), *user, *password)
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
	fmt.Printf("  Token complet sauvegardé dans: ~/.endoriumfort_token\n")

	// Save token to file with restricted permissions
	home, _ := os.UserHomeDir()
	if home != "" {
		tokenFile := home + "/.endoriumfort_token"
		os.WriteFile(tokenFile, []byte(token), 0600)
	}
}

func cmdList(args []string) {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	server := fs.String("server", "", "Backend URL")
	token := fs.String("token", "", "Token d'authentification (prefer EF_TOKEN env var)")
	fs.Parse(args)

	// Allow token from env var or saved file
	if *token == "" {
		*token = os.Getenv("EF_TOKEN")
	}
	if *token == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			data, err := os.ReadFile(home + "/.endoriumfort_token")
			if err == nil {
				*token = strings.TrimSpace(string(data))
			}
		}
	}

	if *server == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "Erreur: --server et --token sont requis")
		fmt.Fprintln(os.Stderr, "Astuce: EF_TOKEN env var ou ~/.endoriumfort_token")
		fs.Usage()
		os.Exit(1)
	}

	resources, err := apiListResources(strings.TrimRight(*server, "/"), *token)
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
	fs.Parse(args)

	// Allow token from env var or saved file
	if *token == "" {
		*token = os.Getenv("EF_TOKEN")
	}
	if *token == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			data, err := os.ReadFile(home + "/.endoriumfort_token")
			if err == nil {
				*token = strings.TrimSpace(string(data))
			}
		}
	}

	if *server == "" || *token == "" || *resourceID == 0 || *localPort == 0 {
		fmt.Fprintln(os.Stderr, "Erreur: --server, --token, --resource et --local-port sont requis")
		fmt.Fprintln(os.Stderr, "Astuce: EF_TOKEN env var ou ~/.endoriumfort_token")
		fs.Usage()
		os.Exit(1)
	}

	resource := Resource{ID: *resourceID, Name: fmt.Sprintf("resource-%d", *resourceID)}
	startTunnel(strings.TrimRight(*server, "/"), *token, resource, *localPort)
}

// ─── Connection handler ─────────────────────────────────────────────────

func handleTunnelConnection(tcpConn net.Conn, wsURL string, id int) {
	defer tcpConn.Close()

	log.Printf("[conn-%d] Nouvelle connexion depuis %s", id, tcpConn.RemoteAddr())

	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   16384,
		WriteBufferSize:  16384,
	}

	wsConn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		log.Printf("[conn-%d] Échec WebSocket: %v", id, err)
		return
	}
	defer wsConn.Close()

	log.Printf("[conn-%d] Tunnel établi", id)

	var wg sync.WaitGroup
	wg.Add(2)

	// TCP → WebSocket
	go func() {
		defer wg.Done()
		buf := make([]byte, 16384)
		for {
			n, err := tcpConn.Read(buf)
			if n > 0 {
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
			if _, writeErr := tcpConn.Write(message); writeErr != nil {
				return
			}
		}
	}()

	wg.Wait()
	log.Printf("[conn-%d] Connexion terminée", id)
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

func promptPassword(reader *bufio.Reader, label string) string {
	fmt.Printf("  %s: ", label)
	// Lire le mot de passe sans affichage (masqué)
	if term.IsTerminal(int(syscall.Stdin)) {
		pwBytes, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println() // retour à la ligne après saisie
		if err != nil {
			log.Fatalf("Erreur de lecture du mot de passe: %v", err)
		}
		return strings.TrimSpace(string(pwBytes))
	}
	// Fallback pour les entrées non-interactives (pipe, tests)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
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

func buildWSURL(server, token string, resourceID int) string {
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
	q.Set("token", token)
	q.Set("resource_id", fmt.Sprintf("%d", resourceID))
	u.RawQuery = q.Encode()

	return u.String()
}

func truncStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
