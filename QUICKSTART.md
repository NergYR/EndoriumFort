# 🚀 QuickStart EndoriumFort v0.0.14

## 30 Secondes pour Démarrer

### 1. Lancer les services
```bash
cd /home/energetiq/EndoriumFort
./run-dev.sh
```

Cela va:
- Recompiler le backend (make)
- Démarrer backend sur http://localhost:8080
- Démarrer frontend (Vite) sur http://localhost:5173
- Afficher les logs

### 2. Ouvrir dans le navigateur
Allez à: **http://localhost:5173**

### 3. Se connecter
- Username: `admin`
- Password: `admin`

### 4. Essayer le proxy
1. Aller à **Dashboard**
2. Voir ressource "Test Web" (httpbin.org)
3. Cliquer **"Connect"**
4. Ressource web s'ouvre dans iframe

---

## Vérifier le Status

```bash
./status.sh
```

Affiche:
- Backend status
- Frontend status
- Tests API rapides
- Credentials
- Commandes utiles

---

## Tester en Ligne de Commande

```bash
# Obtenir token
TOKEN=$(curl -s http://localhost:8080/api/auth/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"admin","password":"admin"}' | grep -o '"token":"[^"]*"' | cut -d'"' -f4)

# Tester proxy GET
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:8080/proxy/1/get

# Tester proxy POST
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -d '{"test":"data"}' \
  http://localhost:8080/proxy/1/post
```

---

## Structure Application

### Dashboard (Route: `/`)
- Vue des ressources disponibles
- Bouton "Connect" pour chaque ressource
- Status des sessions

### Admin Console (Route: `/admin`)
- Gestion des utilisateurs
- Gestion des ressources
- Gestion des permissions
- Audit log viewer

### Web Proxy Viewer (Route: `/webproxy`)
- Affiche ressources web en iframe
- Toutes requêtes tunnelées via bastion
- Utilisation transparente

### SSH Console
- Affichée dans panel "Live SSH console"
- WebSocket connection
- Terminal émulation avec xterm.js

---

## Fichiers Importants

```
/home/energetiq/EndoriumFort/
├── backend/
│   ├── src/main.cc              # API backend (2600 lignes)
│   ├── build/endoriumfort_backend # Binary compilé
│   ├── CMakeLists.txt            # Build config
│   └── VERSION                    # Auto-incremented
│
├── frontend/
│   ├── src/App.jsx               # Main app (1276 lignes)
│   ├── src/WebProxyViewer.jsx    # Proxy viewer (NEW)
│   ├── src/api.js                # API client
│   ├── package.json              # Dependencies
│   └── vite.config.js            # Build config
│
├── run-dev.sh                    # Dev launcher (NEW)
├── status.sh                     # Status checker (NEW)
├── test-integration.sh           # Test suite (NEW)
│
└── Documentation/
    ├── README.md                 # Main docs
    ├── IMPLEMENTATION_COMPLETE.md # This delivery (NEW)
    ├── PROXY_IMPLEMENTATION.md   # Proxy docs (NEW)
    └── FEATURES.md               # All features
```

---

## Dépannage

### Backend ne démarre pas
```bash
# Port 8080 déjà utilisé?
lsof -i :8080
# Tuer le processus
pkill -9 -f endoriumfort_backend

# Recompiler
cd backend/build
make clean
make -j$(nproc)
./endoriumfort_backend
```

### Frontend ne se charge pas
```bash
# Nettoyer cache Vite
cd frontend
rm -rf node_modules/.vite
npm run dev
```

### Proxy retourne erreur 403
```bash
# Vérifier permissions user
# Aller Admin Console → User Permissions
# Cocher la ressource pour l'utilisateur
```

### API retourne 500
```bash
# Vérifier les logs backend
tail -f /tmp/backend.log

# Vérifier token valide
TOKEN="tok-1234"
echo "Bearer $TOKEN"
```

---

## Documentation Complète

| Doc | Contenu |
|-----|---------|
| [README.md](README.md) | Vue d'ensemble, architecture |
| [IMPLEMENTATION_COMPLETE.md](IMPLEMENTATION_COMPLETE.md) | Détails implémentation |
| [PROXY_IMPLEMENTATION.md](PROXY_IMPLEMENTATION.md) | Guide complet proxy |
| [FEATURES.md](FEATURES.md) | Liste toutes features |
| [CHANGELOG.md](CHANGELOG.md) | Historique versions |

---

## Cas D'Usage

### 1. Créer Ressource HTTP
```
Admin Console → Resources
+ New Resource
- Name: "Internal Wiki"
- Protocol: http
- Target: 192.168.1.100
- Port: 8080
Save
```

### 2. Assigner Permissions
```
Admin Console → Users
Select User → Permissions
Check "Internal Wiki"
Save
```

### 3. Utilisateur Accède
```
Dashboard → Click "Internal Wiki"
Page s'ouvre dans iframe
Toutes requêtes via bastion
```

---

## API Endpoints

```
Auth
  POST /api/auth/login

Resources
  GET /api/resources
  POST /api/resources
  
Proxy (NEW)
  GET|POST|PUT|DELETE /proxy/{id}/*
  
Sessions
  GET|POST /api/sessions
  
Users
  GET|POST|PUT|DELETE /api/users
  
Audit
  GET /api/audit
```

---

## Support

Pour des questions ou issues:
1. Vérifier [README.md](README.md)
2. Lire [PROXY_IMPLEMENTATION.md](PROXY_IMPLEMENTATION.md)
3. Consulter [DELIVERY_SUMMARY.md](../DELIVERY_SUMMARY.md)
4. Exécuter `./status.sh` pour diagnostiquer

---

**Version:** 0.0.14 | **Date:** 2026-02-15 | **Status:** ✅ Production Ready

