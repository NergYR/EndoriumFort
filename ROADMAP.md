# Roadmap EndoriumFort

Ce document trace la route pour le développement d'EndoriumFort vers une solution complète de gestion des accès privilégiés (PAM/Bastion).

## ✅ v0.1.0 - MVP (Réalisé)
- [x] Structure du projet Backend C++ (Crow) et Frontend React (Vite).
- [x] Système de build (CMake).
- [x] Base de données SQLite initiale.
- [x] Dashboard de base.
- [x] TOTP 2FA (RFC 6238) avec SHA1/HMAC-SHA1 intégré.
- [x] Enregistrement des sessions SSH (format Asciinema v2 .cast).
- [x] Stub RDP/WebSocket (framework FreeRDP optionnel).
- [x] RBAC (admin, auditor, operator, user).

## ✅ v0.2.0 - Sécurité & UX Base (Réalisé)
- [x] Hashage des mots de passe (SHA-256 + Salt, 10000 itérations).
- [x] Gestion des sessions (Expiration token 1h, Logout serveur).
- [x] Audit Logs améliorés (Login/Logout/Fail/2FA).
- [x] Dark Mode (persisté localStorage).
- [x] Changement de mot de passe utilisateur.
- [x] Politique de mot de passe (min 8, maj+min+chiffre).
- [x] Terminal SSH xterm.js via WebSocket + libssh2.
- [x] Web Proxy HTTP intégré.
- [x] Tunnels TCP.

---

## ✅ v0.3.0 - Coffre-fort, Dashboard & Observation (Réalisé)
Enrichissement de l'expérience opérateur et des fonctionnalités de supervision.
- [x] **Coffre-fort d'identifiants** : Champs `sshUsername` / `sshPassword` sur les ressources, stockés en base.
- [x] **Injection automatique** : Connexion SSH auto-remplit les identifiants depuis le coffre-fort.
- [x] **API Credentials** : `GET /api/resources/<id>/credentials` avec audit d'accès (admin/auditor).
- [x] **Dashboard statistiques** : 6 KPI (sessions actives, totales, ressources, utilisateurs, recordings, tokens).
- [x] **Lecteur animé Asciinema** : Player xterm.js intégré avec Play/Pause/Close (timing réel).
- [x] **Recherche & filtres audit** : Recherche texte + filtre par type d'événement.
- [x] **Session Shadowing** : Observation temps réel des sessions SSH en lecture seule.
  - Route WebSocket `/api/ws/shadow` avec authentification et audit.
  - Broadcast depuis le reader thread SSH vers les observateurs.
  - UI dédiée avec indicateur "SHADOW MODE" et terminal read-only.
  - Accessible aux rôles admin et auditor.

## 🔮 v0.4.0 - Chiffrement & Sécurité Avancée
- [ ] **Chiffrement AES-256** des mots de passe du coffre-fort (Master Key).
- [ ] **Rotation automatique** des identifiants stockés.
- [ ] **Détection d'anomalies** : alertes sur comportements suspects (horaires inhabituels, commandes dangereuses).
- [ ] **Rate limiting** sur les endpoints d'authentification.
- [ ] **CSP headers** et hardening HTTP.

## 🔮 v0.5.0 - Multi-protocoles & Intégrations
- [ ] **RDP complet** : Intégration FreeRDP avec streaming bitmap via WebSocket.
- [ ] **VNC** : Support basique via libvncclient.
- [ ] **LDAP/AD** : Authentification externe via annuaire.
- [ ] **SAML/OIDC** : SSO entreprise.

## 🔮 v0.6.0 - Gouvernance & Politiques
- [ ] **Politiques d'accès** : Règles temporelles (créneaux horaires), IP source autorisée.
- [ ] **Workflow d'approbation** : Demande d'accès avec validation par un admin.
- [ ] **Groupes de ressources** : Organisation hiérarchique des assets.
- [ ] **Export audit** : CSV/PDF des logs d'audit.

## 🔮 v1.0.0 - Release Stable
- [ ] Documentation complète (API, déploiement, administration).
- [ ] Images Docker optimisées (multi-stage build).
- [ ] Tests de pénétration et hardening.
- [ ] Tests unitaires et d'intégration automatisés.
- [ ] Interface responsive mobile.
