<div align="center">

# ⚡ PySecOps

### Plateforme de cybersécurité offensive & défensive

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![SQLite](https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Online-22c55e?style=for-the-badge)](https://pysecops.onrender.com)
[![Deploy](https://img.shields.io/badge/Deploy-Render-6366f1?style=for-the-badge&logo=render&logoColor=white)](https://pysecops.onrender.com)

<br/>

**[🌐 Démo en ligne](https://pysecops.onrender.com)** &nbsp;·&nbsp;
**[🐛 Signaler un bug](https://github.com/hyacinthe07/PySecOps/issues)** &nbsp;·&nbsp;
**[💡 Proposer une fonctionnalité](https://github.com/hyacinthe07/PySecOps/issues)**

<br/>

> **PySecOps** est une plateforme web complète de cybersécurité développée en Python/Flask,
> regroupant plus de **22 outils** utilisés lors d'audits de sécurité, de pentests et
> d'opérations SOC — accessible depuis n'importe quel navigateur.

</div>

---

## ⚠️ Avertissement légal

> Ce projet est destiné **exclusivement** à des fins éducatives et à des audits de sécurité
> réalisés sur des systèmes pour lesquels vous disposez d'une **autorisation explicite**.
> L'utilisation de PySecOps sur des systèmes tiers sans autorisation est **illégale**.
> L'auteur décline toute responsabilité en cas d'utilisation abusive ou malveillante.

---

## 📌 Présentation

PySecOps est né d'un projet CLI Python et a évolué en une véritable plateforme web
modulaire orientée cybersécurité. Il s'adresse aux :

- 🎓 **Étudiants** en cybersécurité qui veulent pratiquer sur un vrai projet
- 🔍 **Pentesters** qui cherchent un outil rapide accessible depuis un navigateur
- 🛡️ **Équipes SOC** qui veulent centraliser leurs outils d'analyse
- 👨‍💻 **Développeurs** qui veulent comprendre la sécurité applicative

---

## 🚀 Fonctionnalités

### 📊 Dashboard SOC
- Statistiques persistantes via SQLite (survivent aux redémarrages)
- Historique des 15 dernières analyses en temps réel
- Accès rapide à tous les modules
- Compteurs par catégorie d'outil

---

### 🔍 Analyse réseau

| Module | Description | URL |
|--------|-------------|-----|
| **Port Scanner** | Scan TCP multithreadé (150 workers) sur 1024 ports avec détection de services (FTP, SSH, HTTP...) | `/ports` |
| **WHOIS & DNS** | Lookup WHOIS complet + enregistrements A, AAAA, MX, NS, TXT, SOA, PTR + alertes SPF/DMARC | `/whois` |
| **IP Intelligence** | Géolocalisation, ASN, FAI, DNS inverse, détection proxy/VPN/hébergeur | `/ip-intel` |

---

### 🌐 Audit web

| Module | Description | URL |
|--------|-------------|-----|
| **Web Audit OWASP** | Vérification de 12 headers HTTP : CSP, HSTS, X-Frame-Options, Referrer-Policy... | `/owasp` |
| **SSL/TLS Scanner** | Analyse du certificat SSL : validité, expiration, protocole TLS, cipher, SANs | `/secops/ssl` |
| **Détecteur de phishing** | Score de risque d'une URL sur 8 critères : TLD, IP, mots suspects, imitation marques | `/secops/phishing` |

---

### 🔐 Crypto & SecOps

| Module | Description | URL |
|--------|-------------|-----|
| **Analyse de mot de passe** | Score, entropie, temps de cassage estimé, 10 critères, jauge temps réel via API | `/secops/password-check` |
| **Vérificateur de fuite** | API HaveIBeenPwned avec protocole k-anonymity — le mot de passe n'est jamais envoyé | `/secops/fuite` |
| **Détecteur de hash** | Identification automatique : MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, Argon2... | `/secops/hash-detect` |
| **Générateur de secrets** | Clés AES-128/256, JWT, Flask SECRET\_KEY, Django SECRET\_KEY, UUID, API Key | `/secops/keygen` |
| **Encodeur multi-format** | Base64, Hexadécimal, URL encoding, ROT13, Binaire, Code Morse, Chiffre de César | `/secops/encoder` |
| **Intégrité de fichier** | Calcul MD5/SHA1/SHA256/SHA512 d'un fichier + comparaison avec hash de référence | `/secops/integrity` |
| **QR Code** | Génération (URL, WiFi, vCard, Email, Téléphone) + analyse et détection de risques | `/secops/qrcode` |

---

### 🤖 Outils intelligents

| Module | Description | URL |
|--------|-------------|-----|
| **Assistant cybersécurité** | Chatbot local répondant à 16+ sujets : XSS, ransomware, MFA, VPN, OWASP... | `/assistant` |
| **Log Analyzer** | Détection d'IPs suspectes et d'intrusions dans les fichiers de logs (3 niveaux de gravité) | `/logs` |
| **Rapports PDF** | Export professionnel des résultats — SSL, OWASP, Ports, WHOIS, IP Intelligence | `/rapport/*` |

---

## 🛠️ Stack technique

```
Backend        Python 3.10+ / Flask 3.x / Architecture Blueprints
Base de données SQLite — persistance des statistiques et historique
Réseau         socket, dnspython, python-whois, requests
Cryptographie  hashlib, secrets, cryptography
QR Code        qrcode[pil], Pillow
PDF            ReportLab
Frontend       HTML5 / CSS3 vanilla / JavaScript ES6 (aucun framework)
Déploiement    Render (cloud PaaS) / Gunicorn (WSGI)
```

---

## 📁 Architecture du projet

```
PySecOps/
├── app.py                       # Point d'entrée Flask + init SQLite
├── requirements.txt
├── pysecops.db                  # Base SQLite (générée au démarrage)
│
├── app/
│   ├── blueprints/              # Un Blueprint par module
│   │   ├── home.py              # Dashboard SOC
│   │   ├── ports.py             # Port Scanner multithreadé
│   │   ├── logs.py              # Log Analyzer
│   │   ├── secops.py            # Crypto & SecOps (9 outils)
│   │   ├── owasp.py             # Web Audit OWASP
│   │   ├── network.py           # WHOIS & DNS + IP Intelligence
│   │   ├── rapports.py          # Génération rapports PDF
│   │   ├── qrcode_bp.py         # QR Code
│   │   └── assistant.py         # Assistant cybersécurité
│   │
│   ├── utils/                   # Logique métier séparée des routes
│   │   ├── secops_utils.py      # Crypto, hash, fuite, phishing
│   │   ├── network_utils.py     # WHOIS, DNS, géolocalisation IP
│   │   ├── pdf_utils.py         # Génération rapports PDF
│   │   ├── qrcode_utils.py      # QR Code génération & analyse
│   │   └── db_utils.py          # SQLite — persistance des stats
│   │
│   ├── templates/               # Templates Jinja2 séparés par module
│   │   ├── layout.html          # Layout commun avec sidebar
│   │   ├── home.html            # Dashboard SOC
│   │   ├── scanner.html         # Port Scanner
│   │   ├── logs.html            # Log Analyzer
│   │   ├── owasp.html           # Web Audit OWASP
│   │   ├── assistant.html       # Chatbot
│   │   ├── secops/              # 9 templates Crypto & SecOps
│   │   └── network/             # WHOIS & IP Intelligence
│   │
│   └── static/
│       └── css/
│           └── style.css        # Design dark mode complet (600+ lignes)
│
└── tests/                       # Tests unitaires (roadmap)
```

---

## ⚙️ Installation locale

```bash
# 1. Cloner le dépôt
git clone https://github.com/hyacinthe07/PySecOps.git
cd PySecOps

# 2. Créer un environnement virtuel
python -m venv venv
source venv/bin/activate       # Linux / macOS
# venv\Scripts\activate        # Windows

# 3. Installer les dépendances
pip install -r requirements.txt

# 4. Lancer l'application
python app.py

# 5. Ouvrir dans le navigateur
# http://localhost:8080
```

---

## 🌐 Déploiement sur Render

Le projet se déploie automatiquement à chaque `git push` via GitHub → Render.

| Paramètre | Valeur |
|-----------|--------|
| Build Command | `pip install -r requirements.txt` |
| Start Command | `gunicorn app:app` |
| Python Version | `3.11` |
| URL | `https://pysecops.onrender.com` |

---

## 🗺️ Roadmap

- [ ] Tests unitaires avec pytest
- [ ] Authentification utilisateur (login / logout)
- [ ] Historique complet des scans par utilisateur
- [ ] Export CSV des résultats
- [ ] Mode CLI via argparse
- [ ] API REST publique documentée (Swagger / OpenAPI)
- [ ] Module Traceroute visuel avec carte
- [ ] Intégration API VirusTotal (analyse de fichiers)
- [ ] Notifications email sur alertes critiques
- [ ] Version Docker (Dockerfile + docker-compose)

---

## 🤝 Contribuer

Les contributions sont les bienvenues !

```bash
# 1. Forker le projet sur GitHub

# 2. Créer une branche pour votre fonctionnalité
git checkout -b feature/nom-du-module

# 3. Coder et commiter
git add .
git commit -m "feat: description claire de l'ajout"

# 4. Pousser et ouvrir une Pull Request
git push origin feature/nom-du-module
```

Conventions de commit :
- `feat:` — nouvelle fonctionnalité
- `fix:` — correction de bug
- `docs:` — documentation
- `refactor:` — refactoring sans changement fonctionnel

---

## 📄 Licence

Ce projet est distribué sous licence **MIT**.
Voir le fichier [LICENSE](LICENSE) pour les détails complets.

---

<div align="center">

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/9d5305fc-c13e-4e1f-8178-5af3ffde0862" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/c896ca26-fbba-492f-87ce-25e6536f99fd" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/09169216-9742-4366-9341-f030cb97e1af" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/5e4c86c6-41ab-4942-9bd3-38b2ec8b5e73" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/f5849175-b422-4dc1-978c-5e53f2b05409" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/73a4589d-69ac-4d60-b119-cbe041074fcd" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/66e8bc91-3441-45e5-957f-bddfe44ec56d" />

<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/cdbaba4a-bd56-4d41-b2db-8bb88a613e65" />




Développé avec ❤️ par **[Hyacinthe](https://github.com/hyacinthe07)**

*Security is not a product, it's a process.*

⭐ **Si ce projet vous a été utile, n'oubliez pas de lui mettre une étoile !** ⭐

</div><div align="center">
