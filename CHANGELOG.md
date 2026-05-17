# Changelog — PySecOps

Toutes les modifications notables de ce projet sont documentées ici.
Format basé sur [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/).

---

## [2.0.0] — 2025

### Ajouté
- Architecture complète Flask Blueprints (un fichier par module)
- **Dashboard SOC** avec statistiques persistantes SQLite
- **Port Scanner** multithreadé 150 workers — scan 1024 ports
- **WHOIS & DNS** — lookup complet avec alertes SPF/DMARC
- **IP Intelligence** — géolocalisation + ASN + détection proxy/VPN
- **SSL/TLS Scanner** — certificat, expiration, protocole, cipher
- **Web Audit OWASP** — 12 vérifications de headers HTTP
- **Log Analyzer** — détection IPs suspectes avec niveaux de gravité
- **Crypto & SecOps** — 9 outils regroupés :
  - Vérificateur de fuite (HaveIBeenPwned API k-anonymity)
  - Détecteur automatique de type de hash
  - Générateur de secrets (AES, JWT, Flask, Django, UUID)
  - Analyse avancée de mot de passe (entropie + temps de cassage)
  - Encodeur multi-format (Base64, Hex, URL, ROT13, Binaire, Morse)
  - Scanner SSL/TLS
  - Vérificateur d'intégrité de fichier (MD5/SHA1/SHA256/SHA512)
  - Détecteur de phishing (score de risque URL)
  - Générateur & analyseur QR Code
- **Rapports PDF** professionnels (ReportLab) — 5 modules exportables
- **Assistant cybersécurité** — chatbot local 16+ sujets
- Design dark mode complet CSS vanilla
- Déploiement Render + Gunicorn

### Modifié
- Refactoring complet depuis `app.py` monolithique (277 lignes)
- Séparation logique métier (`utils/`) et routes (`blueprints/`)
- Templates Jinja2 séparés par module

### Supprimé
- Ancien CLI (main.py, scanner.py, analyser.py, securite.py, vuln_scanner.py)

---

## [1.0.0] — 2024

### Ajouté
- Premier outil CLI Python de cybersécurité
- Scanner de ports basique
- Analyseur de logs simple
- Vérificateur de mots de passe
- Scanner de vulnérabilités web (headers HTTP)
- Interface Rich (terminal coloré)
- Première version web Flask (app.py monolithique)
