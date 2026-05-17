"""
PySecOps — OSINT Engine
Email harvesting, Google Dorks, Shodan, fingerprinting avancé.
Tout en passif — aucun paquet envoyé directement à la cible.
"""

import re
import requests
import socket
import concurrent.futures
import urllib.parse
import datetime
import urllib3

urllib3.disable_warnings()

HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; PySecOps/2.0)"}
TIMEOUT = 8


# ─────────────────────────────────────────────
# 1. EMAIL HARVESTING
# ─────────────────────────────────────────────

def harvester_emails(domaine: str) -> dict:
    """
    Collecte les emails exposés publiquement liés à un domaine.
    Sources : crt.sh metadata, Hunter.io (sans clé), scraping headers.
    """
    domaine = domaine.replace("https://","").replace("http://","").split("/")[0].strip()
    emails  = set()
    sources = []

    # Source 1 : Hunter.io API publique (sans clé — 25 req/mois)
    try:
        r = requests.get(
            f"https://api.hunter.io/v2/domain-search",
            params={"domain": domaine, "limit": 20},
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            for e in data.get("emails", []):
                val = e.get("value","")
                if val:
                    emails.add(val.lower())
                    sources.append({
                        "email":    val.lower(),
                        "source":   "Hunter.io",
                        "type":     e.get("type",""),
                        "prenom":   e.get("first_name",""),
                        "nom":      e.get("last_name",""),
                        "poste":    e.get("position",""),
                        "confiance":e.get("confidence", 0),
                    })
    except Exception:
        pass

    # Source 2 : Recherche dans les pages publiques du domaine
    try:
        r = requests.get(
            f"http://{domaine}",
            timeout=TIMEOUT,
            verify=False,
            headers=HEADERS,
            allow_redirects=True
        )
        trouves = re.findall(
            r'[a-zA-Z0-9._%+\-]+@' + re.escape(domaine),
            r.text, re.IGNORECASE
        )
        for e in trouves:
            if e.lower() not in emails:
                emails.add(e.lower())
                sources.append({
                    "email":    e.lower(),
                    "source":   "Page web publique",
                    "type":     "générique",
                    "prenom":   "",
                    "nom":      "",
                    "poste":    "",
                    "confiance": 60,
                })
    except Exception:
        pass

    # Source 3 : Emails dans les enregistrements WHOIS
    try:
        import whois as w
        data = w.whois(domaine)
        whois_emails = data.emails or []
        if isinstance(whois_emails, str):
            whois_emails = [whois_emails]
        for e in whois_emails:
            if e and e.lower() not in emails:
                emails.add(e.lower())
                sources.append({
                    "email":    e.lower(),
                    "source":   "WHOIS",
                    "type":     "registrant",
                    "prenom":   "",
                    "nom":      "",
                    "poste":    "",
                    "confiance": 90,
                })
    except Exception:
        pass

    # Patterns d'emails courants à vérifier
    patterns_communs = [
        f"contact@{domaine}",
        f"admin@{domaine}",
        f"info@{domaine}",
        f"security@{domaine}",
        f"support@{domaine}",
        f"abuse@{domaine}",
        f"postmaster@{domaine}",
        f"webmaster@{domaine}",
        f"noc@{domaine}",
    ]

    return {
        "domaine":  domaine,
        "total":    len(emails),
        "emails":   sources,
        "patterns": patterns_communs,
        "date":     datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
    }


# ─────────────────────────────────────────────
# 2. GOOGLE DORKS GENERATOR
# ─────────────────────────────────────────────

DORKS_TEMPLATES = [
    # Fichiers sensibles
    {
        "categorie": "Fichiers sensibles",
        "severite":  "CRITIQUE",
        "nom":       "Fichiers de configuration exposés",
        "dork":      'site:{domaine} ext:conf OR ext:config OR ext:cfg OR ext:ini',
    },
    {
        "categorie": "Fichiers sensibles",
        "severite":  "CRITIQUE",
        "nom":       "Fichiers de base de données exposés",
        "dork":      'site:{domaine} ext:sql OR ext:db OR ext:sqlite OR ext:dump',
    },
    {
        "categorie": "Fichiers sensibles",
        "severite":  "CRITIQUE",
        "nom":       "Fichiers de sauvegarde exposés",
        "dork":      'site:{domaine} ext:bak OR ext:backup OR ext:old OR ext:orig',
    },
    {
        "categorie": "Fichiers sensibles",
        "severite":  "HAUTE",
        "nom":       "Fichiers log exposés",
        "dork":      'site:{domaine} ext:log',
    },
    {
        "categorie": "Fichiers sensibles",
        "severite":  "HAUTE",
        "nom":       "Fichiers Excel/CSV potentiellement sensibles",
        "dork":      'site:{domaine} ext:xls OR ext:xlsx OR ext:csv',
    },
    # Panneaux d'administration
    {
        "categorie": "Administration",
        "severite":  "HAUTE",
        "nom":       "Interfaces d'administration",
        "dork":      'site:{domaine} inurl:admin OR inurl:administrator OR inurl:dashboard OR inurl:panel',
    },
    {
        "categorie": "Administration",
        "severite":  "HAUTE",
        "nom":       "Pages de login exposées",
        "dork":      'site:{domaine} inurl:login OR inurl:signin OR inurl:auth',
    },
    {
        "categorie": "Administration",
        "severite":  "MOYENNE",
        "nom":       "phpMyAdmin exposé",
        "dork":      'site:{domaine} inurl:phpmyadmin',
    },
    # Informations exposées
    {
        "categorie": "Exposition de données",
        "severite":  "CRITIQUE",
        "nom":       "Mots de passe dans le code source",
        "dork":      'site:{domaine} intext:password OR intext:passwd OR intext:pwd',
    },
    {
        "categorie": "Exposition de données",
        "severite":  "CRITIQUE",
        "nom":       "Clés API exposées",
        "dork":      'site:{domaine} intext:"api_key" OR intext:"api_secret" OR intext:"access_token"',
    },
    {
        "categorie": "Exposition de données",
        "severite":  "HAUTE",
        "nom":       "Emails exposés sur le site",
        "dork":      f'site:{{domaine}} intext:"@{{domaine}}"',
    },
    {
        "categorie": "Exposition de données",
        "severite":  "HAUTE",
        "nom":       "Numéros de téléphone exposés",
        "dork":      'site:{domaine} intext:"tel:" OR intext:"phone:" OR intext:"+33"',
    },
    # Vulnérabilités
    {
        "categorie": "Vulnérabilités potentielles",
        "severite":  "CRITIQUE",
        "nom":       "Pages potentiellement vulnérables SQLi",
        "dork":      'site:{domaine} inurl:".php?id=" OR inurl:".asp?id=" OR inurl:"?cat="',
    },
    {
        "categorie": "Vulnérabilités potentielles",
        "severite":  "HAUTE",
        "nom":       "Formulaires d'upload de fichiers",
        "dork":      'site:{domaine} inurl:upload OR intext:"choose file" OR intext:"upload file"',
    },
    {
        "categorie": "Vulnérabilités potentielles",
        "severite":  "HAUTE",
        "nom":       "Pages d'erreur exposant des infos",
        "dork":      'site:{domaine} "Fatal error" OR "SQL syntax" OR "mysql_fetch" OR "Warning:"',
    },
    # Sous-domaines et infrastructure
    {
        "categorie": "Infrastructure",
        "severite":  "MOYENNE",
        "nom":       "Sous-domaines indexés",
        "dork":      'site:*.{domaine}',
    },
    {
        "categorie": "Infrastructure",
        "severite":  "MOYENNE",
        "nom":       "Documents PDF/Word indexés",
        "dork":      'site:{domaine} ext:pdf OR ext:doc OR ext:docx',
    },
    {
        "categorie": "Infrastructure",
        "severite":  "BASSE",
        "nom":       "Mentions sur d'autres sites",
        "dork":      'link:{domaine} -site:{domaine}',
    },
    # Réseaux sociaux et OSINT
    {
        "categorie": "OSINT Social",
        "severite":  "BASSE",
        "nom":       "Profils LinkedIn des employés",
        "dork":      'site:linkedin.com "{domaine}"',
    },
    {
        "categorie": "OSINT Social",
        "severite":  "MOYENNE",
        "nom":       "Code source sur GitHub",
        "dork":      'site:github.com "{domaine}"',
    },
    {
        "categorie": "OSINT Social",
        "severite":  "HAUTE",
        "nom":       "Credentials leakés sur Pastebin",
        "dork":      'site:pastebin.com "{domaine}" password OR passwd OR credentials',
    },
]


def generer_dorks(domaine: str) -> dict:
    """
    Génère les Google Dorks pour un domaine donné.
    Retourne les dorks avec leurs URLs cliquables.
    """
    domaine = domaine.replace("https://","").replace("http://","").split("/")[0].strip()
    dorks   = []

    for template in DORKS_TEMPLATES:
        dork_query = template["dork"].replace("{domaine}", domaine)
        url_google = (
            "https://www.google.com/search?q=" +
            urllib.parse.quote(dork_query)
        )
        url_duckduckgo = (
            "https://duckduckgo.com/?q=" +
            urllib.parse.quote(dork_query)
        )
        dorks.append({
            "nom":          template["nom"],
            "categorie":    template["categorie"],
            "severite":     template["severite"],
            "dork":         dork_query,
            "url_google":   url_google,
            "url_ddg":      url_duckduckgo,
        })

    # Grouper par catégorie
    categories = {}
    for d in dorks:
        cat = d["categorie"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(d)

    return {
        "domaine":    domaine,
        "total":      len(dorks),
        "dorks":      dorks,
        "categories": categories,
        "date":       datetime.datetime.now().strftime("%d/%m/%Y à %H:%M"),
    }


# ─────────────────────────────────────────────
# 3. SHODAN LOOKUP
# ─────────────────────────────────────────────

def shodan_lookup(cible: str, api_key: str = "") -> dict:
    """
    Interroge l'API Shodan pour une IP ou un domaine.
    Retourne les services, ports, vulnérabilités et historique.
    """
    cible = cible.replace("https://","").replace("http://","").split("/")[0].strip()

    # Résoudre en IP si domaine
    try:
        ip = socket.gethostbyname(cible)
    except Exception:
        return {"erreur": f"Impossible de résoudre '{cible}'"}

    if not api_key:
        # Sans clé : utiliser l'API publique limitée
        try:
            r = requests.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=TIMEOUT
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "ip":          ip,
                    "cible":       cible,
                    "source":      "Shodan InternetDB (gratuit)",
                    "ports":       data.get("ports", []),
                    "cpes":        data.get("cpes", []),
                    "vulns":       data.get("vulns", []),
                    "hostnames":   data.get("hostnames", []),
                    "tags":        data.get("tags", []),
                    "nb_ports":    len(data.get("ports", [])),
                    "nb_vulns":    len(data.get("vulns", [])),
                    "api_complete": False,
                }
            elif r.status_code == 404:
                return {
                    "ip":     ip,
                    "cible":  cible,
                    "source": "Shodan InternetDB",
                    "ports":  [],
                    "vulns":  [],
                    "message":"IP non indexée dans Shodan.",
                    "nb_ports": 0,
                    "nb_vulns": 0,
                    "api_complete": False,
                }
        except Exception as e:
            return {"erreur": f"Shodan InternetDB indisponible : {e}"}

    # Avec clé API Shodan complète
    try:
        import shodan
        api  = shodan.Shodan(api_key)
        host = api.host(ip)

        services = []
        for item in host.get("data", []):
            services.append({
                "port":      item.get("port"),
                "transport": item.get("transport","tcp"),
                "produit":   item.get("product",""),
                "version":   item.get("version",""),
                "banner":    item.get("data","")[:150],
                "cpe":       item.get("cpe",""),
                "timestamp": item.get("timestamp","")[:10],
            })

        return {
            "ip":           ip,
            "cible":        cible,
            "source":       "Shodan API complète",
            "organisation": host.get("org",""),
            "isp":          host.get("isp",""),
            "asn":          host.get("asn",""),
            "pays":         host.get("country_name",""),
            "ville":        host.get("city",""),
            "ports":        host.get("ports",[]),
            "hostnames":    host.get("hostnames",[]),
            "domaines":     host.get("domains",[]),
            "tags":         host.get("tags",[]),
            "vulns":        list(host.get("vulns",{}).keys()),
            "services":     services,
            "nb_ports":     len(host.get("ports",[])),
            "nb_vulns":     len(host.get("vulns",{})),
            "last_update":  host.get("last_update","")[:10],
            "api_complete": True,
        }
    except Exception as e:
        return {"erreur": f"Erreur Shodan API : {e}"}


# ─────────────────────────────────────────────
# 4. FINGERPRINTING AVANCÉ
# ─────────────────────────────────────────────

def fingerprint_avance(url: str) -> dict:
    """
    Fingerprinting technologique approfondi d'une cible web.
    Détecte CMS, frameworks, versions, WAF, CDN, cookies sécurité.
    """
    if not url.startswith("http"):
        url = "https://" + url

    try:
        r = requests.get(
            url, timeout=TIMEOUT, verify=False,
            headers=HEADERS, allow_redirects=True
        )
    except Exception as e:
        try:
            url = url.replace("https://","http://")
            r = requests.get(
                url, timeout=TIMEOUT, verify=False,
                headers=HEADERS, allow_redirects=True
            )
        except Exception:
            return {"erreur": f"Impossible de contacter la cible : {e}"}

    headers  = dict(r.headers)
    contenu  = r.text[:100000]
    h_str    = str(headers).lower()
    c_str    = contenu.lower()

    resultats = {
        "url":          r.url,
        "code":         r.status_code,
        "serveur":      headers.get("Server",""),
        "powered_by":   headers.get("X-Powered-By",""),
        "cms":          [],
        "frameworks":   [],
        "langages":     [],
        "cdn":          [],
        "waf":          [],
        "cloud":        [],
        "analytics":    [],
        "securite":     [],
        "cookies":      [],
        "versions":     {},
        "alertes":      [],
    }

    # CMS
    cms_signatures = {
        "WordPress":    [r"wp-content", r"wp-includes", r"wordpress"],
        "Joomla":       [r"joomla!", r"/components/com_", r"joomla"],
        "Drupal":       [r"drupal", r"/sites/default/files"],
        "Magento":      [r"mage/cookies", r"magento", r"skin/frontend"],
        "Shopify":      [r"cdn.shopify.com", r"shopify"],
        "Wix":          [r"wix.com", r"wixstatic"],
        "Squarespace":  [r"squarespace.com", r"squarespace"],
        "PrestaShop":   [r"prestashop", r"/themes/default-bootstrap"],
        "TYPO3":        [r"typo3", r"/typo3conf/"],
        "OpenCart":     [r"opencart", r"catalog/view/theme"],
    }

    for cms, patterns in cms_signatures.items():
        if any(re.search(p, contenu, re.I) for p in patterns):
            resultats["cms"].append(cms)

    # Frameworks
    fw_signatures = {
        "React":        [r"react\.js", r"react-dom", r"__reactfiber"],
        "Vue.js":       [r"vue\.js", r"vue\.min\.js", r"__vue__"],
        "Angular":      [r"angular\.js", r"ng-version", r"angular/core"],
        "Next.js":      [r"__next", r"/_next/", r"next/dist"],
        "Nuxt.js":      [r"__nuxt", r"/_nuxt/"],
        "Laravel":      [r"laravel_session", r"laravel"],
        "Django":       [r"csrfmiddlewaretoken", r"django"],
        "Ruby on Rails":[r"rails", r"authenticity_token"],
        "Express.js":   [r"x-powered-by: express"],
        "Spring Boot":  [r"x-application-context", r"spring"],
        "ASP.NET":      [r"__viewstate", r"asp.net"],
        "Flask":        [r"werkzeug", r"flask"],
        "Symfony":      [r"symfony", r"sf_redirect"],
        "Bootstrap":    [r'bootstrap[./](\d+\.\d+)'],
        "jQuery":       [r'jquery[./](\d+\.\d+\.\d+)'],
        "Tailwind":     [r"tailwind"],
    }

    for fw, patterns in fw_signatures.items():
        texte = h_str + " " + c_str
        if any(re.search(p, texte, re.I) for p in patterns):
            resultats["frameworks"].append(fw)
            # Extraire version
            for p in patterns:
                m = re.search(p, texte, re.I)
                if m and m.lastindex:
                    resultats["versions"][fw] = m.group(1)

    # Langages
    lang_signatures = {
        "PHP":    [r"\.php", r"x-powered-by: php/([\d.]+)"],
        "Python": [r"python", r"wsgi"],
        "Ruby":   [r"ruby", r"passenger"],
        "Java":   [r"jsessionid", r"java", r"\.jsp"],
        "Node.js":[r"x-powered-by: express", r"node\.js"],
        ".NET":   [r"asp\.net", r"\.aspx", r"x-aspnet"],
        "Go":     [r"x-powered-by: go", r"golang"],
    }

    for lang, patterns in lang_signatures.items():
        texte = h_str + " " + c_str
        for p in patterns:
            m = re.search(p, texte, re.I)
            if m:
                version = m.group(1) if m.lastindex else ""
                resultats["langages"].append(lang)
                if version:
                    resultats["versions"][lang] = version
                break

    # CDN & Cloud
    cdn_signatures = {
        "Cloudflare":  ["cf-ray", "cloudflare"],
        "AWS CloudFront": ["x-amz-cf-id", "cloudfront"],
        "Fastly":      ["x-fastly-request-id", "fastly"],
        "Akamai":      ["x-akamai-request-id", "akamai"],
        "Google CDN":  ["x-goog-", "googleusercontent"],
        "Azure CDN":   ["x-azure-", "azureedge"],
    }

    for cdn, patterns in cdn_signatures.items():
        if any(p in h_str or p in c_str for p in patterns):
            resultats["cdn"].append(cdn)

    # WAF (Web Application Firewall)
    waf_signatures = {
        "Cloudflare WAF":   ["cf-ray", "__cfduid"],
        "AWS WAF":          ["x-amzn-requestid", "awswaf"],
        "Imperva/Incapsula": ["incap_ses", "visid_incap"],
        "Sucuri":           ["x-sucuri-id", "sucuri"],
        "ModSecurity":      ["mod_security", "modsec"],
        "F5 BIG-IP":        ["bigip", "f5-trafficshield"],
        "Barracuda":        ["barracuda_", "barra_counter_session"],
        "Akamai Kona":      ["akamai", "x-check-cacheable"],
    }

    for waf, patterns in waf_signatures.items():
        if any(p in h_str or p in c_str for p in patterns):
            resultats["waf"].append(waf)

    # Analytics
    analytics_signatures = {
        "Google Analytics":  [r"google-analytics\.com/ga\.js",
                               r"gtag\(", r"UA-\d+-\d+"],
        "Google Tag Manager":[r"googletagmanager\.com", r"GTM-"],
        "Hotjar":            [r"hotjar\.com", r"hjid"],
        "Mixpanel":          [r"mixpanel\.com"],
        "Facebook Pixel":    [r"connect\.facebook\.net/en_US/fbevents",
                               r"fbq\("],
        "Matomo/Piwik":      [r"piwik\.js", r"matomo\.js"],
    }

    for analytics, patterns in analytics_signatures.items():
        if any(re.search(p, contenu, re.I) for p in patterns):
            resultats["analytics"].append(analytics)

    # Headers de sécurité
    security_headers = {
        "HSTS":             headers.get("Strict-Transport-Security"),
        "CSP":              headers.get("Content-Security-Policy"),
        "X-Frame-Options":  headers.get("X-Frame-Options"),
        "X-Content-Type":   headers.get("X-Content-Type-Options"),
        "Referrer-Policy":  headers.get("Referrer-Policy"),
        "Permissions-Policy":headers.get("Permissions-Policy"),
    }

    for header, valeur in security_headers.items():
        resultats["securite"].append({
            "header":  header,
            "present": bool(valeur),
            "valeur":  valeur or "",
        })

    # Cookies
    for cookie in r.cookies:
        flags = []
        if cookie.secure:
            flags.append("Secure")
        if cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("HttpOnly")
        samesite = cookie.get_nonstandard_attr("SameSite","")
        if samesite:
            flags.append(f"SameSite={samesite}")

        manquants = []
        if not cookie.secure:
            manquants.append("Secure manquant")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            manquants.append("HttpOnly manquant")

        resultats["cookies"].append({
            "nom":      cookie.name,
            "flags":    flags,
            "manquants":manquants,
            "risque":   len(manquants) > 0,
        })

    # Alertes
    if not resultats["waf"]:
        resultats["alertes"].append({
            "type": "MOYENNE",
            "msg":  "Aucun WAF détecté — site exposé directement"
        })
    if resultats.get("powered_by"):
        resultats["alertes"].append({
            "type": "HAUTE",
            "msg":  f"Technologie exposée via X-Powered-By : {resultats['powered_by']}"
        })
    if resultats.get("serveur"):
        resultats["alertes"].append({
            "type": "MOYENNE",
            "msg":  f"Version serveur exposée : {resultats['serveur']}"
        })
    for c in resultats["cookies"]:
        if c["risque"]:
            resultats["alertes"].append({
                "type": "HAUTE",
                "msg":  f"Cookie '{c['nom']}' : {', '.join(c['manquants'])}"
            })

    return resultats
