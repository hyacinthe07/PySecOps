"""
PySecOps — Générateur de rapports PDF professionnels
Utilise ReportLab pour produire des rapports lisibles et exportables.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
import io
import datetime


# ── Palette couleurs PySecOps
C_DARK    = colors.HexColor("#0d1117")
C_CARD    = colors.HexColor("#161b22")
C_BLUE    = colors.HexColor("#58a6ff")
C_GREEN   = colors.HexColor("#3fb950")
C_RED     = colors.HexColor("#f85149")
C_ORANGE  = colors.HexColor("#d29922")
C_TEXT    = colors.HexColor("#c9d1d9")
C_DIM     = colors.HexColor("#8b949e")
C_BORDER  = colors.HexColor("#30363d")
C_WHITE   = colors.white
C_BLACK   = colors.black


def _styles():
    """Retourne les styles réutilisables du rapport."""
    base = getSampleStyleSheet()

    return {
        "titre": ParagraphStyle(
            "titre", parent=base["Normal"],
            fontSize=22, textColor=C_BLUE,
            fontName="Helvetica-Bold",
            spaceAfter=4, alignment=TA_LEFT,
        ),
        "sous_titre": ParagraphStyle(
            "sous_titre", parent=base["Normal"],
            fontSize=10, textColor=C_DIM,
            fontName="Helvetica",
            spaceAfter=2, alignment=TA_LEFT,
        ),
        "section": ParagraphStyle(
            "section", parent=base["Normal"],
            fontSize=11, textColor=C_BLUE,
            fontName="Helvetica-Bold",
            spaceBefore=14, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "body", parent=base["Normal"],
            fontSize=9, textColor=C_BLACK,
            fontName="Helvetica",
            spaceAfter=4, leading=14,
        ),
        "mono": ParagraphStyle(
            "mono", parent=base["Normal"],
            fontSize=8, textColor=colors.HexColor("#24292f"),
            fontName="Courier",
            spaceAfter=2, leading=12,
        ),
        "label": ParagraphStyle(
            "label", parent=base["Normal"],
            fontSize=8, textColor=C_DIM,
            fontName="Helvetica-Bold",
            spaceAfter=1,
        ),
        "footer": ParagraphStyle(
            "footer", parent=base["Normal"],
            fontSize=8, textColor=C_DIM,
            fontName="Helvetica",
            alignment=TA_CENTER,
        ),
        "badge_ok":     ParagraphStyle("badge_ok",     parent=base["Normal"], fontSize=8, textColor=C_GREEN,  fontName="Helvetica-Bold"),
        "badge_danger": ParagraphStyle("badge_danger", parent=base["Normal"], fontSize=8, textColor=C_RED,    fontName="Helvetica-Bold"),
        "badge_warn":   ParagraphStyle("badge_warn",   parent=base["Normal"], fontSize=8, textColor=C_ORANGE, fontName="Helvetica-Bold"),
    }


def _entete(elements, styles, titre_rapport, cible, module):
    """Génère l'en-tête du rapport."""
    now = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")

    # Bande de titre
    data = [[
        Paragraph("⚡ PYSECOPS", ParagraphStyle("logo", fontSize=16, textColor=C_WHITE, fontName="Helvetica-Bold")),
        Paragraph(f"Security Report<br/><font size='8' color='#8b949e'>{now}</font>",
                  ParagraphStyle("hdr_right", fontSize=10, textColor=C_WHITE, fontName="Helvetica", alignment=TA_RIGHT)),
    ]]
    t = Table(data, colWidths=[9*cm, 9*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, -1), C_DARK),
        ("TEXTCOLOR",   (0, 0), (-1, -1), C_WHITE),
        ("TOPPADDING",  (0, 0), (-1, -1), 12),
        ("BOTTOMPADDING",(0,0), (-1, -1), 12),
        ("LEFTPADDING", (0, 0), (-1, -1), 14),
        ("RIGHTPADDING",(0, 0), (-1, -1), 14),
        ("ROUNDEDCORNERS", [6]),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 14))

    # Titre du rapport
    elements.append(Paragraph(titre_rapport, styles["titre"]))
    elements.append(Paragraph(f"Module : {module}  ·  Cible : {cible}", styles["sous_titre"]))
    elements.append(HRFlowable(width="100%", thickness=1, color=C_BORDER, spaceAfter=10))


def _pied_de_page(elements, styles):
    """Génère le pied de page."""
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5, color=C_BORDER, spaceAfter=6))
    elements.append(Paragraph(
        "Rapport généré par PySecOps — plateforme de cybersécurité offensive &amp; défensive · by Hyacinthe",
        styles["footer"]
    ))
    elements.append(Paragraph(
        "⚠ Ce rapport est strictement confidentiel. Utilisation réservée à des fins légales et autorisées.",
        styles["footer"]
    ))


def _tableau_kv(data_pairs, styles, col_widths=None):
    """Crée un tableau clé-valeur stylé."""
    col_widths = col_widths or [5*cm, 13*cm]
    rows = []
    for label, valeur in data_pairs:
        rows.append([
            Paragraph(label, styles["label"]),
            Paragraph(str(valeur), styles["body"]),
        ])
    t = Table(rows, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (0, -1), colors.HexColor("#f6f8fa")),
        ("BACKGROUND",   (1, 0), (1, -1), C_WHITE),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("FONTNAME",     (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _tableau_alertes(alertes, styles):
    """Crée un tableau d'alertes coloré."""
    if not alertes:
        return Paragraph("✅ Aucune alerte détectée.", styles["body"])

    rows = [["Sévérité", "Description"]]
    for a in alertes:
        rows.append([a.get("type", "—"), a.get("msg", "—")])

    t = Table(rows, colWidths=[3*cm, 15*cm])
    style_list = [
        ("BACKGROUND",   (0, 0), (-1, 0),  C_DARK),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  C_WHITE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 8),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#d0d7de")),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING",  (0, 0), (-1, -1), 8),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
    ]
    for i, a in enumerate(alertes, start=1):
        t_val = a.get("type", "")
        if t_val in ("CRITIQUE", "HAUTE"):
            bg = colors.HexColor("#fff0ee")
            fg = C_RED
        elif t_val == "MOYENNE":
            bg = colors.HexColor("#fffbdd")
            fg = C_ORANGE
        else:
            bg = colors.HexColor("#f0fff4")
            fg = C_GREEN
        style_list += [
            ("BACKGROUND", (0, i), (0, i), bg),
            ("TEXTCOLOR",  (0, i), (0, i), fg),
            ("FONTNAME",   (0, i), (0, i), "Helvetica-Bold"),
        ]
    t.setStyle(TableStyle(style_list))
    return t


# ═══════════════════════════════════════════
# GÉNÉRATEURS SPÉCIFIQUES PAR MODULE
# ═══════════════════════════════════════════

def rapport_ssl(data: dict) -> bytes:
    """Génère un rapport PDF pour le scanner SSL/TLS."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = _styles()
    elements = []

    _entete(elements, styles, "Rapport SSL/TLS", data.get("domaine", "—"), "SSL/TLS Scanner")

    # Score global
    elements.append(Paragraph("Score de sécurité", styles["section"]))
    score = data.get("score", 0)
    niveau = data.get("niveau", "—")
    couleur = C_GREEN if score >= 80 else (C_ORANGE if score >= 50 else C_RED)
    score_data = [[
        Paragraph(f"{score}/100", ParagraphStyle("sc", fontSize=28, textColor=couleur, fontName="Helvetica-Bold")),
        Paragraph(niveau, ParagraphStyle("nv", fontSize=14, textColor=couleur, fontName="Helvetica-Bold")),
    ]]
    t = Table(score_data, colWidths=[4*cm, 14*cm])
    t.setStyle(TableStyle([("VALIGN", (0,0), (-1,-1), "MIDDLE"), ("TOPPADDING", (0,0),(-1,-1), 8)]))
    elements.append(t)
    elements.append(Spacer(1, 8))

    # Détails
    elements.append(Paragraph("Détails du certificat", styles["section"]))
    elements.append(_tableau_kv([
        ("Domaine (CN)",     data.get("cn", "—")),
        ("Organisation",     data.get("org", "—")),
        ("Émetteur (CA)",    f"{data.get('emetteur_org','—')} — {data.get('emetteur_cn','—')}"),
        ("Protocole TLS",    data.get("protocole", "—")),
        ("Cipher",           data.get("cipher", "—")),
        ("Valide depuis",    data.get("date_debut", "—")),
        ("Expire le",        data.get("date_fin", "—")),
        ("Jours restants",   str(data.get("jours_restants", "—"))),
        ("SANs couverts",    ", ".join(data.get("sans", [])[:6]) or "—"),
    ], styles))
    elements.append(Spacer(1, 10))

    # Alertes
    elements.append(Paragraph("Alertes détectées", styles["section"]))
    elements.append(_tableau_alertes(data.get("alertes", []), styles))

    _pied_de_page(elements, styles)
    doc.build(elements)
    return buffer.getvalue()


def rapport_owasp(data: dict) -> bytes:
    """Génère un rapport PDF pour le Web Audit OWASP."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = _styles()
    elements = []

    _entete(elements, styles, "Rapport Web Audit OWASP", data.get("url", "—"), "Web Vulnerability Scanner")

    # Stats
    stats = data.get("stats", {})
    elements.append(Paragraph("Résumé des vulnérabilités", styles["section"]))
    stats_rows = [[
        Paragraph(f"{stats.get('haute',0)}\nHAUTES",   ParagraphStyle("sh", fontSize=14, textColor=C_RED,    fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"{stats.get('moyenne',0)}\nMOYENNES",ParagraphStyle("sm", fontSize=14, textColor=C_ORANGE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"{stats.get('basse',0)}\nBASSES",   ParagraphStyle("sb", fontSize=14, textColor=C_BLUE,   fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph(f"{stats.get('ok',0)}\nOK",          ParagraphStyle("so", fontSize=14, textColor=C_GREEN,  fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]]
    t = Table(stats_rows, colWidths=[4.5*cm]*4)
    t.setStyle(TableStyle([
        ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 10),
        ("BOTTOMPADDING", (0,0),(-1,-1), 10),
        ("ALIGN",         (0,0),(-1,-1), "CENTER"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 10))

    # Résultats détaillés
    elements.append(Paragraph("Résultats détaillés", styles["section"]))
    rows = [["Vérification", "Statut", "Sévérité", "Valeur"]]
    for r in data.get("resultats", []):
        statut  = r.get("statut", "—")
        severite = r.get("severite", "—")
        rows.append([
            r.get("nom", "—"),
            statut,
            severite,
            str(r.get("valeur", "—"))[:40],
        ])
    t = Table(rows, colWidths=[6*cm, 2.5*cm, 2.5*cm, 7*cm])
    style_list = [
        ("BACKGROUND",   (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",    (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0),(-1,-1), 7.5),
        ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor("#d0d7de")),
        ("TOPPADDING",   (0,0),(-1,-1), 4),
        ("BOTTOMPADDING",(0,0),(-1,-1), 4),
        ("LEFTPADDING",  (0,0),(-1,-1), 6),
        ("VALIGN",       (0,0),(-1,-1), "TOP"),
        ("WORDWRAP",     (0,0),(-1,-1), True),
    ]
    for i, r in enumerate(data.get("resultats", []), start=1):
        if r.get("statut") == "VULNÉRABLE":
            sev = r.get("severite", "")
            if sev == "HAUTE":   style_list.append(("BACKGROUND", (0,i),(0,i), colors.HexColor("#fff0ee")))
            elif sev == "MOYENNE": style_list.append(("BACKGROUND", (0,i),(0,i), colors.HexColor("#fffbdd")))
        else:
            style_list.append(("TEXTCOLOR", (1,i),(1,i), C_GREEN))
    t.setStyle(TableStyle(style_list))
    elements.append(t)

    _pied_de_page(elements, styles)
    doc.build(elements)
    return buffer.getvalue()


def rapport_ports(data: dict) -> bytes:
    """Génère un rapport PDF pour le scanner de ports."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = _styles()
    elements = []

    _entete(elements, styles, "Rapport Port Scanner", data.get("target", "—"), "Port Scanner")

    elements.append(Paragraph("Résumé du scan", styles["section"]))
    elements.append(_tableau_kv([
        ("Cible",           data.get("target", "—")),
        ("Ports scannés",   str(data.get("range", "—"))),
        ("Ports ouverts",   str(data.get("total", 0))),
    ], styles))
    elements.append(Spacer(1, 10))

    ports = data.get("ports", [])
    if ports:
        elements.append(Paragraph("Ports ouverts détectés", styles["section"]))
        rows = [["Port", "Protocole", "Service", "Bannière"]]
        for p in ports:
            rows.append([
                str(p.get("port", "—")),
                "TCP",
                p.get("service", "Unknown"),
                str(p.get("banner", "—"))[:50],
            ])
        t = Table(rows, colWidths=[2*cm, 2.5*cm, 3.5*cm, 10*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0),(-1,0),  C_DARK),
            ("TEXTCOLOR",    (0,0),(-1,0),  C_WHITE),
            ("FONTNAME",     (0,0),(-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0,0),(-1,-1), 8),
            ("GRID",         (0,0),(-1,-1), 0.5, colors.HexColor("#d0d7de")),
            ("TOPPADDING",   (0,0),(-1,-1), 4),
            ("BOTTOMPADDING",(0,0),(-1,-1), 4),
            ("LEFTPADDING",  (0,0),(-1,-1), 6),
            ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_WHITE, colors.HexColor("#f6f8fa")]),
        ]))
        elements.append(t)
    else:
        elements.append(Paragraph("Aucun port ouvert détecté.", styles["body"]))

    _pied_de_page(elements, styles)
    doc.build(elements)
    return buffer.getvalue()


def rapport_whois(whois_data: dict, dns_data: dict) -> bytes:
    """Génère un rapport PDF pour WHOIS + DNS."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = _styles()
    elements = []

    domaine = whois_data.get("domaine", "—")
    _entete(elements, styles, "Rapport WHOIS & DNS", domaine, "Network Intelligence")

    # WHOIS
    elements.append(Paragraph("Informations WHOIS", styles["section"]))
    elements.append(_tableau_kv([
        ("Registrant",   whois_data.get("registrant", "—")),
        ("Organisation", whois_data.get("organisation", "—")),
        ("Pays",         whois_data.get("pays", "—")),
        ("Registrar",    whois_data.get("registrar", "—")),
        ("Création",     whois_data.get("creation", "—")),
        ("Expiration",   whois_data.get("expiration", "—")),
        ("DNSSEC",       whois_data.get("dnssec", "—")),
    ], styles))
    elements.append(Spacer(1, 8))

    # Nameservers
    ns_list = whois_data.get("nameservers", [])
    if ns_list:
        elements.append(Paragraph("Serveurs de noms (NS)", styles["section"]))
        for ns in ns_list:
            elements.append(Paragraph(f"• {ns}", styles["mono"]))
        elements.append(Spacer(1, 8))

    # DNS
    if dns_data and not dns_data.get("erreur"):
        elements.append(Paragraph("Enregistrements DNS", styles["section"]))
        for rtype, valeurs in dns_data.get("enregistrements", {}).items():
            if valeurs:
                elements.append(Paragraph(rtype, styles["label"]))
                for v in valeurs:
                    elements.append(Paragraph(f"  {v}", styles["mono"]))
                elements.append(Spacer(1, 4))

    # Alertes combinées
    toutes_alertes = whois_data.get("alertes", []) + (dns_data or {}).get("alertes", [])
    if toutes_alertes:
        elements.append(Paragraph("Alertes détectées", styles["section"]))
        elements.append(_tableau_alertes(toutes_alertes, styles))

    _pied_de_page(elements, styles)
    doc.build(elements)
    return buffer.getvalue()


def rapport_ip(data: dict) -> bytes:
    """Génère un rapport PDF pour IP Intelligence."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = _styles()
    elements = []

    _entete(elements, styles, "Rapport IP Intelligence", data.get("ip", "—"), "IP Intelligence")

    elements.append(Paragraph("Informations générales", styles["section"]))
    elements.append(_tableau_kv([
        ("IP analysée",    data.get("ip", "—")),
        ("Niveau de risque", data.get("niveau_risque", "—")),
        ("Score de risque", f"{data.get('score_risque', 0)}/100"),
        ("Proxy/VPN",      "OUI" if data.get("est_proxy") else "NON"),
        ("Hébergeur",      "OUI" if data.get("est_hosting") else "NON"),
        ("Mobile",         "OUI" if data.get("est_mobile") else "NON"),
    ], styles))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Localisation géographique", styles["section"]))
    elements.append(_tableau_kv([
        ("Pays",       f"{data.get('pays','—')} ({data.get('code_pays','')})"),
        ("Région",     data.get("region", "—")),
        ("Ville",      data.get("ville", "—")),
        ("Timezone",   data.get("timezone", "—")),
        ("Coordonnées",f"{data.get('lat','—')}, {data.get('lon','—')}"),
    ], styles))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("Réseau / ASN", styles["section"]))
    elements.append(_tableau_kv([
        ("FAI / ISP",    data.get("isp", "—")),
        ("Organisation", data.get("org", "—")),
        ("ASN",          data.get("asn", "—")),
        ("Nom ASN",      data.get("asname", "—")),
        ("DNS inverse",  data.get("reverse_dns", "—")),
    ], styles))

    if data.get("alertes"):
        elements.append(Paragraph("Indicateurs de risque", styles["section"]))
        elements.append(_tableau_alertes(data.get("alertes", []), styles))

    _pied_de_page(elements, styles)
    doc.build(elements)
    return buffer.getvalue()
