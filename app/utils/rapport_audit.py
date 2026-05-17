"""
PySecOps — Rapport d'audit PTES professionnel
Structure : Synthèse exécutive + Findings + Remédiation + Annexes
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
import io
import datetime

C_DARK   = colors.HexColor("#0d1117")
C_BLUE   = colors.HexColor("#58a6ff")
C_GREEN  = colors.HexColor("#3fb950")
C_RED    = colors.HexColor("#f85149")
C_ORANGE = colors.HexColor("#d29922")
C_DIM    = colors.HexColor("#8b949e")
C_WHITE  = colors.white
C_LIGHT  = colors.HexColor("#f6f8fa")
C_BORDER = colors.HexColor("#d0d7de")


def _styles():
    base = getSampleStyleSheet()
    return {
        "h1": ParagraphStyle("h1", fontSize=24, textColor=C_BLUE,
                             fontName="Helvetica-Bold", spaceAfter=8),
        "h2": ParagraphStyle("h2", fontSize=14, textColor=C_DARK,
                             fontName="Helvetica-Bold",
                             spaceBefore=16, spaceAfter=8,
                             borderPad=4),
        "h3": ParagraphStyle("h3", fontSize=11, textColor=C_BLUE,
                             fontName="Helvetica-Bold",
                             spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", fontSize=9, textColor=C_DARK,
                               fontName="Helvetica",
                               spaceAfter=4, leading=14,
                               alignment=TA_JUSTIFY),
        "mono": ParagraphStyle("mono", fontSize=8,
                               textColor=colors.HexColor("#24292f"),
                               fontName="Courier",
                               spaceAfter=2, leading=11),
        "label": ParagraphStyle("label", fontSize=8, textColor=C_DIM,
                                fontName="Helvetica-Bold"),
        "center": ParagraphStyle("center", fontSize=9, textColor=C_DARK,
                                 fontName="Helvetica", alignment=TA_CENTER),
        "footer": ParagraphStyle("footer", fontSize=7.5, textColor=C_DIM,
                                 fontName="Helvetica", alignment=TA_CENTER),
        "rouge":  ParagraphStyle("rouge",  fontSize=9, textColor=C_RED,
                                 fontName="Helvetica-Bold"),
        "orange": ParagraphStyle("orange", fontSize=9, textColor=C_ORANGE,
                                 fontName="Helvetica-Bold"),
        "vert":   ParagraphStyle("vert",   fontSize=9, textColor=C_GREEN,
                                 fontName="Helvetica-Bold"),
    }


def _page_garde(elements, styles, meta: dict):
    """Page de garde professionnelle."""
    elements.append(Spacer(1, 3*cm))

    # Logo / Titre plateforme
    entete = Table([[
        Paragraph("⚡ PYSECOPS", ParagraphStyle(
            "logo", fontSize=28, textColor=C_WHITE,
            fontName="Helvetica-Bold", alignment=TA_CENTER
        )),
    ]], colWidths=[17*cm])
    entete.setStyle(TableStyle([
        ("BACKGROUND",   (0,0),(-1,-1), C_DARK),
        ("TOPPADDING",   (0,0),(-1,-1), 20),
        ("BOTTOMPADDING",(0,0),(-1,-1), 20),
        ("ROUNDEDCORNERS",[8]),
    ]))
    elements.append(entete)
    elements.append(Spacer(1, 1*cm))

    # Titre du rapport
    elements.append(Paragraph(
        "RAPPORT D'AUDIT DE SÉCURITÉ",
        ParagraphStyle("rt", fontSize=20, textColor=C_DARK,
                       fontName="Helvetica-Bold", alignment=TA_CENTER)
    ))
    elements.append(Paragraph(
        meta.get("titre", "Pentest — Rapport technique"),
        ParagraphStyle("st", fontSize=13, textColor=C_DIM,
                       fontName="Helvetica", alignment=TA_CENTER,
                       spaceAfter=4)
    ))
    elements.append(Spacer(1, 1.5*cm))
    elements.append(HRFlowable(width="100%", thickness=2,
                               color=C_BLUE, spaceAfter=20))

    # Métadonnées
    now = datetime.datetime.now().strftime("%d/%m/%Y")
    meta_data = [
        ["Cible analysée",  meta.get("cible", "—")],
        ["Client",          meta.get("client", "Confidentiel")],
        ["Auditeur",        meta.get("auditeur", "Hyacinthe — PySecOps")],
        ["Date du rapport", now],
        ["Classification",  "CONFIDENTIEL"],
        ["Version",         "1.0"],
    ]
    t = Table(meta_data, colWidths=[5*cm, 12*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(0,-1), C_LIGHT),
        ("FONTNAME",      (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTNAME",      (1,0),(1,-1), "Helvetica"),
        ("FONTSIZE",      (0,0),(-1,-1), 9),
        ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 7),
        ("BOTTOMPADDING", (0,0),(-1,-1), 7),
        ("LEFTPADDING",   (0,0),(-1,-1), 10),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 1*cm))

    # Avertissement
    elements.append(Paragraph(
        "⚠ Ce document est strictement confidentiel. Il contient des informations "
        "sensibles sur les vulnérabilités détectées. Sa diffusion doit être "
        "limitée aux personnes autorisées.",
        ParagraphStyle("warn", fontSize=8, textColor=C_ORANGE,
                       fontName="Helvetica", alignment=TA_CENTER,
                       borderColor=C_ORANGE, borderWidth=1,
                       borderPad=6)
    ))
    elements.append(PageBreak())


def _synthese_executive(elements, styles, data: dict):
    """Synthèse exécutive — pour le management."""
    elements.append(Paragraph("1. Synthèse exécutive", styles["h2"]))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=C_BORDER, spaceAfter=8))

    score = data.get("score_global", 0)
    niveau = data.get("niveau_global", "MODÉRÉ")

    elements.append(Paragraph(
        f"L'audit de sécurité réalisé sur la cible <b>{data.get('cible','—')}</b> "
        f"a permis d'identifier <b>{data.get('nb_findings', 0)} vulnérabilités</b>, "
        f"dont <b>{data.get('nb_critique',0)} critiques</b> et "
        f"<b>{data.get('nb_haute',0)} hautes</b>. "
        f"Le niveau de risque global est évalué à <b>{niveau}</b> "
        f"avec un score de surface d'attaque de <b>{score}/100</b>.",
        styles["body"]
    ))
    elements.append(Spacer(1, 8))

    # Score visuel
    couleur_score = (
        C_RED    if score >= 75 else
        C_ORANGE if score >= 40 else
        C_GREEN
    )
    score_row = [[
        Paragraph(f"{score}/100", ParagraphStyle(
            "sc", fontSize=32, textColor=couleur_score,
            fontName="Helvetica-Bold", alignment=TA_CENTER
        )),
        Paragraph(f"Niveau : {niveau}", ParagraphStyle(
            "nv", fontSize=14, textColor=couleur_score,
            fontName="Helvetica-Bold"
        )),
    ]]
    t = Table(score_row, colWidths=[5*cm, 12*cm])
    t.setStyle(TableStyle([
        ("VALIGN",       (0,0),(-1,-1), "MIDDLE"),
        ("TOPPADDING",   (0,0),(-1,-1), 8),
        ("BOTTOMPADDING",(0,0),(-1,-1), 8),
        ("BACKGROUND",   (0,0),(-1,-1), C_LIGHT),
        ("GRID",         (0,0),(-1,-1), 0.5, C_BORDER),
        ("ROUNDEDCORNERS",[4]),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    # Tableau de synthèse des findings
    elements.append(Paragraph("Répartition des vulnérabilités", styles["h3"]))
    synth = [
        ["Criticité", "Nombre", "Impact"],
        ["CRITIQUE",  str(data.get("nb_critique",0)),
         "Compromission immédiate possible"],
        ["HAUTE",     str(data.get("nb_haute",0)),
         "Exploitation probable sans effort significatif"],
        ["MOYENNE",   str(data.get("nb_moyenne",0)),
         "Exploitation nécessitant des conditions particulières"],
        ["BASSE",     str(data.get("nb_basse",0)),
         "Impact limité, correction recommandée"],
    ]
    t = Table(synth, colWidths=[4*cm, 3*cm, 10*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8.5),
        ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 6),
        ("BOTTOMPADDING", (0,0),(-1,-1), 6),
        ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ("BACKGROUND",    (0,1),(0,1),   colors.HexColor("#fff0ee")),
        ("TEXTCOLOR",     (0,1),(0,1),   C_RED),
        ("FONTNAME",      (0,1),(0,1),   "Helvetica-Bold"),
        ("BACKGROUND",    (0,2),(0,2),   colors.HexColor("#fff0ee")),
        ("TEXTCOLOR",     (0,2),(0,2),   C_RED),
        ("FONTNAME",      (0,2),(0,2),   "Helvetica-Bold"),
        ("BACKGROUND",    (0,3),(0,3),   colors.HexColor("#fffbdd")),
        ("TEXTCOLOR",     (0,3),(0,3),   C_ORANGE),
        ("FONTNAME",      (0,3),(0,3),   "Helvetica-Bold"),
        ("BACKGROUND",    (0,4),(0,4),   colors.HexColor("#f0fff4")),
        ("TEXTCOLOR",     (0,4),(0,4),   C_GREEN),
        ("FONTNAME",      (0,4),(0,4),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS",(1,1),(-1,-1),
         [C_WHITE, colors.HexColor("#f6f8fa")]),
    ]))
    elements.append(t)
    elements.append(PageBreak())


def _findings(elements, styles, findings: list):
    """Section findings — détail de chaque vulnérabilité."""
    elements.append(Paragraph("2. Vulnérabilités détectées", styles["h2"]))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=C_BORDER, spaceAfter=8))

    for i, f in enumerate(findings, 1):
        sev = f.get("severite","MOYENNE")
        couleur_sev = (
            C_RED    if sev == "CRITIQUE" else
            C_RED    if sev == "HAUTE"    else
            C_ORANGE if sev == "MOYENNE"  else
            C_GREEN
        )

        # En-tête du finding
        header = Table([[
            Paragraph(f"[{f.get('id','F-'+str(i))}] {f.get('titre','—')}",
                      ParagraphStyle("fh", fontSize=10, textColor=C_WHITE,
                                     fontName="Helvetica-Bold")),
            Paragraph(sev, ParagraphStyle("fs", fontSize=9,
                                          textColor=couleur_sev,
                                          fontName="Helvetica-Bold",
                                          alignment=TA_RIGHT)),
        ]], colWidths=[13*cm, 4*cm])
        header.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(-1,-1), C_DARK),
            ("TOPPADDING",    (0,0),(-1,-1), 8),
            ("BOTTOMPADDING", (0,0),(-1,-1), 8),
            ("LEFTPADDING",   (0,0),(-1,-1), 10),
            ("RIGHTPADDING",  (0,0),(-1,-1), 10),
            ("VALIGN",        (0,0),(-1,-1), "MIDDLE"),
        ]))
        elements.append(header)

        # Détails du finding
        details = [
            ["CVSS Score",   str(f.get("cvss","—"))],
            ["Catégorie",    f.get("categorie","—")],
            ["Composant",    f.get("composant","—")],
            ["URL / Port",   f.get("localisation","—")],
        ]
        t = Table(details, colWidths=[4*cm, 13*cm])
        t.setStyle(TableStyle([
            ("BACKGROUND",    (0,0),(0,-1), C_LIGHT),
            ("FONTNAME",      (0,0),(0,-1), "Helvetica-Bold"),
            ("FONTSIZE",      (0,0),(-1,-1), 8),
            ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
            ("TOPPADDING",    (0,0),(-1,-1), 4),
            ("BOTTOMPADDING", (0,0),(-1,-1), 4),
            ("LEFTPADDING",   (0,0),(-1,-1), 8),
        ]))
        elements.append(t)

        # Description + Evidence + Remédiation
        for label, key, style_key in [
            ("Description",      "description",  "body"),
            ("Preuve (Evidence)","evidence",      "mono"),
            ("Impact",           "impact",        "body"),
            ("Remédiation",      "remediation",   "body"),
        ]:
            contenu = f.get(key,"")
            if contenu:
                elements.append(Paragraph(label, styles["h3"]))
                elements.append(Paragraph(str(contenu), styles[style_key]))

        elements.append(Spacer(1, 12))

    elements.append(PageBreak())


def _plan_remediation(elements, styles, findings: list):
    """Plan de remédiation priorisé."""
    elements.append(Paragraph("3. Plan de remédiation", styles["h2"]))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=C_BORDER, spaceAfter=8))
    elements.append(Paragraph(
        "Les actions de remédiation sont classées par ordre de priorité. "
        "Les vulnérabilités critiques doivent être corrigées immédiatement, "
        "avant toute mise en production.",
        styles["body"]
    ))
    elements.append(Spacer(1, 8))

    ordre = {"CRITIQUE":0,"HAUTE":1,"MOYENNE":2,"BASSE":3}
    tries = sorted(findings,
                   key=lambda x: ordre.get(x.get("severite","BASSE"), 3))

    rows = [["Priorité","ID","Vulnérabilité","Action immédiate","Délai"]]
    delais = {"CRITIQUE":"24-48h","HAUTE":"1 semaine",
              "MOYENNE":"1 mois","BASSE":"3 mois"}

    for f in tries:
        sev = f.get("severite","BASSE")
        rows.append([
            sev,
            f.get("id","—"),
            f.get("titre","—")[:40],
            f.get("remediation","—")[:60],
            delais.get(sev,"—"),
        ])

    t = Table(rows, colWidths=[2.5*cm, 2*cm, 5*cm, 6*cm, 1.5*cm])
    style_list = [
        ("BACKGROUND",    (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 7.5),
        ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ("ROWBACKGROUNDS",(1,0),(-1,-1),
         [C_WHITE, C_LIGHT]),
    ]
    for i, f in enumerate(tries, 1):
        sev = f.get("severite","BASSE")
        if sev in ("CRITIQUE","HAUTE"):
            style_list += [
                ("TEXTCOLOR",  (0,i),(0,i), C_RED),
                ("FONTNAME",   (0,i),(0,i), "Helvetica-Bold"),
                ("BACKGROUND", (0,i),(0,i),
                 colors.HexColor("#fff0ee")),
            ]
        elif sev == "MOYENNE":
            style_list += [
                ("TEXTCOLOR",  (0,i),(0,i), C_ORANGE),
                ("FONTNAME",   (0,i),(0,i), "Helvetica-Bold"),
            ]
    t.setStyle(TableStyle(style_list))
    elements.append(t)
    elements.append(PageBreak())


def _annexes(elements, styles, data: dict):
    """Annexes techniques."""
    elements.append(Paragraph("4. Annexes techniques", styles["h2"]))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=C_BORDER, spaceAfter=8))

    # Méthodologie
    elements.append(Paragraph("Méthodologie utilisée (PTES)", styles["h3"]))
    phases = [
        ["Phase", "Description", "Outils"],
        ["1. Reconnaissance",
         "Collecte passive d'informations sur la cible",
         "WHOIS, DNS, crt.sh, Subdomain enum"],
        ["2. Scanning",
         "Identification des services et versions exposés",
         "Port Scanner, Banner Grabbing"],
        ["3. Analyse vulnérabilités",
         "Corrélation des services avec la base CVE",
         "NIST NVD API, CVE Lookup"],
        ["4. Exploitation",
         "Tentative d'exploitation contrôlée des failles",
         "Techniques manuelles, PoC publics"],
        ["5. Post-exploitation",
         "Évaluation de l'impact réel d'une compromission",
         "Analyse d'accès, pivoting"],
        ["6. Rapport",
         "Documentation des findings et recommandations",
         "PySecOps PDF Engine"],
    ]
    t = Table(phases, colWidths=[4*cm, 7.5*cm, 5.5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0),(-1,0),  C_DARK),
        ("TEXTCOLOR",     (0,0),(-1,0),  C_WHITE),
        ("FONTNAME",      (0,0),(-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 5),
        ("BOTTOMPADDING", (0,0),(-1,-1), 5),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("VALIGN",        (0,0),(-1,-1), "TOP"),
        ("ROWBACKGROUNDS",(1,0),(-1,-1),
         [C_WHITE, C_LIGHT]),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 12))

    # Glossaire
    elements.append(Paragraph("Glossaire", styles["h3"]))
    glossaire = [
        ["CVE",      "Common Vulnerabilities and Exposures — identifiant unique de vulnérabilité"],
        ["CVSS",     "Common Vulnerability Scoring System — score de criticité de 0 à 10"],
        ["IOC",      "Indicator of Compromise — indicateur d'une intrusion"],
        ["PTES",     "Penetration Testing Execution Standard — méthodologie de pentest"],
        ["RCE",      "Remote Code Execution — exécution de code à distance"],
        ["LFI/RFI",  "Local/Remote File Inclusion — inclusion de fichiers locaux ou distants"],
        ["SSTI",     "Server-Side Template Injection — injection dans les templates serveur"],
        ["APT",      "Advanced Persistent Threat — menace avancée persistante"],
    ]
    t = Table(glossaire, colWidths=[3*cm, 14*cm])
    t.setStyle(TableStyle([
        ("FONTNAME",      (0,0),(0,-1), "Helvetica-Bold"),
        ("FONTSIZE",      (0,0),(-1,-1), 8),
        ("GRID",          (0,0),(-1,-1), 0.5, C_BORDER),
        ("TOPPADDING",    (0,0),(-1,-1), 4),
        ("BOTTOMPADDING", (0,0),(-1,-1), 4),
        ("LEFTPADDING",   (0,0),(-1,-1), 6),
        ("ROWBACKGROUNDS",(0,0),(-1,-1),
         [C_WHITE, C_LIGHT]),
    ]))
    elements.append(t)


def _pied_de_page(elements, styles, meta: dict):
    now = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M:%S")
    elements.append(Spacer(1, 20))
    elements.append(HRFlowable(width="100%", thickness=0.5,
                               color=C_BORDER, spaceAfter=6))
    elements.append(Paragraph(
        f"Rapport généré par PySecOps Security Platform · "
        f"Auditeur : {meta.get('auditeur','Hyacinthe')} · {now}",
        styles["footer"]
    ))
    elements.append(Paragraph(
        "DOCUMENT CONFIDENTIEL — Diffusion restreinte aux personnes autorisées",
        styles["footer"]
    ))


def generer_rapport_ptes(meta: dict, findings: list) -> bytes:
    """
    Génère un rapport d'audit PTES complet en PDF.
    meta : titre, cible, client, auditeur
    findings : liste de vulnérabilités avec id, titre, severite,
               cvss, description, evidence, impact, remediation,
               categorie, composant, localisation
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )
    styles  = _styles()
    elements = []

    # Stats globales
    sev_count = {"CRITIQUE":0,"HAUTE":0,"MOYENNE":0,"BASSE":0}
    for f in findings:
        sev = f.get("severite","BASSE")
        sev_count[sev] = sev_count.get(sev,0) + 1

    score = min(
        sev_count["CRITIQUE"] * 25 +
        sev_count["HAUTE"]    * 15 +
        sev_count["MOYENNE"]  * 5  +
        sev_count["BASSE"]    * 1,
        100
    )
    niveau = (
        "CRITIQUE" if score >= 75 else
        "ÉLEVÉ"    if score >= 40 else
        "MODÉRÉ"   if score >= 15 else
        "FAIBLE"
    )

    data = {
        "cible":        meta.get("cible","—"),
        "score_global": score,
        "niveau_global":niveau,
        "nb_findings":  len(findings),
        **sev_count,
    }

    _page_garde(elements, styles, meta)
    _synthese_executive(elements, styles, data)
    _findings(elements, styles, findings)
    _plan_remediation(elements, styles, findings)
    _annexes(elements, styles, data)
    _pied_de_page(elements, styles, meta)

    doc.build(elements)
    return buffer.getvalue()
