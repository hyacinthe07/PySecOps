from rich.console import Console

console = Console()

def generer_rapport_html(nom_cible, resultats):
    """
    resultats = liste de dictionnaires ex: 
    [{"test": "Serveur", "statut": "VULNERABLE", "severite": "HAUTE", "details": "Apache 2.4"}]
    """
    
    # Début du code HTML avec du CSS intégré pour faire un rendu "Hacker Pro"
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <title>Rapport PySecOps - {nom_cible}</title>
        <style>
            body {{ background-color: #1e1e1e; color: #d4d4d4; font-family: 'Courier New', Courier, monospace; padding: 40px; }}
            h1 {{ color: #00ff00; text-align: center; border-bottom: 2px solid #00ff00; padding-bottom: 10px; }}
            .signature {{ text-align: center; color: #ff00ff; font-size: 1.2em; margin-bottom: 30px; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #444; padding: 12px; text-align: left; }}
            th {{ background-color: #2d2d2d; color: #00bcd4; }}
            .haute {{ color: #ff4444; font-weight: bold; }}
            .moyenne {{ color: #ffaa00; font-weight: bold; }}
            .basse {{ color: #4488ff; }}
            .ok {{ color: #00ff00; }}
        </style>
    </head>
    <body>
        <h1>PYSECOPS TOOLKIT</h1>
        <div class="signature">Rapport d'audit généré par hyacinthe</div>
        <h2>Cible analysée : {nom_cible}</h2>
        <table>
            <tr>
                <th>Test Effectué</th>
                <th>Statut</th>
                <th>Sévérité</th>
                <th>Détails</th>
            </tr>
    """

    # On remplit le tableau avec les résultats
    for ligne in resultats:
        classe_sev = "ok"
        if "HAUTE" in ligne['severite']: classe_sev = "haute"
        elif "MOYENNE" in ligne['severite']: classe_sev = "moyenne"
        elif "BASSE" in ligne['severite']: classe_sev = "basse"

        html_content += f"""
            <tr>
                <td>{ligne['test']}</td>
                <td>{ligne['statut']}</td>
                <td class="{classe_sev}">{ligne['severite']}</td>
                <td>{ligne['details']}</td>
            </tr>
        """

    html_content += """
        </table>
    </body>
    </html>
    """

    # On sauvegarde le fichier
    nom_fichier = f"rapport_{nom_cible}.html"
    with open(nom_fichier, "w") as f:
        f.write(html_content)
        
    console.print(f"\n[bold green][+][/bold green] Rapport professionnel généré avec succès : [bold white]{nom_fichier}[/bold white]\n")
