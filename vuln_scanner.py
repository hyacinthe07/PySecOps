import requests
from rich.console import Console
from rich.table import Table

console = Console()

def scanner_vuln(url):
    if not url.startswith("http"):
        url = "http://" + url
        
    console.print(f"\n[bold yellow][*][/bold yellow] Cible Web : [bold cyan]{url}[/bold cyan]")
    console.print("[bold yellow][*][/bold yellow] Analyse des en-têtes HTTP en cours...\n")
    
    # On augmente le timeout à 10 secondes pour éviter les erreurs intempestives
    try:
        reponse = requests.get(url, timeout=10)
        en_tetes = reponse.headers
        
        # Variables pour le résumé final
        critique = 0
        moyenne = 0
        basse = 0
        
        # NOUVEAU : Ajout de la colonne Sévérité
        table = Table(title="[bold white][ RAPPORT DE VULNÉRABILITÉ WEB ][/bold white]", show_lines=True)
        table.add_column("[bold cyan]Test de Sécurité[/bold cyan]", style="cyan")
        table.add_column("[bold white]Statut[/bold white]", justify="center")
        table.add_column("[bold yellow]Sévérité[/bold yellow]", justify="center")
        table.add_column("[bold white]Détails[/bold white]")
        
        # --- Test 1 : Divulgation du serveur ---
        serveur = en_tetes.get("Server", "Non divulgué")
        if "Non divulgué" in serveur:
            table.add_row("Divulgation Serveur", "[bold green]OK[/bold green]", "[dim]-[/dim]", "La version du serveur est masquée.")
        else:
            critique += 1
            table.add_row("Divulgation Serveur", "[bold red]VULNÉRABLE[/bold red]", "[bold red]HAUTE[/bold red]", f"Version exposée : {serveur}")
            
        # --- Test 2 : Clickjacking ---
        xfo = en_tetes.get("X-Frame-Options")
        if not xfo:
            moyenne += 1
            table.add_row("Clickjacking (X-Frame)", "[bold red]MANQUANT[/bold red]", "[bold yellow]MOYENNE[/bold yellow]", "Le site peut être inclus dans un iframe caché.")
        else:
            table.add_row("Clickjacking (X-Frame)", "[bold green]OK[/bold green]", "[dim]-[/dim]", f"Protégé par : {xfo}")
            
        # --- Test 3 : Protection XSS ---
        xss = en_tetes.get("X-XSS-Protection")
        if not xss:
            basse += 1
            table.add_row("Protection XSS", "[bold yellow]OBSOLETE[/bold yellow]", "[bold blue]BASSE[/bold blue]", "Ancienne protection manquante (préférer CSP).")
        else:
            table.add_row("Protection XSS", "[bold green]OK[/bold green]", "[dim]-[/dim]", f"Protégé par : {xss}")

        # --- Test 4 : Divulgation Techno ---
        techno = en_tetes.get("X-Powered-By")
        if techno:
            moyenne += 1
            table.add_row("Divulgation Techno", "[bold red]VULNÉRABLE[/bold red]", "[bold yellow]MOYENNE[/bold yellow]", f"Technologie exposée : {techno}")
        else:
            table.add_row("Divulgation Techno", "[bold green]OK[/bold green]", "[dim]-[/dim]", "La technologie backend est masquée.")

        console.print(table)
        
        # NOUVEAU : Résumé de fin style "Rapport d'audit"
        console.print("\n[bold]--- RÉSUMÉ DE L'AUDIT ---[/bold]")
        if critique > 0:
            console.print(f"[bold red][!][/bold red] Vulnérabilités HAUTES  : {critique}")
        if moyenne > 0:
            console.print(f"[bold yellow][!][/bold yellow] Vulnérabilités MOYENNES: {moyenne}")
        if basse > 0:
            console.print(f"[bold blue][!][/bold blue] Vulnérabilités BASSES  : {basse}")
        if critique == 0 and moyenne == 0 and basse == 0:
            console.print("[bold green][+][/bold green] Aucune vulnérabilité détectée. Serveur durci.")
        console.print()
        if critique == 0 and moyenne == 0 and basse == 0:
            console.print("[bold green][+][/bold green] Aucune vulnérabilité détectée. Serveur durci.")
            
        console.print("[dim magenta]--- Audit Web signé by hyacinthe ---[/dim magenta]\n")
        
    except requests.exceptions.Timeout:
        console.print("[bold red][-][/bold red] Erreur : La cible met trop de temps à répondre (Timeout).\n")
    except requests.exceptions.ConnectionError:
        console.print("[bold red][-][/bold red] Erreur : Impossible de se connecter. Vérifiez l'URL ou votre connexion internet.\n")
    except Exception as e:
        console.print(f"[bold red][-][/bold red] Erreur inattendue : {e}\n")
