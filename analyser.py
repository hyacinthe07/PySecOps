import re
from collections import Counter
from rich.console import Console
from rich.table import Table

console = Console()

def analyser_logs(fichier):
    console.print(f"\n[bold yellow][*][/bold yellow] Lecture du fichier : [bold cyan]{fichier}[/bold cyan]")
    
    # 1. Listes pour stocker nos données
    toutes_les_ip = []
    ip_suspectes = {} # Dictionnaire pour stocker : {IP: nombre_de_suspicions}

    # 2. Mots clés qui trahissent une attaque
    mots_suspects = ["404", "401", "403", "admin", "passwd", "../", "wp-admin"]

    try:
        with open(fichier, "r") as f:
            for ligne in f:
                # On cherche une adresse IP dans la ligne (4 groupes de 1 à 3 chiffres séparés par des points)
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ligne)
                
                if ip_match:
                    ip = ip_match.group(0)
                    toutes_les_ip.append(ip)
                    
                    # On vérifie si la ligne contient un mot suspect
                    ligne_lower = ligne.lower()
                    if any(mot in ligne_lower for mot in mots_suspects):
                        if ip in ip_suspectes:
                            ip_suspectes[ip] += 1
                        else:
                            ip_suspectes[ip] = 1
                            
    except FileNotFoundError:
        console.print(f"[bold red][-][/bold red] Erreur : Le fichier '{fichier}' est introuvable.")
        return

    # 3. Traitement et Affichage avec un beau Tableau
    console.print("[bold green][+][/bold green] Analyse terminée. Génération du rapport...\n")
    
    # On compte le nombre total de requêtes par IP
    compteur_ip = Counter(toutes_les_ip).most_common(5) # Top 5 des IP les plus actives

    # Création du tableau RICHE
    table = Table(title="[bold white][ RAPPORT D'INTRUSION ][/bold white]", box=None, show_lines=True)
    table.add_column("[bold cyan]Adresse IP[/bold cyan]", justify="center")
    table.add_column("[bold white]Requêtes Totales[/bold white]", justify="center")
    table.add_column("[bold red]Alertes Suspectes[/bold red]", justify="center")
    table.add_column("[bold yellow]Statut[/bold yellow]", justify="center")

    for ip, total in compteur_ip:
        alertes = ip_suspectes.get(ip, 0) # Récupère le nombre d'alertes (0 si pas dans le dico)
        
        # Logique de décision pour le statut
        if alertes > 2:
            statut = "[bold red]DANGEREUX[/bold red]"
        elif alertes > 0:
            statut = "[bold yellow]A SURVEILLER[/bold yellow]"
        else:
            statut = "[bold green]NORMAL[/bold green]"
            
        table.add_row(ip, str(total), str(alertes), statut)

    console.print(table)
    console.print()
    console.print("[dim magenta]--- Analyse validée by hyacinthe ---[/dim magenta]\n")
