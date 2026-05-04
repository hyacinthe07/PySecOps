import socket
from rich.console import Console

console = Console()

def lancer_scan(target):
    console.print(f"\n[bold yellow][*][/bold yellow] Initialisation du scanner réseau...")
    console.print(f"[bold yellow][*][/bold yellow] Cible : [bold cyan]{target}[/bold cyan]")
    
    # NOUVEAU : On vérifie d'abord si la cible est joignable (simule un mini-Ping)
    console.print("[bold yellow][*][/bold yellow] Vérification de l'hôte...", style="yellow")
    try:
        socket.gethostbyname(target)
        console.print(f"[bold green][+][/bold green] Hôte [bold white]{target}[/bold white] est en ligne. Début du scan des ports.\n")
    except socket.gaierror:
        console.print(f"[bold red][-][/bold red] Erreur : Hôte {target} injoignable ou nom de domaine inconnu.\n")
        return # On arrête le script ici si la cible n'existe pas

    # Variables
    ports_ouverts = 0
    
    console.print("[dim white]Scanning 1-1024...[/dim white]\n")

    # Boucle de scan des 1024 premiers ports (les plus courants)
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4) # 0.4 seconde max par port (assez rapide sans être trop agressif)

        resultat = s.connect_ex((target, port))

        if resultat == 0:
            console.print(f"[bold green][+][/bold green] Port {port}/tcp : [bold white]OUVERT[/bold white]")
            ports_ouverts += 1

        s.close() # Toujours fermer le socket pour libérer la machine
        
    # Résumé de fin
    console.print(f"\n[bold cyan][*][/bold cyan] Scan terminé ! [bold white]{ports_ouverts}[/bold white] port(s) ouvert(s) trouvé(s) sur {target}.\n")
    console.print("[dim magenta]--- Scan validé by hyacinthe ---[/dim magenta]\n")
