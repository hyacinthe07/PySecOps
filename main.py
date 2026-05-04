#!/usr/bin/env python3
import pyfiglet
import datetime
import platform
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

# IMPORTATIONS DES 4 MODULES
from scanner import lancer_scan
from analyser import analyser_logs
from securite import menu_securite
from vuln_scanner import scanner_vuln

console = Console()

def get_system_info():
    now = datetime.datetime.now().strftime("%d/%m/%Y - %H:%M:%S")
    os_info = f"{platform.system()} {platform.release()}"
    user = f"{platform.node()}"
    return f"[bold cyan]OS:[/bold cyan] {os_info}  |  [bold cyan]User:[/bold cyan] {user}  |  [bold cyan]Time:[/bold cyan] {now}"

def afficher_banniere():
    console.clear()
    
    # On récupère la date et l'heure actuelle
    heure_connexion = datetime.datetime.now().strftime("%d/%m/%Y - %H:%M:%S")
    
    # Génération du texte ASCII
    ascii_banner = pyfiglet.figlet_format("PYSECOPS", font="slant")
    banner_text = Text(ascii_banner, style="bold bright_green", justify="center")
    
    # Signature + Date/Heure séparées par un joli séparateur " | "
    bas_de_page = Text(f"      by hyacinthe  |  {heure_connexion}", style="bold magenta", justify="center")
    
    # On assemble le tout
    console.print(Panel(
        banner_text + "\n" + bas_de_page, 
        box=box.DOUBLE, 
        border_style="bright_blue",
        padding=(1, 4)
    ))
def afficher_menu():
    menu_content = Text()
    menu_content.append("\n    "); menu_content.append("[1]", style="bold bright_white"); menu_content.append("  Scanner de ports (Réseau)\n", style="bold cyan")
    menu_content.append("    "); menu_content.append("[2]", style="bold bright_white"); menu_content.append("  Analyseur de logs (Intrusions)\n", style="bold cyan")
    menu_content.append("    "); menu_content.append("[3]", style="bold bright_white"); menu_content.append("  Outils SecOps (Mdp / Hash)\n", style="bold cyan")
    menu_content.append("    "); menu_content.append("[4]", style="bold bright_white"); menu_content.append("  Scan de vulnérabilités (Web)\n", style="bold cyan")
    menu_content.append("    "); menu_content.append("[Q]", style="bold bright_white"); menu_content.append("  Quitter l'application\n", style="bold red")
    console.print(Panel(menu_content, title="[bold white][ MODULES ][/bold white]", border_style="green", box=box.ROUNDED))

def main():
    afficher_banniere()
    while True:
        afficher_menu()
        prompt_style = "[bold red]┌──([/bold red][bold white]root㉿pysecops[/bold white][bold red])─[/bold red][bold green]~[/bold green][bold red])\n[bold red]└─[/bold red][bold white]#[/bold white] "
        choix = console.input(prompt_style)
        
        if choix == "1":
            cible = console.input("\n[bold cyan]Entrez l'IP cible (ex: 127.0.0.1) > [/bold cyan]")
            if cible: lancer_scan(cible)
            else: console.print("[bold red][-][/bold red] Erreur : Aucune IP saisie.\n")
            
        elif choix == "2":
            fichier = console.input("\n[bold cyan]Entrez le fichier log (ex: access.log) > [/bold cyan]")
            if fichier: analyser_logs(fichier)
            else: console.print("[bold red][-][/bold red] Erreur : Aucun fichier saisi.\n")
            
        elif choix == "3":
            console.print("\n[bold yellow][*][/bold yellow] Accès au module SecOps...")
            menu_securite()
            
        elif choix == "4":
            console.print("\n[bold yellow][*][/bold yellow] Accès au scanner Web...")
            url = console.input("[bold cyan]Entrez l'URL (ex: testphp.vulnweb.com) > [/bold cyan]")
            if url: scanner_vuln(url)
            else: console.print("[bold red][-][/bold red] Erreur : Aucune URL saisie.\n")
            
        elif choix.upper() == "Q":
            console.print("\n[bold red][!][/bold red] Arrêt immédiat. Au revoir !\n")
            break
        else:
            console.print("\n[bold red][-][/bold red] Commande inconnue.\n")

if __name__ == "__main__":
    main()
