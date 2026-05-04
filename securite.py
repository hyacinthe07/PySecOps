import secrets
import string
import hashlib
import re
from rich.console import Console
from rich.panel import Panel

console = Console()

def generer_mdp(longueur=16):
    """Génère un mot de passe cryptographiquement sécurisé"""
    # Alphabet complet : lettres, chiffres, symboles
    alphabet = string.ascii_letters + string.digits + string.punctuation
    
    # secrets.choice est plus sûr que random.choice pour la sécurité
    mot_de_passe = ''.join(secrets.choice(alphabet) for _ in range(longueur))
    console.print(f"\n[bold green][+][/bold green] Mot de passe généré : [bold white]{mot_de_passe}[/bold white]\n")

def hacher_texte(texte):
    """Transforme un texte en Hash SHA-256"""
    # On encode le texte en bytes, puis on le hache
    texte_bytes = texte.encode('utf-8')
    hash_obj = hashlib.sha256(texte_bytes)
    hash_hex = hash_obj.hexdigest()
    
    console.print(f"\n[bold cyan][*][/bold cyan] Texte original : [dim white]{texte}[/dim white]")
    console.print(f"[bold green][+][/bold green] Hash SHA-256  : [bold white]{hash_hex}[/bold white]\n")

def verifier_force_mdp(mdp):
    """Évalue la sécurité d'un mot de passe"""
    score = 0
    if len(mdp) >= 8: score += 1
    if len(mdp) >= 12: score += 1
    if re.search(r"[A-Z]", mdp): score += 1 # Majuscules
    if re.search(r"[a-z]", mdp): score += 1 # Minuscules
    if re.search(r"\d", mdp): score += 1    # Chiffres
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", mdp): score += 1 # Symboles

    etat = ""
    couleur = ""
    if score <= 2:
        etat = "FAIBLE (Risque élevé)"
        couleur = "bold red"
    elif score <= 4:
        etat = "MOYEN (Acceptable)"
        couleur = "bold yellow"
    else:
        etat = "FORT (Excellente sécurité)"
        couleur = "bold green"

    console.print(f"\n[*] Score de sécurité : {score}/6")
    console.print(f"[{couleur}][+][/{couleur}] Statut : [{couleur}]{etat}[/{couleur}]\n")

def menu_securite():
    """Sous-menu dédié à la sécurité"""
    console.print(Panel("[bold white]1. Générer un mot de passe sécurisé\n2. Hacher un texte (SHA-256)\n3. Vérifier la force d'un mot de passe\n0. Retour au menu principal[/bold white]", 
                       title="[bold white][ SECOPS TOOLKIT ][/bold white]", border_style="bright_yellow"))
    
    choix = console.input("[bold red]└─[/bold red][bold white]SecOps > [/bold white]")
    
    if choix == "1":
        longueur = console.input("[bold cyan]Longueur du mot de passe (défaut 16) > [/bold cyan]")
        if not longueur.isdigit():
            longueur = 16
        generer_mdp(int(longueur))
    elif choix == "2":
        texte = console.input("[bold cyan]Texte à hacher > [/bold cyan]")
        if texte:
            hacher_texte(texte)
        else:
            console.print("[bold red][-][/bold red] Erreur : Texte vide.\n")
    elif choix == "3":
        mdp = console.input("[bold cyan]Entrez le mot de passe à tester > [/bold cyan]")
        if mdp:
            verifier_force_mdp(mdp)
        else:
            console.print("[bold red][-][/bold red] Erreur : Mot de passe vide.\n")
    elif choix == "0":
        return # Revient au menu principal
    else:
        console.print("[bold red][-][/bold red] Choix inconnu.\n")
