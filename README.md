# Automation Script - BOC Tools

## Description

Ce script automatise l'exécution de plusieurs outils de reconnaissance et d'analyse de sécurité pour effectuer une analyse EAS (External Attack Surface) d'un domaine. L'utilisateur peut choisir entre un scan passif ou actif selon ses besoins.

## Outils supportés

- **Amass** : Reconnaissance de sous-domaines et cartographie de l'attack surface
- **Nmap** : Scan de ports et découverte de services
- **Testssl** : Analyse de la configuration SSL/TLS
- **Httpx** : Vérification des services HTTP/HTTPS
- **Checkdmarc** : Vérification des enregistrements DMARC

## Prérequis

Tous les outils listés ci-dessus doivent être installés sur le système. Le script vérifie automatiquement leur présence au démarrage.

## Utilisation

```bash
python3 automation.py
```

### Étapes d'exécution

1. **Vérification des outils** : Le script vérifie que tous les outils requis sont installés
2. **Choix du type de scan** : Passif ou Actif
3. **Saisie du domaine** : Entrer le domaine sans préfixe (ex: `example.com`)
4. **Gestion des dossiers** : Si un dossier existe déjà pour ce domaine, 3 options :
   - Skip (ne pas effectuer le scan)
   - Écraser les résultats existants
   - Créer un nouveau dossier avec timestamp
5. **Exécution des outils** selon la configuration choisie

## Structure des dossiers de sortie

```
output/
└── [domaine]/
    ├── amass/
    │   ├── intel_output.txt
    │   ├── amass_output.txt
    │   └── [base de données amass pour visualisation]
    ├── nmap/
    ├── testssl/
    ├── httpx/
    └── checkdmarc/
```

## Fonctionnalités principales

### Amass Intel

- Collecte d'informations de renseignement sur le domaine
- Mode passif ou actif
- Sortie des résultats dans `intel_output.txt`

### Amass Enum

- Énumération de sous-domaines
- Possibilité d'utiliser les résultats d'Intel comme input
- Support des fichiers de configuration personnalisés
- Option de génération de visualisation D3
- Mode sans couleur disponible

### Gestion des erreurs

- Vérification de l'existence des fichiers requis
- Gestion des erreurs d'exécution des commandes
- Messages d'erreur détaillés avec stdout/stderr

## Options disponibles

### Pour Amass Intel

- Mode passif/actif
- Sortie avec informations WHOIS

### Pour Amass Enum

- Scan d'un domaine unique ou d'une liste de sous-domaines
- Mode passif/actif
- Fichier de configuration personnalisé
- Option sans couleur
- Génération de visualisation

## Types de scan

### Scan Passif

- Utilise uniquement des sources publiques
- Plus discret mais moins complet
- Recommandé pour la reconnaissance initiale

### Scan Actif

- Interaction directe avec les cibles
- Plus intrusif mais plus complet
- Nécessite des autorisations appropriées

## Exemples d'utilisation

```bash
# Lancement du script
python3 automation.py

# Saisies exemple :
# Type de scan : passive
# Domaine : example.com
# Mode amass intel : passive
# Utiliser config personnalisé : no
# Générer visualisation : yes
```

## Fichiers générés

- `intel_output.txt` : Résultats de la collecte de renseignements
- `amass_output.txt` : Liste des sous-domaines découverts
- Base de données Amass pour la visualisation D3
- Fichiers de visualisation HTML (si demandé)

## Notes importantes

- Assurez-vous d'avoir les autorisations nécessaires avant de scanner un domaine
- Les scans actifs peuvent être détectés par les systèmes de sécurité
- Respectez les conditions d'utilisation des services tiers
- Les résultats peuvent varier selon la configuration et les sources disponibles

## Dépannage

### Erreur "Tool not installed"

Vérifiez que tous les outils requis sont installés et accessibles dans le PATH.

### Erreur "Failed to find domains in database"

Cette erreur peut survenir si la base de données Amass ne contient pas suffisamment de données pour la visualisation. Essayez d'abord un scan avec plus de sources ou vérifiez la configuration.

### Problèmes de permissions

Assurez-vous que le script a les permissions d'écriture dans le répertoire de travail.
