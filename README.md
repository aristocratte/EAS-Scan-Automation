# 🤖 Automation.py - Guide Complet

## 📋 Vue d'ensemble

`automation.py` est un script Python avancé qui automatise l'exécution de cinq outils de reconnaissance et d'analyse de sécurité. Il permet d'effectuer une analyse complète d'un domaine en utilisant une approche modulaire avec possibilité d'ignorer individuellement chaque étape.

## 🎯 Fonctionnalités Principales

### ✨ Workflow Intelligent

- **5 étapes configurables** : Chaque outil peut être exécuté ou ignoré individuellement
- **Logique de continuation** : Si une étape échoue ou est ignorée, le script continue automatiquement
- **Interface colorée** : Messages avec codes couleur pour une meilleure lisibilité
- **Gestion d'erreurs robuste** : Protection contre les crashes et récupération automatique

### 🔧 Outils Intégrés

1. **🔍 AMASS INTEL** - Collecte d'informations initiales
2. **🌐 AMASS ENUM** - Énumération des sous-domaines
3. **🔍 NMAP** - Scan des ports et services
4. **📧 CheckDMARC** - Analyse des configurations email
5. **🔒 TestSSL** - Audit SSL/TLS avec parallélisme avancé

### 🚀 Nouvelle Fonctionnalité : TestSSL Parallèle

Le script inclut maintenant un système de traitement parallèle pour TestSSL avec :

- **Surveillance des ressources système** en temps réel
- **Protection anti-crash** automatique
- **Suggestions intelligentes** du nombre de processus optimal
- **Monitoring continu** des performances pendant l'exécution

---

## 📦 Prérequis

### Outils Système Requis

```bash
# Vérification automatique lors de l'exécution
amass       # Reconnaissance de sous-domaines
nmap        # Scan de ports et services
testssl     # Audit SSL/TLS
checkdmarc  # Analyse des configurations email
```

### Dépendances Python

```bash
pip3 install psutil concurrent.futures
```

### Installation des Outils

```bash
# Utilisez le script d'installation fourni
python3 install-tools.py
```

---

## 🚀 Utilisation

### Lancement Basique

```bash
python3 automation.py
```

### Workflow Interactif

1. **Choix du type de scan** : `passive` ou `active`
2. **Saisie du domaine** : Format sans préfixe (ex: `example.com`)
3. **Gestion des répertoires** : Création automatique ou choix d'action
4. **Exécution des 5 étapes** : Confirmation individuelle pour chaque outil

---

## 📊 Description Détaillée des Étapes

### 🔍 ÉTAPE 1/5: AMASS INTEL

**Collecte d'informations sur le domaine cible**

```bash
Objectif : Découvrir des domaines et organisations liés
Options  : Mode passif ou actif
Sortie   : intel_output.txt
```

**Fonctionnalités :**

- Recherche WHOIS automatique
- Découverte d'organisations liées
- Mode actif pour recherches approfondies
- Affichage des résultats en temps réel

### 🌐 ÉTAPE 2/5: AMASS ENUM

**Énumération complète des sous-domaines**

```bash
Objectif : Découvrir tous les sous-domaines accessibles
Source   : Domaine unique ou liste intel
Sortie   : amass_output.txt + base de données graphique
```

**Options avancées :**

- Configuration personnalisée (config.yaml)
- Mode sans couleur pour parsing
- Génération de visualisations D3
- Support des listes de domaines

### 🔍 ÉTAPE 3/5: NMAP

**Scan des ports et détection de services**

```bash
Objectif : Identifier les services exposés
Modes    : Passif (top 100 ports) / Actif (scan complet)
Sortie   : Fichiers nmap (XML, nmap, gnmap)
```

**Protections intégrées :**

- Avertissements pour le mode actif
- Confirmation double pour scans intrusifs
- Génération de visualisations HTML
- Timeout et retry configurables

### 📧 ÉTAPE 4/5: CheckDMARC

**Analyse complète des configurations email**

```bash
Objectif : Vérifier SPF, DMARC, DKIM
Support  : Domaine unique ou liste de sous-domaines
Sortie   : Fichiers JSON individuels par domaine
```

**Analyses effectuées :**

- Configuration SPF (Sender Policy Framework)
- Politique DMARC (Domain-based Message Authentication)
- Enregistrements DKIM (DomainKeys Identified Mail)
- Validation des enregistrements DNS

### 🔒 ÉTAPE 5/5: TestSSL (NOUVEAU : Parallélisme Avancé)

**Audit SSL/TLS avec traitement parallèle intelligent**

```bash
Objectif : Analyser la sécurité SSL/TLS
Support  : Traitement parallèle pour listes de domaines
Sortie   : Fichiers JSON détaillés par domaine
```

## 🚀 Nouvelles Fonctionnalités TestSSL

### 📊 Surveillance des Ressources Système

Le script surveille automatiquement :

- **Utilisation CPU** : Pourcentage en temps réel
- **Mémoire disponible** : RAM libre en GB
- **Load Average** : Charge système
- **Nombre de cœurs** : Détection automatique

### 🛡️ Protection Anti-Crash

**Critères de protection :**

```python
CPU > 80%           # Arrêt si surcharge processeur
Mémoire > 85%       # Arrêt si RAM insuffisante
RAM libre < 1GB     # Protection mémoire minimale
Workers > CPU cores # Limitation intelligente
```

### 🎯 Suggestions Intelligentes

Le système calcule automatiquement :

```python
Max par CPU    = Cœurs - 1        # Garde 1 cœur libre
Max par RAM    = RAM_GB / 2       # ~2GB par worker
Suggestion     = min(CPU, RAM, 8) # Maximum 8 workers
```

### 🔄 Exécution Parallèle

**Fonctionnalités avancées :**

- **ThreadPoolExecutor** : Gestion professionnelle des threads
- **Timeout de 5 minutes** par domaine
- **Monitoring continu** des ressources pendant l'exécution
- **Fallback séquentiel** en cas de surcharge
- **Affichage du progrès** en temps réel

**Exemple d'exécution :**

```bash
[?] How many parallel processes do you want? (Suggested: 3, Max safe: 3): 2
[-] System Resources: CPU: 15.2%, Memory: 45.8%, Available RAM: 8.2GB
[-] Running testssl with 2 parallel processes...
[-] Progress: 5/19 (26.3%)
[+] TestSSL output for subdomain1.example.com saved (Duration: 45.2s)
[+] TestSSL output for subdomain2.example.com saved (Duration: 52.1s)
```

---

## 🎨 Codes Couleur du Terminal

| Couleur  | Code          | Usage        | Exemple                           |
| -------- | ------------- | ------------ | --------------------------------- |
| 🟢 Vert  | `\033[92m[+]` | Succès       | `[+] Scan completed successfully` |
| 🔴 Rouge | `\033[91m[!]` | Erreurs      | `[!] Command failed`              |
| 🟡 Jaune | `\033[93m[?]` | Questions    | `[?] Do you want to continue?`    |
| 🔵 Cyan  | `\033[96m[-]` | Informations | `[-] Running nmap scan...`        |
| 🟦 Bleu  | `\033[94m[>]` | Progression  | `[>] Moving to next step...`      |
| ⚫ Gris  | `\033[90m`    | Debug        | Commandes et détails techniques   |

---

## 📁 Structure des Outputs

```
output/
└── exemple.com/
    ├── amass/
    │   ├── intel_output.txt
    │   ├── amass_output.txt
    │   └── [base de données graphique]
    ├── nmap/
    │   ├── nmap.nmap
    │   ├── nmap.xml
    │   ├── nmap.gnmap
    │   └── nmap.html (optionnel)
    ├── checkdmarc/
    │   ├── exemple.com.json
    │   ├── subdomain1.exemple.com.json
    │   └── subdomain2.exemple.com.json
    └── testssl/
        ├── exemple.com.json
        ├── subdomain1.exemple.com.json
        └── subdomain2.exemple.com.json
```

---

## ⚙️ Configuration Avancée

### Variables d'Environnement

```bash
export AMASS_CONFIG="/path/to/config.yaml"
export NMAP_TIMING="T3"  # T1-T5
export TESTSSL_TIMEOUT="300"  # Secondes
```

### Optimisation des Performances

**Pour TestSSL Parallèle :**

- **Systèmes performants** : 4-8 workers recommandés
- **Systèmes limités** : 1-2 workers maximum
- **Surveillance continue** : Le script ajuste automatiquement

**Recommandations matériel :**

- **RAM minimum** : 4GB (8GB+ recommandé)
- **CPU** : Multi-cœur recommandé pour parallélisme
- **Stockage** : SSD pour performances optimales

---

## 🐛 Dépannage

### Problèmes Courants

**1. Outils manquants**

```bash
[!] amass is not installed.
Solution: python3 install-tools.py
```

**2. Permissions insuffisantes**

```bash
[!] Permission denied
Solution: chmod +x automation.py
```

**3. Erreurs de mémoire TestSSL**

```bash
[!] High resource usage detected! CPU: 95.2%, Memory: 92.1%
Action: Le script réduit automatiquement les workers
```

**4. Timeouts TestSSL**

```bash
[!] TestSSL timeout for subdomain.com
Cause: Domaine inaccessible ou très lent
Action: Continuez avec les autres domaines
```

### Logs et Debug

**Mode verbose :**

```python
# Dans le code, activez les prints de debug
DEBUG = True
```

**Surveillance ressources :**

```bash
# Pendant l'exécution, surveillez dans un autre terminal
htop
# ou
watch -n 1 'ps aux | grep testssl'
```

---

## 🔄 Intégration avec d'autres Scripts

### Génération de Dashboard Excel

```bash
# Après exécution d'automation.py
./generate_excel_dashboard.sh
# ou directement
python3 excel_security_dashboard.py output/exemple.com/checkdmarc/
```

### Beautification Amass

```bash
python3 amassbeautifier.py output/exemple.com/amass/amass_output.txt
```

### Cartographie des Domaines

```bash
python3 domain_mapper.py output/exemple.com/amass/amass_output.txt
```

---

## 📊 Métriques et Performance

### Benchmarks Typiques

| Étape       | Domaine Unique | 10 Sous-domaines     | 50 Sous-domaines      |
| ----------- | -------------- | -------------------- | --------------------- |
| Amass Intel | 30-60s         | 1-2 min              | 2-5 min               |
| Amass Enum  | 2-10 min       | 5-15 min             | 10-30 min             |
| Nmap        | 1-5 min        | 5-20 min             | 20-60 min             |
| CheckDMARC  | 10-30s         | 2-5 min              | 5-15 min              |
| TestSSL     | 1-3 min        | 3-10 min (parallèle) | 10-25 min (parallèle) |

### TestSSL Parallèle vs Séquentiel

**Exemple avec 20 sous-domaines :**

- **Séquentiel** : ~60 minutes (3 min/domaine)
- **Parallèle (4 workers)** : ~15 minutes (gain x4)
- **Parallèle (8 workers)** : ~8 minutes (gain x7-8)

---

## 🔧 Développement et Contribution

### Structure du Code

```python
# Fonctions principales
main()                    # Point d'entrée
run_intel_command()       # Étape 1
run_enum_amass()         # Étape 2
run_nmap()               # Étape 3
run_checkdmarc()         # Étape 4
run_testssl()            # Étape 5 (avec parallélisme)

# Fonctions utilitaires
check_system_resources() # Surveillance système
is_system_overloaded()   # Protection anti-crash
suggest_max_workers()    # Suggestions intelligentes
run_testssl_single()     # Exécution TestSSL unitaire
```

### Ajout de Nouveaux Outils

1. **Ajouter à list_tools** : `["amass", "nmap", "testssl", "checkdmarc", "nouveau_outil"]`
2. **Créer la fonction** : `run_nouveau_outil(domain, input_dir, output_dir)`
3. **Ajouter dans main()** : Appel de la nouvelle fonction
4. **Tester** : Vérification complète du workflow

---

## 📚 Ressources et Références

### Documentation Officielle

- [Amass Documentation](https://github.com/OWASP/Amass)
- [Nmap Reference Guide](https://nmap.org/book/)
- [TestSSL.sh Documentation](https://testssl.sh/)
- [CheckDMARC Documentation](https://domainaware.github.io/checkdmarc/)

### Liens Utiles

- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)
- [SSL/TLS Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)

---

## 📝 Changelog

### Version 3.0 (Actuelle)

- ✨ **Ajout du parallélisme TestSSL** avec surveillance intelligente
- 🛡️ **Protection anti-crash** automatique
- 🎨 **Interface colorée** pour tous les messages
- 🔄 **Logique de continuation** pour toutes les étapes
- 📊 **Monitoring des ressources** en temps réel

### Version 2.0

- 🌐 **Support des listes de domaines** pour tous les outils
- 🎯 **Logique de continuation** pour ignorer les étapes
- 📧 **Intégration CheckDMARC** complète
- 🔍 **Améliorations Nmap** avec protections

### Version 1.0

- 🚀 **Version initiale** avec 5 outils intégrés
- 📁 **Gestion automatique** des répertoires
- ⚙️ **Configuration flexible** pour chaque outil

---

## 📞 Support

Pour toute question ou problème :

1. **Vérifiez** que tous les outils sont installés : `python3 install-tools.py`
2. **Consultez** les logs d'erreur dans le terminal
3. **Testez** avec un domaine simple avant les listes importantes
4. **Surveillez** les ressources système pendant l'exécution

---

## 🎉 Conclusion

`automation.py` offre maintenant un workflow complet et robuste pour l'analyse de sécurité des domaines. Avec le nouveau système de parallélisme pour TestSSL, la surveillance intelligente des ressources et la protection anti-crash, vous disposez d'un outil professionnel capable de gérer des analyses à grande échelle tout en préservant la stabilité de votre système.

**Workflow recommandé :**

```bash
1. python3 automation.py          # Analyse complète
2. ./generate_excel_dashboard.sh  # Dashboard Excel
3. python3 domain_mapper.py       # Cartographie (optionnel)
```

---

_Dernière mise à jour : Juin 2025_
↓
Résultat final -> sous_domaines.txt + rapport nmap + testssl + checkdmarc
