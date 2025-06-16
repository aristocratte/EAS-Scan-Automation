# This tool is used to automate the process of running several tools according to automation.md
# The user decides what kind of scan he wants to run (passive or active) and the tool will run the appropriate commands.
# This script allows you to perform an EAS analysis of a domain using various tools. 
from typing import List, Dict, Any  
import os
import subprocess
import concurrent.futures
import psutil
import time

list_tools = ["amass", "nmap", "testssl", "checkdmarc"]  

def check_system_resources() -> Dict[str, float]:
    """Check current system resources usage."""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    load_avg = os.getloadavg()[0] if hasattr(os, 'getloadavg') else 0
    
    return {
        "cpu_percent": cpu_percent,
        "memory_percent": memory.percent,
        "memory_available_gb": memory.available / (1024**3),
        "load_average": load_avg
    }

def is_system_overloaded(resources: Dict[str, float], max_workers: int) -> bool:
    """Check if system would be overloaded with given number of workers."""
    cpu_cores = psutil.cpu_count()
    
    # Critères de surcharge
    if resources["cpu_percent"] > 80:
        return True
    if resources["memory_percent"] > 85:
        return True
    if resources["memory_available_gb"] < 1.0:
        return True
    if resources["load_average"] > cpu_cores * 0.8:
        return True
    if max_workers > cpu_cores:
        return True
        
    return False

def suggest_max_workers() -> int:
    """Suggest maximum number of workers based on system resources."""
    cpu_cores = psutil.cpu_count()
    memory_gb = psutil.virtual_memory().total / (1024**3)
    
    # Base sur les ressources disponibles
    max_by_cpu = max(1, cpu_cores - 1)  # Garder au moins 1 core libre
    max_by_memory = max(1, int(memory_gb / 2))  # Environ 2GB par worker
    
    return min(max_by_cpu, max_by_memory, 8)  # Maximum 8 workers

def run_testssl_single(subdomain: str, testssl_dir: str) -> Dict[str, Any]:
    """Run testssl on a single subdomain."""
    testssl_command = ["testssl", "--quiet", "--color", "0", "--jsonfile", f"{testssl_dir}/{subdomain}.json", f"https://{subdomain}"]
    
    try:
        start_time = time.time()
        result = subprocess.run(testssl_command, check=True, capture_output=True, text=True, timeout=300)  # 5 min timeout
        end_time = time.time()
        
        return {
            "subdomain": subdomain,
            "success": True,
            "duration": end_time - start_time,
            "message": f"TestSSL output for {subdomain} saved to {testssl_dir}/{subdomain}.json"
        }
    except subprocess.TimeoutExpired:
        return {
            "subdomain": subdomain,
            "success": False,
            "error": "Timeout (5 minutes)",
            "message": f"TestSSL timeout for {subdomain}"
        }
    except subprocess.CalledProcessError as e:
        return {
            "subdomain": subdomain,
            "success": False,
            "error": str(e),
            "message": f"TestSSL command failed for {subdomain}"
        }  

def is_tool_installed(list_tools: str) -> bool:
    """Check if a tool is installed on the system."""
    for tool in list_tools:
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print(f"\033[91m[!] {tool} is not installed.\033[0m")
            return False
    print("\033[92m[+] All tools are installed.\033[0m")
    return True


def creating_output_directory(domain: str) -> str:
    """Create an output directory for the given domain."""
    output_dir = f"output/{domain}"
    
    # Check if directory already exists
    if os.path.exists(output_dir):
        print(f"\033[93m[!] Directory {output_dir} already exists.\033[0m")
        choice = input("What would you like to do?\n1. Skip (don't run scan)\n2. Overwrite existing results\n3. Create new directory with timestamp\nEnter your choice (1/2/3): ").strip()
        
        if choice == "1":
            print("\033[93m[-] Scan cancelled.\033[0m")
            return None
        elif choice == "2":
            print(f"\033[96m[-] Will overwrite existing directory: {output_dir}\033[0m")
        elif choice == "3":
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"output/{domain}_{timestamp}"
            print(f"\033[96m[-] Creating new directory: {output_dir}\033[0m")
        else:
            print("\033[93m[!] Invalid choice. Defaulting to overwrite.\033[0m")
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"\033[92m[+] Output directory created: {output_dir}\033[0m")
    return output_dir

def creating_tool_directories(domain: str) -> Dict[str, str]:
    """Create output directories for each tool."""
    base_dir = creating_output_directory(domain)
    
    # If user chose to skip, return None
    if base_dir is None:
        return None
    
    amass_dir = f"{base_dir}/amass"
    nmap_dir = f"{base_dir}/nmap"
    testssl_dir = f"{base_dir}/testssl"
    checkdmarc_dir = f"{base_dir}/checkdmarc"
    
    # Create tool directories
    os.makedirs(amass_dir, exist_ok=True)
    os.makedirs(nmap_dir, exist_ok=True)
    os.makedirs(testssl_dir, exist_ok=True)
    os.makedirs(checkdmarc_dir, exist_ok=True)
    
    print("\033[92m[+] Tool directories created.\033[0m")
    return {
        "amass": amass_dir,
        "nmap": nmap_dir,
        "testssl": testssl_dir,
        "checkdmarc": checkdmarc_dir
    }

def user_choices_input() -> Dict[str, Any]:
    """Get user choices for the scan type and domain."""
    scan_type = input("Enter the scan type (passive/active): ").strip().lower()
    if scan_type not in ["passive", "active"]:
        raise ValueError("Invalid scan type. Please enter 'passive' or 'active'.")

    domain = input("Enter the domain to scan without prefix (http(s):// or www. etc..):\n").strip()
    print("\033[90mExample: owasp.org or hackerone.com\033[0m")
    print(f"\033[96m[-] Domain entered: {domain}\033[0m")
    if not domain:
        raise ValueError("Domain cannot be empty.")
    
    return {"scan_type": scan_type, "domain": domain}

def amass_viz(db_dir: str) -> None:
    """Run amass viz command to generate D3 visualization."""
    # db_dir est le répertoire contenant la base de données graphique Amass (par exemple, output/{domain}/amass)
    amass_viz_command = [
        "amass", "viz",
        "-dir", db_dir,  # Spécifie le répertoire de la base de données graphique Amass
        "-d3"
    ]
    print(f"\033[90mExecuting Amass viz command: {' '.join(amass_viz_command)}\033[0m")
    try:
        # Utilisation de capture_output pour voir si amass viz imprime quelque chose d'utile
        result = subprocess.run(amass_viz_command, check=True, capture_output=True, text=True)
        print(f"\033[92m[+] Amass viz executed successfully.\033[0m")
        if result.stdout:
            print(f"\033[90mAmass viz stdout:\n{result.stdout}\033[0m")
        if result.stderr: # Amass imprime souvent des messages d'information sur stderr même en cas de succès
            print(f"\033[90mAmass viz stderr:\n{result.stderr}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"\033[91m[!] Amass viz command failed with exit code {e.returncode}:\033[0m")
        print(f"\033[90mCommand: {' '.join(e.cmd)}\033[0m")
        if e.stdout:
            print(f"\033[90mStdout:\n{e.stdout}\033[0m")
        if e.stderr: # C'est ici que "Failed to find the domains of interest in la base de données" apparaîtrait
            print(f"\033[91mStderr:\n{e.stderr}\033[0m")
        # Gérer l'échec si nécessaire

def run_intel_command(domain: str, amass_dir: str) -> None:
    """Run amass intel command to gather intelligence on the domain."""
    print("\n" + "="*60)
    print("\033[96m[-] STEP 1/5: AMASS INTEL - Information gathering\033[0m")
    print("="*60)
    
    confirmation = input(f"\033[93m[?] Do you want to run amass intel for {domain}? (yes/no): \033[0m").strip().lower()
    
    if confirmation != "yes":
        print(f"\033[93m[-] Skipping amass intel for {domain}.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return
    
    mode = input("Enter the mode for amass intel (passive/active): ").strip().lower()
    
    intel_command = [
        "amass", "intel", "-d", domain, "-whois", "-o", f"{amass_dir}/intel_output.txt"
    ]
    
    if mode == "active": # Insérer l'option après "intel"
        intel_command.insert(2, "-active")
    
    print(f"\033[94m[-] Running amass intel for {domain}...\033[0m")
    print(f"\033[90mAmass intel command: {' '.join(intel_command)}\033[0m")
    try:
        subprocess.run(intel_command, check=True, capture_output=True, text=True)  
        print(f"\033[92m[+] Amass intel output saved to {amass_dir}/intel_output.txt\033[0m")
        print("\033[96mResults are : \033[0m")
        with open(f"{amass_dir}/intel_output.txt", "r") as file:
            intel_output = file.read()
            print(intel_output)

    except subprocess.CalledProcessError as e:
        print(f"\033[91m[!] Amass intel command failed: {e}\033[0m")
        print(f"\033[91mError output (stderr): {e.stderr}\033[0m")
    





def run_enum_amass(domain: str, amass_dir: str, scan_type: str) -> None:
    """Run amass tool."""
    print("\n" + "="*60)
    print("\033[96m[-] STEP 2/5: AMASS ENUM - Subdomain enumeration\033[0m")
    print("="*60)
    
    confirmation = input(f"\033[93m[?] Do you want to run amass enum for {domain}? (yes/no): \033[0m").strip().lower()
    
    if confirmation != "yes":
        print(f"\033[93m[-] Skipping amass enum for {domain}.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return
    
    original_domain = domain  # Sauvegarder le domaine original
    use_file_list = False
    
    subdomain_list = input("Is your scan only a domain (1) or a list of subdomains from intel command (2) ? (1/2): ")
    if subdomain_list == "2":
        intel_file = os.path.join(amass_dir, "intel_output.txt")
        if not os.path.isfile(intel_file):
            print(f"\033[91m[!] intel_output.txt not found in {amass_dir}. Please run amass intel first.\033[0m")
            print("\033[94m    [>] Moving to next step...\033[0m")
            return
        print(f"Using intel_output.txt from {amass_dir} for subdomains.")
        use_file_list = True
    
    nocolor = input("Do you want to run amass without color? (yes/no): ").strip().lower()
    config = input("Do you want to use a custom config file? (yes/no): ").strip().lower()
    
    # Construire la commande amass
    amass_command = ["amass", "enum"]
    
    # Ajouter le type de scan
    if scan_type == "active":
        amass_command.append("-active")
    # Pour passive, on n'ajoute -passive
    elif scan_type == "passive":
        amass_command.append("-passive")
    else:
        print("Invalid scan type. Please enter 'passive' or 'active'.")
        return
    # Ajouter la source (domaine ou fichier)
    if use_file_list:
        amass_command.extend(["-df", os.path.join(amass_dir, "intel_output.txt")])
    else:
        amass_command.extend(["-d", original_domain])
    
    # Ajouter les options de sortie
    amass_command.extend(["-o", f"{amass_dir}/amass_output.txt", "-dir", amass_dir])
    
    # Ajouter les options supplémentaires
    if config == "yes":
        config_file = input("Enter the absolute path to the config file config.yaml (by default ~/.config/amass/config.yaml): ").strip()
        if not os.path.isfile(config_file):
            print(f"Config file {config_file} does not exist.")
            return
        amass_command.extend(["-config", config_file])
    
    if nocolor == "yes":
        amass_command.append("-nocolor")
    
    print(f"\033[94m[-] Running amass enum for {original_domain}...\033[0m")
    print(f"\033[90mAmass command: {' '.join(amass_command)}\033[0m") # Pour le débogage
    try:
        result = subprocess.run(amass_command, check=True, capture_output=True, text=True)
        print(f"\033[92m[+] Amass output saved to {amass_dir}/amass_output.txt\033[0m")
        if result.stderr: # Afficher stderr même en cas de succès, car amass peut y mettre des infos
            print(f"\033[90mAmass enum stderr:\n{result.stderr}\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"\033[91m[!] Amass enum command failed: {e}\033[0m")
        print(f"\033[90mCommand: {' '.join(e.cmd)}\033[0m")
        print(f"\033[91mError output (stdout): {e.stdout}\033[0m")
        print(f"\033[91mError output (stderr): {e.stderr}\033[0m")
        return
    
    viz_choice = input("\033[93m[?] Do you want to generate a visualization of the amass output? (yes/no): \033[0m").strip().lower()
    if viz_choice == "yes":
        print("\033[94m[-] Generating visualization...\033[0m")
        amass_viz(amass_dir)
        print("\033[92m[+] Visualization generation complete.\033[0m")
    
    print("\033[92m    [+] Amass enum completed successfully !\033[0m")
    return

def run_nmap(domain: str,  amass_dir: str, nmap_dir: str) -> None:
    """Run nmap tool."""
    print("\n" + "="*60)
    print("\033[96m[-] STEP 3/5: NMAP - Port and service scanning\033[0m")
    print("="*60)
    
    confirmation = input(f"\033[93m[?] Do you want to run nmap for {domain}? (yes/no): \033[0m").strip().lower()
    
    if confirmation != "yes":
        print(f"\033[93m[-] Skipping nmap for {domain}.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return
    
    original_domain = domain  # Sauvegarder le domaine original
    use_file_list = False

    subdomain_list = input("Is your scan only a domain (1) or a list of subdomains (2) ? (1/2): ")
    if subdomain_list == "2":
        live_hosts = os.path.join(amass_dir, "amass_output.txt")
        if not os.path.isfile(live_hosts):
            print(f"\033[91m[!] amass_output.txt not found in {amass_dir}. Please run amass first.\033[0m")
            print("\033[94m    [>] Moving to next step...\033[0m")
            return
        print(f"\033[96m[-] Using amass_output.txt from {amass_dir} for nmap scan.\033[0m")
        use_file_list = True
    elif subdomain_list == "1":
        live_hosts = original_domain
    else:
        print("\033[91m[!] Invalid choice. Please enter '1' or '2'.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return
    
    mode = input("Enter the mode for nmap (passive/active): ").strip().lower()
    
    # Construire la commande nmap dans le bon ordre
    nmap_command = ["nmap"]
    
    if mode == "active":
        nmap_command.extend(["-sS", "-sV", "-sC", "-A", "-T4", "-p-", "--max-retries", "2", "--open"])
        print("\033[91mARE YOU SURE YOU WANT TO RUN NMAP IN ACTIVE MODE ?\033[0m")
        print("\033[93mThis Scan will be more intrusive and may trigger alerts on the target system.\033[0m")
        print("\033[94mIt is using SYN scan, service version detection, script scanning, OS detection, and aggressive timing.\033[0m")
        print("\033[92mIf you are not sure please select 'passive' option\033[0m")
        # Ask for confirmation
        active_confirmation = input("\033[91m[?] Do you want to proceed with the active scan? (yes/no): \033[0m").strip().lower()
        if active_confirmation != "yes":
            print("\033[93m[-] Active scan cancelled.\033[0m")
            print("\033[94m    [>] Moving to next step...\033[0m")
            return
    elif mode == "passive":
        nmap_command.extend(["-T3", "-Pn", "--top-ports", "100", "--open"])
    else:
        print("\033[91m[!] Invalid mode. Please enter 'passive' or 'active'.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return
    
    if use_file_list:
        nmap_command.extend(["-iL", live_hosts])
    else:
        nmap_command.append(domain)
    # Ajouter l'option de sortie
    nmap_command.extend(["-oA", f"{nmap_dir}/nmap"])

    print(f"\033[94m[-] Running nmap for {domain}...\033[0m")
    print(f"\033[90mNmap command: {' '.join(nmap_command)}\033[0m")
    try:
        subprocess.run(nmap_command, check=True, capture_output=True, text=True)
        print(f"\033[92m[+] Nmap output saved to {nmap_dir}\033[0m")
        visualization_choice = input("\033[93m[?] Do you want to generate a visualization of the nmap output? (yes/no): \033[0m").strip().lower()
        if visualization_choice == "yes":
            print("\033[94m[-] Generating nmap visualization...\033[0m")
            subprocess.run(["xsltproc", f"{nmap_dir}/nmap.xml", "-o", f"{nmap_dir}/nmap.html"], check=True)
            print(f"\033[92m[+] Nmap visualization saved to {nmap_dir}/nmap.html\033[0m")
            print("\033[92m[-] Nmap visualization generation complete.\033[0m")
    except subprocess.CalledProcessError as e:
        print(f"\033[91m[!] Nmap command failed: {e}\033[0m")
        print(f"\033[91mError output (stderr): {e.stderr}\033[0m")
    
    print("\033[92m    [+] Nmap scan completed successfully !\033[0m")


def run_checkdmarc(domain: str, amass_dir: str, checkdmarc_dir: str) -> None:
    """Run checkdmarc tool."""
    print("\n" + "="*60)
    print(f"\033[96m[-] STEP 4/5: CheckDMARC Analysis - {domain}\033[0m")
    print("="*60)
    
    original_domain = domain  # Sauvegarder le domaine original
    use_file_list = False

    confirmation = input(f"\033[93m[?] Do you want to run checkdmarc for {domain} ? (yes/no): \033[0m").strip().lower()
    if confirmation != "yes":
        print(f"\033[93m[-] Skipping checkdmarc for {domain}.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return


    subdomain_list = input("Is your scan only a domain (1) or a list of subdomains (2) ? (1/2): ")
    if subdomain_list == "2":
        subdomain_file = os.path.join(amass_dir, "amass_output.txt")
        if not os.path.isfile(subdomain_file):
            print(f"\033[91m[!] amass_output.txt not found in {amass_dir}. Please run amass first.\033[0m")
            print("\033[94m    [>] Moving to next step...\033[0m")
            return
        print(f"\033[96m[-] Using amass_output.txt from {amass_dir} for checkdmarc scan.\033[0m")
        use_file_list = True
    elif subdomain_list == "1":
        use_file_list = False
    else:
        print("\033[91m[!] Invalid choice. Please enter '1' or '2'.\033[0m")
        print("\033[94m    [>] Moving to next step...\033[0m")
        return
        
    
    
    # Construire la commande checkdmarc et faire une boucle for pour chaque sous-domaine présent dans le fichier amass_output.txt. Ecrire ensuite le fichier sous format json avec le nom du domaine en préfixe.
    if use_file_list:
        subdomains = []
        with open(subdomain_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        if not subdomains:
            print("\033[91m[!] No subdomains found in the file. Please check the file content.\033[0m")
            print("\033[94m    [>] Moving to next step...\033[0m")
            return
        
        print(f"\033[94m[-] Running checkdmarc for {len(subdomains)} subdomains...\033[0m")
        for sub in subdomains:
            checkdmarc_command = ["checkdmarc", sub, "-o", f"{checkdmarc_dir}/{sub}.json"]
            print(f"\033[90mCheckDMARC command: {' '.join(checkdmarc_command)}\033[0m")
            try:
                subprocess.run(checkdmarc_command, check=True)
                print(f"\033[92m[+] CheckDMARC output for {sub} saved to {checkdmarc_dir}/{sub}.json\033[0m")
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[!] CheckDMARC command failed for {sub}: {e}\033[0m")
                continue
    else:
        checkdmarc_command = ["checkdmarc", original_domain, "-o", f"{checkdmarc_dir}/{original_domain}.json"]
        print(f"\033[96m[-] Using domain {original_domain} for checkdmarc scan.\033[0m")
        print(f"\033[90mCheckDMARC command: {' '.join(checkdmarc_command)}\033[0m")
        try:
            subprocess.run(checkdmarc_command, check=True)
            print(f"\033[92m[+] CheckDMARC output saved to {checkdmarc_dir}/{original_domain}.json\033[0m")
        except subprocess.CalledProcessError as e:
            print(f"\033[91m[!] CheckDMARC command failed: {e}\033[0m")
            print("\033[94m    [>] Moving to next step...\033[0m")
            return
    
    print("\033[92m    [+] CheckDMARC analysis completed successfully !\033[0m")
    report = input("\033[93m[?] Do you want to generate a report for the checkdmarc results? (yes/no): \033[0m").strip().lower()
    if report == "yes":
        import glob
        json_files = glob.glob(f"{checkdmarc_dir}/*.json")
        
        if json_files:
            # Construire la commande avec tous les fichiers JSON trouvés
            cmd = ["python3", "checkdmarc_enhanced.py"] + json_files + ["-excel"]
            print(f"\033[90mRunning Excel generation: python3 checkdmarc_enhanced.py {len(json_files)} files -excel\033[0m")
            
            try:
                # Exécuter la commande directement sans changer de répertoire
                result = subprocess.run(cmd, check=True, capture_output=True, text=True)
                print("\033[92m[+] CheckDMARC Excel report generated successfully.\033[0m")
                print(f"\033[96m[-] Report should be in the same directory as the script\033[0m")
                
                # Optionnel : afficher la sortie du script
                if result.stdout:
                    print(f"\033[90m{result.stdout}\033[0m")
                    
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[!] Excel generation failed: {e}\033[0m")
                if e.stderr:
                    print(f"\033[91mError details: {e.stderr}\033[0m")
                if e.stdout:
                    print(f"\033[90mOutput: {e.stdout}\033[0m")
        else:
            print("\033[93m[!] No JSON files found in checkdmarc directory.\033[0m")
    else:
        print("\033[93m[-] Skipping report generation for checkdmarc results.\033[0m")
    




def run_testssl(domain: str, amass_dir: str, testssl_dir: str) -> None:
    """Run testssl tool."""
    print("\n" + "="*60)
    print(f"\033[96m[-] STEP 5/5: TestSSL Analysis - {domain}\033[0m")
    print("="*60)
    
    original_domain = domain  # Sauvegarder le domaine original
    use_file_list = False

    confirmation = input(f"\033[93m[?] Do you want to run testssl for {domain} ? (yes/no): \033[0m").strip().lower()
    
    if confirmation != "yes":
        print(f"\033[93m[-] Skipping testssl for {domain}.\033[0m")
        print("\033[94m    [>] TestSSL scan completed (skipped by user)\033[0m")
        return


    subdomain_list = input("Is your scan only a domain (1) or a list of subdomains (2) ? (1/2): ")
    if subdomain_list == "2":
        subdomain_file = os.path.join(amass_dir, "amass_output.txt")
        if not os.path.isfile(subdomain_file):
            print(f"\033[91m[!] amass_output.txt not found in {amass_dir}. Please run amass first.\033[0m")
            print("\033[94m    [>] TestSSL scan completed (missing file)\033[0m")
            return
        print(f"\033[96m[-] Using amass_output.txt from {amass_dir} for testssl scan.\033[0m")
        use_file_list = True
    elif subdomain_list == "1":
        use_file_list = False
    else:
        print("\033[91m[!] Invalid choice. Please enter '1' or '2'.\033[0m")
        print("\033[94m    [>] TestSSL scan completed (invalid choice)\033[0m")
        return
    
    
    
    # Construire la commande testssl
    if use_file_list:
        with open(subdomain_file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
        
        if not subdomains:
            print("\033[91m[!] No subdomains found in the file. Please check the file content.\033[0m")
            print("\033[94m    [>] TestSSL scan completed (no subdomains)\033[0m")
            return
        
        print(f"\033[94m[-] Running testssl for {len(subdomains)} subdomains...\033[0m")
        for sub in subdomains:
            testssl_command = ["testssl", "--quiet", "--color","0", "--parallel", "--hints", "--wide", "--jsonfile", f"{testssl_dir}/{sub}.json", "--htmlfile", f"{testssl_dir}/{sub}.html", f"https://{sub}"]
            print(f"\033[90mTestSSL command: {' '.join(testssl_command)}\033[0m")
            try:
                subprocess.run(testssl_command, check=True)
                print(f"\033[92m[+] TestSSL output for {sub} saved to {testssl_dir}/{sub}.json\033[0m")
            except subprocess.CalledProcessError as e:
                print(f"\033[91m[!] TestSSL command failed for {sub}: {e}\033[0m")
                continue
    else:
        testssl_command = ["testssl", "--quiet", "--color","0", "--jsonfile", f"{testssl_dir}/{original_domain}.json", f"https://{original_domain}"]
        print(f"\033[96m[-] Using domain {original_domain} for testssl scan.\033[0m")
        print(f"\033[90mTestSSL command : {' '.join(testssl_command)}\033[0m")
        try:
            subprocess.run(testssl_command, check=True)
            print(f"\033[92m[+] TestSSL output saved to {testssl_dir}/{original_domain}.json\033[0m")
        except subprocess.CalledProcessError as e:
            print(f"\033[91m[!] TestSSL command failed: {e}\033[0m")
            print("\033[94m    [>] TestSSL scan completed (command error)\033[0m")
            return
    
    print("\033[92m    [+] TestSSL analysis completed successfully !\033[0m")

def main():
    """Main function to run the automation script."""
    
    if not is_tool_installed(list_tools):
        print("\033[91m[!] Please install the required tools and try again.\033[0m")
        return

    user_choices = user_choices_input()
    scan_type = user_choices["scan_type"]
    domain = user_choices["domain"]

    output_dirs = creating_tool_directories(domain)
    
    # Check if user chose to skip
    if output_dirs is None:
        return
    
    amass_dir = output_dirs["amass"]
    nmap_dir = output_dirs["nmap"]
    testssl_dir = output_dirs["testssl"]
    chekcdmarc_dir = output_dirs["checkdmarc"]

    run_intel_command(domain, amass_dir)
    run_enum_amass(domain, amass_dir, scan_type)
    run_nmap(domain, amass_dir, nmap_dir)
    run_checkdmarc(domain, amass_dir, chekcdmarc_dir)
    run_testssl(domain, amass_dir, testssl_dir)
    print("\033[92m[+] Automation script completed successfully.\033[0m")

if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        print(f"\033[91m[!] Error: {e}\033[0m")
    except Exception as e:
        print(f"\033[91m[!] An unexpected error occurred: {e}\033[0m")






