# This tool is used to automate the process of running several tools according to automation.md
# The user decides what kind of scan he wants to run (passive or active) and the tool will run the appropriate commands.
# This script allows you to perform an EAS analysis of a domain using various tools. 
from typing import List, Dict, Any  
import os
import subprocess

list_tools = ["amass", "nmap", "testssl", "httpx", "checkdmarc"]  

def is_tool_installed(list_tools: str) -> bool:
    """Check if a tool is installed on the system."""
    for tool in list_tools:
        if subprocess.call(["which", tool], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            print(f"{tool} is not installed.")
            return False
    print("All tools are installed.")
    return True


def creating_output_directory(domain: str) -> str:
    """Create an output directory for the given domain."""
    output_dir = f"output/{domain}"
    
    # Check if directory already exists
    if os.path.exists(output_dir):
        print(f"Directory {output_dir} already exists.")
        choice = input("What would you like to do?\n1. Skip (don't run scan)\n2. Overwrite existing results\n3. Create new directory with timestamp\nEnter your choice (1/2/3): ").strip()
        
        if choice == "1":
            print("Scan cancelled.")
            return None
        elif choice == "2":
            print(f"Will overwrite existing directory: {output_dir}")
        elif choice == "3":
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"output/{domain}_{timestamp}"
            print(f"Creating new directory: {output_dir}")
        else:
            print("Invalid choice. Defaulting to overwrite.")
    
    os.makedirs(output_dir, exist_ok=True)
    print(f"Output directory created: {output_dir}")
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
    httpx_dir = f"{base_dir}/httpx"
    checkdmarc_dir = f"{base_dir}/checkdmarc"
    
    # Create tool directories
    os.makedirs(amass_dir, exist_ok=True)
    os.makedirs(nmap_dir, exist_ok=True)
    os.makedirs(testssl_dir, exist_ok=True)
    os.makedirs(httpx_dir, exist_ok=True)
    os.makedirs(checkdmarc_dir, exist_ok=True)
    
    print("Tool directories created.")
    return {
        "amass": amass_dir,
        "nmap": nmap_dir,
        "testssl": testssl_dir,
        "httpx": httpx_dir,
        "checkdmarc": checkdmarc_dir
    }

def user_choices_input() -> Dict[str, Any]:
    """Get user choices for the scan type and domain."""
    scan_type = input("Enter the scan type (passive/active): ").strip().lower()
    if scan_type not in ["passive", "active"]:
        raise ValueError("Invalid scan type. Please enter 'passive' or 'active'.")

    domain = input("Enter the domain to scan without prefix (http(s):// or www. etc..):\n").strip()
    print("Example: owasp.org or hackerone.com")
    print(f"Domain entered: {domain}")
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
    print(f"Executing Amass viz command: {' '.join(amass_viz_command)}")
    try:
        # Utilisation de capture_output pour voir si amass viz imprime quelque chose d'utile
        result = subprocess.run(amass_viz_command, check=True, capture_output=True, text=True)
        print(f"Amass viz executed successfully.")
        if result.stdout:
            print(f"Amass viz stdout:\n{result.stdout}")
        if result.stderr: # Amass imprime souvent des messages d'information sur stderr même en cas de succès
            print(f"Amass viz stderr:\n{result.stderr}")
    except subprocess.CalledProcessError as e:
        print(f"Amass viz command failed with exit code {e.returncode}:")
        print(f"Command: {' '.join(e.cmd)}")
        if e.stdout:
            print(f"Stdout:\n{e.stdout}")
        if e.stderr: # C'est ici que "Failed to find the domains of interest in la base de données" apparaîtrait
            print(f"Stderr:\n{e.stderr}")
        # Gérer l'échec si nécessaire

def run_enum_amass(domain: str, amass_dir: str, scan_type: str) -> None: # Type de retour corrigé en None
    """Run amass tool."""
    amass_intel_command =[
        "amass", "intel", "-d", domain, 
    ] 
    amass_command = [
        "amass", "enum", "-d", domain, "-o", f"{amass_dir}/amass_output.txt", "-dir", amass_dir
    ]
    confirmation = input(f"Do you want to run amass for {domain}? (yes/no): ").strip().lower()
    nocolor = input("Do you want to run amass without color? (yes/no): ").strip().lower()
    config = input("Do you want to use a custom config file? (yes/no): ").strip().lower()
    
    if config == "yes":
        config_file = input("Enter the absolute path to the config file config.yaml (by default ~/.config/amass/config.yaml): ").strip()
        if not os.path.isfile(config_file):
            print(f"Config file {config_file} does not exist.")
            return
        amass_command.extend(["-config", config_file])
    
    if scan_type == "active":
        active_options = ["-active", "-ip", "-brute"]
        insert_pos = amass_command.index("enum") + 1
        for i, opt in enumerate(active_options):
            amass_command.insert(insert_pos + i, opt)
    if nocolor == "yes":
        amass_command.extend(["-nocolor"])
    
    if confirmation == "yes":
        print(f"[-] Running amass for {domain}...")
        print(f"Amass command: {' '.join(amass_command)}") # Pour le débogage
        try:
            result = subprocess.run(amass_command, check=True, capture_output=True, text=True)
            print(f"Amass output saved to {amass_dir}/amass_output.txt")
            if result.stderr: # Afficher stderr même en cas de succès, car amass peut y mettre des infos
                print(f"Amass enum stderr:\n{result.stderr}")
        except subprocess.CalledProcessError as e:
            print(f"Amass enum command failed: {e}")
            print(f"Command: {' '.join(e.cmd)}")
            print(f"Error output (stdout): {e.stdout}")
            print(f"Error output (stderr): {e.stderr}")
            return
    
    viz_choice = input("Do you want to generate a visualization of the amass output? (yes/no): ").strip().lower()
    if viz_choice == "yes":
        print("Generating visualization...")

        amass_viz(amass_dir)
        print("Visualization generation complete.")
    return




def main():
    """Main function to run the automation script."""
    if not is_tool_installed(list_tools):
        print("Please install the required tools and try again.")
        return

    user_choices = user_choices_input()
    scan_type = user_choices["scan_type"]
    domain = user_choices["domain"]

    output_dirs = creating_tool_directories(domain)
    
    # Check if user chose to skip
    if output_dirs is None:
        return
    
    amass_dir = output_dirs["amass"]

    run_enum_amass(domain, amass_dir, scan_type)

if __name__ == "__main__":
    try:
        main()
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")






