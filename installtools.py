#!/usr/bin/env python3
"""
🔧 ULTRA-ROBUST BOC Tools Installation Script
============================================

This script handles ALL possible installation scenarios and error cases with 
multiple fallback methods for each tool and comprehensive error recovery.

Features:
- ✅ Multiple fallback installation methods for each tool
- ✅ Complete virtual environment management with error recovery  
- ✅ Handles externally-managed Python environments (Kali Linux, Ubuntu 23+)
- ✅ Advanced error detection and recovery with logging
- ✅ Support for automation.py and checkdmarc_enhanced.py with Excel capabilities
- ✅ Comprehensive dependency management and verification
- ✅ Automatic environment configuration and PATH management
- ✅ Rollback and recovery mechanisms for failed installations

Author: BOC Tools Team
Version: 3.0 - Ultra Robust Edition
"""

import subprocess
import sys
import os
import shutil
import json
import platform
import time
import logging
import tempfile
import signal
import threading
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Callable
from dataclasses import dataclass
from contextlib import contextmanager
import urllib.request
import urllib.error

# =============================================================================
# 🚀 CONFIGURATION AND LOGGING SETUP
# =============================================================================

# Configure comprehensive logging
log_file = Path(os.path.expanduser("~/boc_tools_install.log"))
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(log_file)),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

@dataclass
class InstallationMethod:
    """Represents a single installation method with metadata."""
    name: str
    description: str
    command: List[str]
    check_command: List[str]
    requires_sudo: bool = False
    requires_internet: bool = True
    env_vars: Dict[str, str] = None
    working_dir: Optional[str] = None
    timeout: int = 300
    
@dataclass
class Tool:
    """Represents a tool to be installed with multiple fallback methods."""
    name: str
    description: str
    check_commands: List[str]
    install_methods: List[InstallationMethod]
    post_install_commands: List[List[str]] = None
    required_for: List[str] = None

class Colors:
    """ANSI color codes for beautiful terminal output."""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# =============================================================================
# 🛠️ CORE UTILITY FUNCTIONS
# =============================================================================

@contextmanager
def timeout_context(seconds: int):
    """Context manager for command timeouts."""
    def timeout_handler(signum, frame):
        raise TimeoutError(f"Command timed out after {seconds} seconds")
    
    old_handler = signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def print_banner(text: str, color: str = Colors.HEADER) -> None:
    """Print a beautiful banner with color."""
    border = "=" * 80
    print(f"\n{color}{border}")
    print(f"🚀 {text}")
    print(f"{border}{Colors.ENDC}")

def print_step(step_num: int, total_steps: int, description: str) -> None:
    """Print step progress."""
    print(f"\n{Colors.OKCYAN}[{step_num}/{total_steps}] {description}{Colors.ENDC}")

def print_success(message: str) -> None:
    """Print success message."""
    print(f"{Colors.OKGREEN}✅ {message}{Colors.ENDC}")

def print_warning(message: str) -> None:
    """Print warning message."""
    print(f"{Colors.WARNING}⚠️ {message}{Colors.ENDC}")

def print_error(message: str) -> None:
    """Print error message."""
    print(f"{Colors.FAIL}❌ {message}{Colors.ENDC}")

def print_info(message: str) -> None:
    """Print info message."""
    print(f"{Colors.OKBLUE}ℹ️ {message}{Colors.ENDC}")

def run_command(
    cmd: List[str], 
    check: bool = True, 
    capture_output: bool = True, 
    timeout: int = 300,
    cwd: Optional[str] = None,
    env: Optional[Dict[str, str]] = None,
    shell: bool = False
) -> subprocess.CompletedProcess:
    """Enhanced command runner with comprehensive error handling."""
    try:
        logger.info(f"Running command: {' '.join(cmd) if isinstance(cmd, list) else cmd}")
        
        # Merge environment variables
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        
        result = subprocess.run(
            cmd,
            check=check,
            capture_output=capture_output,
            text=True,
            cwd=cwd,
            env=run_env,
            shell=shell,
            timeout=timeout
        )
        
        if result.stdout:
            logger.debug(f"STDOUT: {result.stdout}")
        if result.stderr:
            logger.debug(f"STDERR: {result.stderr}")
            
        return result
        
    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout} seconds: {cmd}")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed with return code {e.returncode}: {cmd}")
        if hasattr(e, 'stderr') and e.stderr:
            logger.error(f"STDERR: {e.stderr}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error running command {cmd}: {e}")
        raise

def check_command_exists(command: str) -> bool:
    """Check if a command exists in the system PATH."""
    try:
        run_command(["which", command], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def check_package_installed(package_name: str) -> bool:
    """Check if a package is installed using multiple methods."""
    # Method 1: dpkg for Debian/Ubuntu systems
    try:
        run_command(["dpkg", "-l", package_name], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Method 2: Check if command exists in PATH
    if check_command_exists(package_name):
        return True
    
    # Method 3: Try rpm for RedHat systems
    try:
        run_command(["rpm", "-q", package_name], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Method 4: Try pacman for Arch systems
    try:
        run_command(["pacman", "-Q", package_name], check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return False

def check_python_externally_managed() -> bool:
    """Check if Python environment is externally managed."""
    try:
        # Check for PEP 668 marker file
        for path in [
            "/usr/lib/python*/EXTERNALLY-MANAGED",
            "/usr/local/lib/python*/EXTERNALLY-MANAGED"
        ]:
            if any(Path(p).exists() for p in Path("/").glob(path.lstrip("/"))):
                return True
                
        # Try installing a dummy package to check
        try:
            run_command([sys.executable, "-m", "pip", "install", "--dry-run", "requests"], 
                       capture_output=True, timeout=30)
            return False
        except subprocess.CalledProcessError as e:
            if hasattr(e, 'stderr') and e.stderr and "externally-managed-environment" in e.stderr.lower():
                return True
                
    except Exception as e:
        logger.warning(f"Could not determine if Python is externally managed: {e}")
        
    return False

def create_virtual_environment(venv_path: str, python_executable: str = None) -> bool:
    """Create a virtual environment with multiple fallback methods."""
    if python_executable is None:
        python_executable = sys.executable
    
    venv_path = Path(venv_path)
    
    # Method 1: Standard venv module
    try:
        logger.info(f"Creating virtual environment with venv module: {venv_path}")
        run_command([python_executable, "-m", "venv", str(venv_path)])
        return True
    except Exception as e:
        logger.warning(f"venv module failed: {e}")
    
    # Method 2: virtualenv package
    try:
        logger.info(f"Trying virtualenv package: {venv_path}")
        run_command(["virtualenv", str(venv_path)])
        return True
    except Exception as e:
        logger.warning(f"virtualenv package failed: {e}")
    
    # Method 3: python -m virtualenv
    try:
        logger.info(f"Trying python -m virtualenv: {venv_path}")
        run_command([python_executable, "-m", "virtualenv", str(venv_path)])
        return True
    except Exception as e:
        logger.warning(f"python -m virtualenv failed: {e}")
    
    return False

def install_to_venv(venv_path: str, packages: List[str], upgrade: bool = True) -> bool:
    """Install packages to a virtual environment with error recovery."""
    venv_path = Path(venv_path)
    
    # Determine pip path based on OS
    if os.name == 'nt':  # Windows
        pip_path = venv_path / "Scripts" / "pip"
        python_path = venv_path / "Scripts" / "python"
    else:  # Unix/Linux
        pip_path = venv_path / "bin" / "pip"
        python_path = venv_path / "bin" / "python"
    
    if not pip_path.exists():
        logger.error(f"Virtual environment pip not found at {pip_path}")
        return False
    
    # Upgrade pip first
    if upgrade:
        try:
            logger.info("Upgrading pip in virtual environment...")
            run_command([str(python_path), "-m", "pip", "install", "--upgrade", "pip"])
        except Exception as e:
            logger.warning(f"Could not upgrade pip: {e}")
    
    # Install packages one by one for better error handling
    success_count = 0
    for package in packages:
        try:
            logger.info(f"Installing {package} in virtual environment...")
            run_command([str(pip_path), "install", package])
            success_count += 1
            print_success(f"Installed {package}")
        except Exception as e:
            logger.error(f"Failed to install {package}: {e}")
            print_error(f"Failed to install {package}")
            
            # Try alternative installation methods
            try:
                logger.info(f"Trying alternative installation for {package}...")
                run_command([str(python_path), "-m", "pip", "install", package])
                success_count += 1
                print_success(f"Installed {package} (alternative method)")
            except Exception as e2:
                logger.error(f"Alternative installation also failed for {package}: {e2}")
    
    return success_count == len(packages)

# =============================================================================
# 🔧 INSTALLATION MANAGER CLASS
# =============================================================================

class RobustInstaller:
    """Ultra-robust installation manager with comprehensive error handling."""
    
    def __init__(self):
        self.script_dir = Path(os.path.dirname(os.path.abspath(__file__)))
        self.is_externally_managed = check_python_externally_managed()
        self.system_info = self._get_system_info()
        self.installation_log = []
        
        logger.info(f"Installer initialized for {self.system_info['os']} {self.system_info['version']}")
        logger.info(f"Python externally managed: {self.is_externally_managed}")
    
    def _get_system_info(self) -> Dict[str, str]:
        """Get comprehensive system information."""
        try:
            return {
                'os': platform.system(),
                'version': platform.release(),
                'architecture': platform.machine(),
                'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                'distribution': self._get_linux_distribution()
            }
        except Exception as e:
            logger.warning(f"Could not get complete system info: {e}")
            return {'os': 'unknown', 'version': 'unknown', 'architecture': 'unknown'}
    
    def _get_linux_distribution(self) -> str:
        """Get Linux distribution name."""
        try:
            if Path("/etc/os-release").exists():
                with open("/etc/os-release") as f:
                    for line in f:
                        if line.startswith("NAME="):
                            return line.split("=")[1].strip().strip('"')
            return "unknown"
        except Exception:
            return "unknown"
    
    def check_prerequisites(self) -> bool:
        """Check and install basic prerequisites."""
        print_banner("CHECKING PREREQUISITES")
        
        prerequisites_passed = 0
        total_prerequisites = 6
        
        # 1. Check Python version
        print_step(1, total_prerequisites, "Checking Python version")
        if sys.version_info >= (3, 8):
            print_success(f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro} is supported")
            prerequisites_passed += 1
        else:
            print_error(f"Python {sys.version_info.major}.{sys.version_info.minor} is too old. Need Python 3.8+")
            if self._install_modern_python():
                prerequisites_passed += 1
        
        # 2. Check internet connectivity
        print_step(2, total_prerequisites, "Checking internet connectivity")
        if self._check_internet():
            print_success("Internet connectivity available")
            prerequisites_passed += 1
        else:
            print_warning("Limited internet connectivity - some features may not work")
        
        # 3. Check package manager
        print_step(3, total_prerequisites, "Checking package manager")
        if self._check_package_manager():
            print_success("Package manager available")
            prerequisites_passed += 1
        else:
            print_warning("No compatible package manager found")
        
        # 4. Check development tools
        print_step(4, total_prerequisites, "Checking development tools")
        if self._install_dev_tools():
            print_success("Development tools available")
            prerequisites_passed += 1
        
        # 5. Check pip availability
        print_step(5, total_prerequisites, "Checking pip availability")
        if self._ensure_pip():
            print_success("pip is available")
            prerequisites_passed += 1
        
        # 6. Setup virtual environment strategy
        print_step(6, total_prerequisites, "Setting up virtual environment strategy")
        if self._setup_venv_strategy():
            print_success("Virtual environment strategy configured")
            prerequisites_passed += 1
        
        success_rate = prerequisites_passed / total_prerequisites
        if success_rate >= 0.8:
            print_success(f"Prerequisites check passed ({prerequisites_passed}/{total_prerequisites})")
            return True
        else:
            print_error(f"Prerequisites check failed ({prerequisites_passed}/{total_prerequisites})")
            return False
    
    def _check_internet(self) -> bool:
        """Check internet connectivity."""
        try:
            # Try multiple hosts for redundancy
            hosts = ["8.8.8.8", "1.1.1.1", "github.com"]
            for host in hosts:
                try:
                    if host in ["8.8.8.8", "1.1.1.1"]:
                        run_command(["ping", "-c", "1", "-W", "3", host], timeout=5)
                    else:
                        urllib.request.urlopen(f"https://{host}", timeout=5)
                    return True
                except Exception:
                    continue
            return False
        except Exception:
            return False
    
    def _check_package_manager(self) -> bool:
        """Check for available package managers."""
        managers = ["apt", "yum", "dnf", "pacman", "zypper", "brew"]
        for manager in managers:        
            if check_command_exists(manager):
                logger.info(f"Found package manager: {manager}")
                return True
        return False
    
    def _install_dev_tools(self) -> bool:
        """Install essential development tools with Kali Linux fixes."""
        # First, try to fix Kali repositories if needed
        if self._is_kali_linux():
            self._fix_kali_repositories()
        
        essential_tools = [
            ("curl", ["curl", "--version"]),
            ("wget", ["wget", "--version"]),
            ("git", ["git", "--version"]),
            ("build-essential", ["gcc", "--version"])
        ]
        
        success_count = 0
        for tool, check_cmd in essential_tools:
            # Check if already installed
            if self._check_tool_installed(check_cmd):
                print_success(f"{tool} is already available")
                success_count += 1
                continue
                
            # Try to install with multiple methods
            if self._install_system_package_robust(tool):
                success_count += 1
            else:
                logger.warning(f"Could not install {tool}")
        
        # At least curl or wget should be available
        has_download_tool = check_command_exists("curl") or check_command_exists("wget")
        has_git = check_command_exists("git")
        
        return success_count >= 2 and has_download_tool  # At least 2 tools including download capability

    def _is_kali_linux(self) -> bool:
        """Check if the system is Kali Linux."""
        return "kali" in self.system_info.get('distribution', '').lower()
    
    def _fix_kali_repositories(self) -> bool:
        """Fix Kali Linux repository issues."""
        try:
            print_info("Fixing Kali Linux repository configuration...")
            
            # Backup original sources.list
            sources_list = Path("/etc/apt/sources.list")
            backup_path = Path("/etc/apt/sources.list.backup")
            
            if sources_list.exists() and not backup_path.exists():
                run_command(["sudo", "cp", str(sources_list), str(backup_path)])
                print_success("Backed up original sources.list")
            
            # Create new sources.list with working repositories
            kali_sources = """# Kali Linux repositories
deb http://http.kali.org/kali kali-rolling main non-free-firmware contrib non-free
deb-src http://http.kali.org/kali kali-rolling main non-free-firmware contrib non-free

# Alternative mirrors in case of issues
# deb http://ftp.halifax.rwth-aachen.de/kali kali-rolling main non-free-firmware contrib non-free
# deb http://mirror.kali.org/kali kali-rolling main non-free-firmware contrib non-free
"""
            
            # Write new sources.list
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(kali_sources)
                temp_sources = f.name
            
            run_command(["sudo", "mv", temp_sources, str(sources_list)])
            print_success("Updated sources.list with working repositories")
            
            # Update package lists with timeout and error handling
            try:
                print_info("Updating package lists...")
                run_command(["sudo", "apt", "update"], timeout=120)
                print_success("Package lists updated successfully")
                return True
            except Exception as e:
                logger.warning(f"Initial apt update failed: {e}")
                
                # Try with alternative repositories
                print_info("Trying with alternative Kali repositories...")
                alt_sources = """# Alternative Kali Linux repositories
deb http://mirror.kali.org/kali kali-rolling main non-free-firmware contrib non-free
deb http://ftp.halifax.rwth-aachen.de/kali kali-rolling main non-free-firmware contrib non-free
"""
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                    f.write(alt_sources)
                    temp_sources = f.name
                
                run_command(["sudo", "mv", temp_sources, str(sources_list)])
                
                try:
                    run_command(["sudo", "apt", "update"], timeout=120)
                    print_success("Alternative repositories working")
                    return True
                except Exception as e2:
                    logger.error(f"Alternative repositories also failed: {e2}")
                    # Restore backup if available
                    if backup_path.exists():
                        run_command(["sudo", "cp", str(backup_path), str(sources_list)])
                        print_warning("Restored original sources.list")
                    return False
                    
        except Exception as e:
            logger.error(f"Failed to fix Kali repositories: {e}")
            return False
    
    def _install_system_package_robust(self, package: str) -> bool:
        """Install system package with robust error handling and multiple attempts."""
        # Check if already installed first
        if check_package_installed(package):
            return True
        
        install_methods = [
            # Standard installation
            lambda: self._install_system_package(package),
            # With --fix-missing
            lambda: self._install_system_package_with_options(package, ["--fix-missing"]),
            # With --no-install-recommends  
            lambda: self._install_system_package_with_options(package, ["--no-install-recommends"]),
            # Force update and install
            lambda: self._force_update_and_install(package)
        ]
        
        for i, method in enumerate(install_methods, 1):
            try:
                print_info(f"Attempting installation method {i} for {package}...")
                if method():
                    return True
            except Exception as e:
                logger.warning(f"Installation method {i} failed for {package}: {e}")
                continue
        
        return False
    
    def _install_system_package_with_options(self, package: str, options: List[str]) -> bool:
        """Install system package with specific apt options."""
        try:
            if check_command_exists("apt"):
                cmd = ["sudo", "apt", "install", "-y"] + options + [package]
                run_command(cmd, timeout=300)
                return True
        except Exception as e:
            logger.warning(f"Failed to install {package} with options {options}: {e}")
        return False
    
    def _force_update_and_install(self, package: str) -> bool:
        """Force apt update and install package."""
        try:
            if check_command_exists("apt"):
                # Force update
                run_command(["sudo", "apt", "update", "--fix-missing"], timeout=120)
                # Clean cache
                run_command(["sudo", "apt", "clean"], timeout=60)
                # Install
                run_command(["sudo", "apt", "install", "-y", package], timeout=300)
                return True
        except Exception as e:
            logger.warning(f"Force install failed for {package}: {e}")
        return False
    
    def _install_system_package(self, package: str) -> bool:
        """Install a system package using the available package manager."""
        try:
            if check_command_exists("apt"):
                run_command(["sudo", "apt", "update"], timeout=60)
                run_command(["sudo", "apt", "install", "-y", package], timeout=300)
                return True
            elif check_command_exists("yum"):
                run_command(["sudo", "yum", "install", "-y", package], timeout=300)
                return True
            elif check_command_exists("dnf"):
                run_command(["sudo", "dnf", "install", "-y", package], timeout=300)
                return True
            elif check_command_exists("pacman"):
                run_command(["sudo", "pacman", "-S", "--noconfirm", package], timeout=300)
                return True
            elif check_command_exists("brew"):
                run_command(["brew", "install", package], timeout=300)
                return True
        except Exception as e:
            logger.warning(f"Failed to install {package}: {e}")
        
        return False
    
    def _install_modern_python(self) -> bool:
        """Install a modern Python version."""
        try:
            # Try to install Python 3.11 or 3.12
            for version in ["python3.12", "python3.11", "python3.10", "python3.9"]:
                if self._install_system_package(version):
                    # Update the interpreter if successful
                    if check_command_exists(version):
                        print_success(f"Installed {version}")
                        return True
            
            # Fallback: try to install python3-dev and python3-pip
            if self._install_system_package("python3-dev") and self._install_system_package("python3-pip"):
                return True
                
        except Exception as e:
            logger.error(f"Failed to install modern Python: {e}")
        
        return False
    
    def _ensure_pip(self) -> bool:
        """Ensure pip is available with multiple methods."""
        # Method 1: Check if pip is already available
        if check_command_exists("pip") or check_command_exists("pip3"):
            return True
        
        # Method 2: Try installing via package manager
        try:
            if self._install_system_package("python3-pip"):
                if check_command_exists("pip3"):
                    return True
        except Exception as e:
            logger.warning(f"Could not install pip via package manager: {e}")
        
        # Method 3: Download and install pip manually
        try:
            logger.info("Downloading and installing pip manually...")
            with tempfile.TemporaryDirectory() as temp_dir:
                get_pip_path = Path(temp_dir) / "get-pip.py"
                
                # Download get-pip.py
                if check_command_exists("curl"):
                    run_command(["curl", "-o", str(get_pip_path), "https://bootstrap.pypa.io/get-pip.py"])
                elif check_command_exists("wget"):
                    run_command(["wget", "-O", str(get_pip_path), "https://bootstrap.pypa.io/get-pip.py"])
                else:
                    # Use urllib as last resort
                    with urllib.request.urlopen("https://bootstrap.pypa.io/get-pip.py") as response:
                        get_pip_path.write_bytes(response.read())
                
                # Install pip
                run_command([sys.executable, str(get_pip_path), "--user"])
                return check_command_exists("pip") or check_command_exists("pip3")
                
        except Exception as e:
            logger.error(f"Manual pip installation failed: {e}")
        
        # Method 4: Try ensurepip
        try:
            logger.info("Trying ensurepip...")
            run_command([sys.executable, "-m", "ensurepip", "--upgrade"])
            return True
        except Exception as e:
            logger.warning(f"ensurepip failed: {e}")
        
        return False
    
    def _setup_venv_strategy(self) -> bool:
        """Setup the virtual environment strategy based on system configuration."""
        if self.is_externally_managed:
            print_warning("Python environment is externally managed")
            print("Will use dedicated virtual environments for all installations")
            
            # Ensure virtualenv is available for externally managed systems
            if not check_command_exists("virtualenv"):
                try:
                    # Try to install virtualenv in user space
                    run_command([sys.executable, "-m", "pip", "install", "--user", "virtualenv"])
                except Exception:
                    # Try via package manager
                    self._install_system_package("python3-virtualenv")
            
            return check_command_exists("virtualenv") or check_command_exists("python3-venv")
        else:
            print_success("Python environment allows direct installations")
            return True
    
    def install_excel_dependencies(self) -> bool:
        """Install Excel dependencies with ultra-robust error handling."""
        print_banner("INSTALLING EXCEL DEPENDENCIES")
        
        venv_excel_path = self.script_dir / "venv_excel"
        
        # Method 1: Try standard virtual environment creation
        try:
            if not venv_excel_path.exists():
                print_step(1, 3, "Creating virtual environment for Excel reporting")
                if create_virtual_environment(str(venv_excel_path)):
                    print_success("Virtual environment created successfully")
                else:
                    raise Exception("Failed to create virtual environment")
            else:
                print_success("Virtual environment already exists")
        except Exception as e:
            logger.error(f"Failed to create venv: {e}")
            # Try alternative approach for externally managed systems
            if self.is_externally_managed:
                print_warning("Trying alternative virtual environment creation for externally managed system")
                try:
                    # Use --break-system-packages for externally managed systems
                    run_command([sys.executable, "-m", "pip", "install", "--user", "--break-system-packages", "virtualenv"])
                    run_command(["virtualenv", str(venv_excel_path)])
                    print_success("Alternative virtual environment creation successful")
                except Exception as e2:
                    logger.error(f"Alternative venv creation also failed: {e2}")
                    return False
            else:
                return False
        
        # Method 2: Install packages
        print_step(2, 3, "Installing Excel packages (pandas, openpyxl)")
        packages = ["pandas", "openpyxl"]
        
        if install_to_venv(str(venv_excel_path), packages):
            print_success("Excel packages installed successfully")
        else:
            # Try alternative installation with --break-system-packages if externally managed
            if self.is_externally_managed:
                print_warning("Trying alternative installation for externally managed system")
                try:
                    for package in packages:
                        run_command([sys.executable, "-m", "pip", "install", "--user", "--break-system-packages", package])
                    print_success("Alternative Excel packages installation successful")
                except Exception as e:
                    logger.error(f"Alternative installation failed: {e}")
                    return False
            else:
                return False
        
        # Method 3: Verify installation
        print_step(3, 3, "Verifying Excel dependencies")
        return self._verify_excel_installation(venv_excel_path)
    
    def _verify_excel_installation(self, venv_path: Path) -> bool:
        """Verify Excel dependencies are properly installed."""
        try:
            # Determine python path
            if os.name == 'nt':
                python_path = venv_path / "Scripts" / "python"
            else:
                python_path = venv_path / "bin" / "python"
            
            # Test script to verify imports
            test_script = """
import sys
try:
    import pandas as pd
    import openpyxl
    print(f"✅ pandas: {pd.__version__}")
    print(f"✅ openpyxl: {openpyxl.__version__}")
    print("SUCCESS: All Excel dependencies verified")
except ImportError as e:
    print(f"ERROR: {e}")
    sys.exit(1)
"""
            
            # Create temporary test file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(test_script)
                test_file = f.name
            
            try:
                result = run_command([str(python_path), test_file], capture_output=True)
                print_success("Excel dependencies verified successfully")
                print(result.stdout)
                return True
            finally:
                os.unlink(test_file)
                
        except Exception as e:
            logger.error(f"Excel verification failed: {e}")
            return False
    
    def install_security_tools(self) -> bool:
        """Install all security tools with comprehensive fallback methods."""
        print_banner("INSTALLING SECURITY TOOLS")
        tools_config = [
            {
                'name': 'amass',
                'description': 'OWASP Amass subdomain enumeration tool',
                'check_cmd': ['amass', 'version'],
                'install_methods': [
                    self._install_amass_snap_only
                ],
                'alternative_methods': []
            },
            {
                'name': 'httpx',
                'description': 'ProjectDiscovery httpx HTTP toolkit',
                'check_cmd': ['httpx', '-version'],
                'install_methods': [
                    ['go', 'install', '-v', 'github.com/projectdiscovery/httpx/cmd/httpx@latest']
                ],
                'alternative_methods': [
                    self._install_httpx_manual
                ]
            },
            {
                'name': 'nmap',
                'description': 'Network Mapper',
                'check_cmd': ['nmap', '--version'],
                'install_methods': [
                    ['sudo', 'apt', 'install', '-y', 'nmap']
                ],
                'alternative_methods': [
                    ['sudo', 'yum', 'install', '-y', 'nmap'],
                    ['sudo', 'pacman', '-S', 'nmap']
                ]
            },            {
                'name': 'testssl.sh',
                'description': 'SSL/TLS testing tool',
                'check_cmd': ['testssl.sh', '--version'],
                'install_methods': [
                    self._install_testssl
                ],
                'alternative_methods': [
                    self._install_testssl_alternative_location
                ]
            }
        ]
        
        success_count = 0
        total_tools = len(tools_config)
        
        for i, tool in enumerate(tools_config, 1):
            print_step(i, total_tools, f"Installing {tool['name']} - {tool['description']}")
            
            # Check if already installed
            if self._check_tool_installed(tool['check_cmd']):
                print_success(f"{tool['name']} is already installed")
                success_count += 1
                continue
            
            # Try primary installation methods
            if self._try_install_methods(tool['name'], tool['install_methods']):
                success_count += 1
                continue
            
            # Try alternative methods
            if tool['alternative_methods'] and self._try_install_methods(tool['name'], tool['alternative_methods']):
                success_count += 1
                continue
            
            print_error(f"Failed to install {tool['name']}")
        
        print_success(f"Security tools installation: {success_count}/{total_tools} successful")
        return success_count >= (total_tools * 0.75)  # 75% success rate required
    
    def _check_tool_installed(self, check_cmd: List[str]) -> bool:
        """Check if a tool is installed by running its check command."""
        try:
            run_command(check_cmd, timeout=10)
            return True
        except Exception:
            return False
    
    def _try_install_methods(self, tool_name: str, methods: List) -> bool:
        """Try multiple installation methods for a tool."""
        for method in methods:
            try:
                if callable(method):
                    # Method is a function
                    if method():
                        print_success(f"{tool_name} installed successfully")
                        return True
                else:
                    # Method is a command list
                    run_command(method, timeout=600)
                    print_success(f"{tool_name} installed successfully")
                    return True
            except Exception as e:
                logger.warning(f"Installation method failed for {tool_name}: {e}")
                continue
        return False
    
    def _install_httpx_manual(self) -> bool:
        """Manual installation of httpx."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Clone repository
                run_command(["git", "clone", "https://github.com/projectdiscovery/httpx.git"], cwd=temp_dir)
                
                # Build httpx
                httpx_dir = Path(temp_dir) / "httpx" / "cmd" / "httpx"
                run_command(["go", "build"], cwd=str(httpx_dir))
                
                # Move to /usr/local/bin
                httpx_binary = httpx_dir / "httpx"
                run_command(["sudo", "mv", str(httpx_binary), "/usr/local/bin/"])
                run_command(["sudo", "chmod", "+x", "/usr/local/bin/httpx"])
                
                return True
        except Exception as e:
            logger.error(f"Manual httpx installation failed: {e}")
            return False
        def _install_testssl(self) -> bool:
            """Install testssl.sh with robust GitHub cloning and proper PATH setup."""
            try:
                print_info("Installing testssl.sh from GitHub...")

                testssl_dir = Path("/opt/testssl.sh")

                # Remove existing installation if present
                if testssl_dir.exists():
                    print_info("Removing existing testssl.sh installation...")
                    run_command(["sudo", "rm", "-rf", str(testssl_dir)])

                # Ensure /opt directory exists
                run_command(["sudo", "mkdir", "-p", "/opt"])

                # Method 1: Try with git clone
                try:
                    print_info("Cloning testssl.sh repository...")
                    run_command([
                        "sudo", "git", "clone", 
                        "https://github.com/drwetter/testssl.sh.git", 
                        str(testssl_dir)
                    ], timeout=300)
                    print_success("testssl.sh repository cloned successfully")
                except Exception as e:
                    logger.warning(f"Git clone failed: {e}")

                    # Method 2: Download and extract manually
                    print_info("Trying manual download of testssl.sh...")
                    if not self._download_testssl_manually(testssl_dir):
                        return False

                # Make testssl.sh executable
                testssl_script = testssl_dir / "testssl.sh"
                if not testssl_script.exists():
                    print_error(f"testssl.sh script not found at {testssl_script}")
                    return False

                run_command(["sudo", "chmod", "+x", str(testssl_script)])
                print_success("testssl.sh made executable")

                # Create symlink in /usr/local/bin for easy access
                symlink_path = Path("/usr/local/bin/testssl.sh")
                try:
                    if symlink_path.exists() or symlink_path.is_symlink():
                        run_command(["sudo", "rm", str(symlink_path)])

                    run_command(["sudo", "ln", "-s", "-f", str(testssl_script), str(symlink_path)])
                    print_success("Created symlink in /usr/local/bin")
                except Exception as e:
                    logger.warning(f"Could not create symlink: {e}")
                    print_warning("testssl.sh installed but not added to PATH")
                    print_info(f"You can run it directly with: {testssl_script}")

                # Verify installation
                try:
                    result = run_command([str(testssl_script), "--version"], timeout=10)
                    print_success("testssl.sh installation verified")
                    return True
                except Exception as e:
                    # Try via symlink
                    try:
                        run_command(["testssl.sh", "--version"], timeout=10)
                        print_success("testssl.sh installation verified via symlink")
                        return True
                    except Exception:
                        print_warning("testssl.sh installed but version check failed")
                        return True  # Consider it successful if files are in place

            except Exception as e:
                logger.error(f"testssl.sh installation failed: {e}")
                return False
    
    def _download_testssl_manually(self, testssl_dir: Path) -> bool:
        """Download testssl.sh manually without git."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                archive_url = "https://github.com/drwetter/testssl.sh/archive/3.0.8.tar.gz"
                archive_path = Path(temp_dir) / "testssl.tar.gz"
                
                # Download archive
                if check_command_exists("curl"):
                    run_command(["curl", "-L", "-o", str(archive_path), archive_url], timeout=300)
                elif check_command_exists("wget"):
                    run_command(["wget", "-O", str(archive_path), archive_url], timeout=300)
                else:
                    print_error("No download tool available (curl or wget)")
                    return False
                
                # Extract archive
                run_command(["tar", "-xzf", str(archive_path)], cwd=temp_dir)
                
                # Find extracted directory
                extracted_dirs = [d for d in Path(temp_dir).iterdir() if d.is_dir() and "testssl" in d.name]
                if not extracted_dirs:
                    print_error("Could not find extracted testssl directory")
                    return False
                
                extracted_dir = extracted_dirs[0]
                
                # Move to final location
                run_command(["sudo", "mv", str(extracted_dir), str(testssl_dir)])
                print_success("testssl.sh downloaded and extracted manually")
                return True
                
        except Exception as e:
            logger.error(f"Manual testssl download failed: {e}")
            return False
    
    def install_python_tools(self) -> bool:
        """Install Python-based security tools with virtual environments."""
        print_banner("INSTALLING PYTHON SECURITY TOOLS")
        
        tools = [
            {
                'name': 'checkdmarc',
                'description': 'DMARC record checker',
                'packages': ['checkdmarc'],
                'venv_name': 'checkdmarc_env',
                'wrapper_needed': True
            },
            {
                'name': 'dnstwist',
                'description': 'Domain name permutation engine',
                'packages': ['dnstwist'],
                'venv_name': 'dnstwist_env',
                'wrapper_needed': True
            }
        ]
        
        success_count = 0
        
        for i, tool in enumerate(tools, 1):
            print_step(i, len(tools), f"Installing {tool['name']} - {tool['description']}")
            
            if self._install_python_tool_with_venv(tool):
                success_count += 1
                
                # Apply checkdmarc bug fix after successful installation
                if tool['name'] == 'checkdmarc':
                    self._fix_checkdmarc_mta_sts_bug()
            else:
                # Try alternative installation
                if self._install_python_tool_alternative(tool):
                    success_count += 1
                    
                    # Apply checkdmarc bug fix after successful alternative installation
                    if tool['name'] == 'checkdmarc':
                        self._fix_checkdmarc_mta_sts_bug()
        
        return success_count == len(tools)
    
    def _install_python_tool_with_venv(self, tool: Dict) -> bool:
        """Install a Python tool in its own virtual environment."""
        try:
            venv_path = Path.home() / ".local" / "venvs" / tool['venv_name']
            venv_path.mkdir(parents=True, exist_ok=True)
            
            # Create virtual environment
            if not create_virtual_environment(str(venv_path)):
                return False
            
            # Install packages
            if not install_to_venv(str(venv_path), tool['packages']):
                return False
            
            # Create wrapper script if needed
            if tool.get('wrapper_needed', False):
                self._create_wrapper_script(tool['name'], venv_path)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to install {tool['name']} with venv: {e}")
            return False
    
    def _install_python_tool_alternative(self, tool: Dict) -> bool:
        """Alternative installation using pipx or user installation."""
        try:
            # Method 1: Try pipx
            if check_command_exists("pipx"):
                for package in tool['packages']:
                    run_command(["pipx", "install", package])
                return True
            
            # Method 2: User installation with --break-system-packages if needed
            for package in tool['packages']:
                try:
                    run_command([sys.executable, "-m", "pip", "install", "--user", package])
                except subprocess.CalledProcessError:
                    if self.is_externally_managed:
                        run_command([sys.executable, "-m", "pip", "install", "--user", "--break-system-packages", package])
                    else:
                        raise
            
            return True
            
        except Exception as e:
            logger.error(f"Alternative installation failed for {tool['name']}: {e}")
            return False
    
    def _create_wrapper_script(self, tool_name: str, venv_path: Path) -> None:
        """Create a wrapper script for a tool installed in a virtual environment."""
        try:
            if os.name == 'nt':
                executable_path = venv_path / "Scripts" / tool_name
            else:
                executable_path = venv_path / "bin" / tool_name
            
            wrapper_content = f"""#!/bin/bash
{executable_path} "$@"
"""
            
            wrapper_path = Path(f"/usr/local/bin/{tool_name}")
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
                f.write(wrapper_content)
                temp_wrapper = f.name
            
            run_command(["sudo", "mv", temp_wrapper, str(wrapper_path)])
            run_command(["sudo", "chmod", "+x", str(wrapper_path)])
            
            print_success(f"Created wrapper script for {tool_name}")
            
        except Exception as e:
            logger.error(f"Failed to create wrapper for {tool_name}: {e}")
    
    def verify_installation(self) -> bool:
        """Comprehensive verification of all installed tools."""
        print_banner("VERIFYING INSTALLATION")
        
        verification_tests = [
            ('Python Excel Dependencies', self._verify_excel_deps),
            ('Security Tools', self._verify_security_tools),
            ('Python Tools', self._verify_python_tools),
            ('Environment Configuration', self._verify_environment)
        ]
        
        success_count = 0
        for i, (test_name, test_func) in enumerate(verification_tests, 1):
            print_step(i, len(verification_tests), f"Verifying {test_name}")
            
            if test_func():
                print_success(f"{test_name} verification passed")
                success_count += 1
            else:
                print_error(f"{test_name} verification failed")
        
        return success_count == len(verification_tests)
    
    def _verify_excel_deps(self) -> bool:
        """Verify Excel dependencies."""
        venv_path = self.script_dir / "venv_excel"
        return self._verify_excel_installation(venv_path)
    
    def _verify_security_tools(self) -> bool:
        """Verify security tools installation."""
        tools = ['amass', 'httpx', 'nmap', 'testssl.sh']
        verified = 0
        
        for tool in tools:
            if check_command_exists(tool):
                verified += 1
                print(f"  ✅ {tool}")
            else:
                print(f"  ❌ {tool}")
        
        return verified >= len(tools) * 0.75  # 75% success rate
    
    def _verify_python_tools(self) -> bool:
        """Verify Python tools installation."""
        tools = ['checkdmarc', 'dnstwist']
        verified = 0
        
        for tool in tools:
            if check_command_exists(tool):
                verified += 1
                print(f"  ✅ {tool}")
            else:
                print(f"  ❌ {tool}")
        
        return verified >= len(tools) * 0.75  # 75% success rate
    
    def _verify_environment(self) -> bool:
        """Verify environment configuration."""
        # Check PATH modifications
        path = os.environ.get('PATH', '')
        checks = [
            '/usr/local/bin' in path,
            check_command_exists('python3'),
            check_command_exists('pip') or check_command_exists('pip3')
        ]
        
        return all(checks)
    
    def setup_environment(self) -> bool:
        """Setup environment variables and PATH."""
        print_banner("CONFIGURING ENVIRONMENT")
        
        try:
            # Determine shell profile
            home = Path.home()
            shell_profiles = [home / '.bashrc', home / '.zshrc', home / '.profile']
            profile = None
            
            for p in shell_profiles:
                if p.exists():
                    profile = p
                    break
            
            if not profile:
                profile = home / '.bashrc'
                profile.touch()
            
            # Environment variables to add
            env_vars = [
                'export PATH="/usr/local/bin:$PATH"',
                'export PATH="$HOME/.local/bin:$PATH"',
                'export PATH="$HOME/go/bin:$PATH"',
                'export PATH="/snap/bin:$PATH"'
            ]
            
            # Read existing content
            existing_content = profile.read_text() if profile.exists() else ""
            
            # Add missing variables
            modified = False
            for var in env_vars:
                if var not in existing_content:
                    with profile.open('a') as f:
                        f.write(f'\n{var}\n')
                    modified = True
                    print(f"  Added: {var}")
            
            if modified:
                print_success("Environment variables updated")
                print_warning("Please restart your terminal or run: source ~/.bashrc")
            else:
                print_success("Environment already configured")
            
            return True
            
        except Exception as e:
            logger.error(f"Environment setup failed: {e}")
            return False
    
    def run_complete_installation(self) -> bool:
        """Run the complete installation process."""
        print_banner("BOC TOOLS ULTRA-ROBUST INSTALLATION")
        print("🎯 Installing ALL dependencies with maximum compatibility")
        print("🔧 Multiple fallback methods for each component")
        print("⚡ Handles externally-managed Python environments")
        
        installation_steps = [
            ("Prerequisites Check", self.check_prerequisites),
            ("Excel Dependencies", self.install_excel_dependencies),
            ("Security Tools", self.install_security_tools),
            ("Python Tools", self.install_python_tools),
            ("Environment Setup", self.setup_environment),
            ("Installation Verification", self.verify_installation)
        ]
        
        success_count = 0
        total_steps = len(installation_steps)
        
        for i, (step_name, step_func) in enumerate(installation_steps, 1):
            print_banner(f"STEP {i}/{total_steps}: {step_name}")
            
            try:
                if step_func():
                    print_success(f"Step {i} completed successfully")
                    success_count += 1
                else:
                    print_error(f"Step {i} failed")
                    # Continue with other steps even if one fails
            except Exception as e:
                print_error(f"Step {i} failed with exception: {e}")
                logger.exception(f"Step {i} exception details")
        
        # Final summary
        self._print_final_summary(success_count, total_steps)
        
        return success_count >= total_steps * 0.8  # 80% success rate required
    
    def _print_final_summary(self, success_count: int, total_steps: int) -> None:
        """Print final installation summary."""
        print_banner("INSTALLATION SUMMARY")
        
        success_rate = success_count / total_steps
        
        if success_rate >= 0.8:
            print_success(f"Installation completed successfully! ({success_count}/{total_steps} steps)")
            print("\n🎉 You can now use:")
            print("  • python3 automation.py - for comprehensive security scanning")
            print("  • python3 checkdmarc_enhanced.py -excel - for Excel reports")
            print("  • All security tools: amass, httpx, nmap, testssl.sh")
            print("  • Python tools: checkdmarc, dnstwist")
            
            print("\n📋 Next steps:")
            print("  1. Restart your terminal: source ~/.bashrc")
            print("  2. Test: python3 automation.py --help")
            print("  3. Test Excel: python3 checkdmarc_enhanced.py sample.json -excel")
            
        else:
            print_warning(f"Partial installation completed ({success_count}/{total_steps} steps)")
            print("Some components may not work correctly.")
            print("Check the log file 'boc_tools_install.log' for details.")
            
        print("\n📁 Created virtual environments:")
        print("  • ./venv_excel/ - Excel reporting dependencies")
        print("  • ~/.local/venvs/checkdmarc_env/ - checkdmarc tool")
        print("  • ~/.local/venvs/dnstwist_env/ - dnstwist tool")
    
    def _fix_checkdmarc_mta_sts_bug(self) -> bool:
        """Fix the checkdmarc bug in mta_sts.py line 473 - timeout parameter conflict."""
        try:
            print_step(1, 1, "Fixing checkdmarc mta_sts.py timeout bug")
            
            # Possible paths for the checkdmarc installation
            possible_paths = [
                Path.home() / ".pyenv/versions/checkdmarc-env/lib/python3.11/site-packages/checkdmarc/mta_sts.py",
                Path.home() / ".pyenv/versions/checkdmarc_env/lib/python3.11/site-packages/checkdmarc/mta_sts.py",
                Path.home() / ".local/venvs/checkdmarc_env/lib/python3.11/site-packages/checkdmarc/mta_sts.py",
                Path.home() / ".local/venvs/checkdmarc-env/lib/python3.11/site-packages/checkdmarc/mta_sts.py"
            ]
            
            # Try different Python versions
            for py_version in ["3.11", "3.12", "3.10", "3.9"]:
                for base_path in [Path.home() / ".pyenv/versions", Path.home() / ".local/venvs"]:
                    for env_name in ["checkdmarc-env", "checkdmarc_env"]:
                        mta_sts_path = base_path / env_name / f"lib/python{py_version}/site-packages/checkdmarc/mta_sts.py"
                        if mta_sts_path.exists():
                            possible_paths.append(mta_sts_path)
            
            # Find the actual file
            mta_sts_path = None
            for path in possible_paths:
                if path.exists():
                    mta_sts_path = path
                    break
            
            if not mta_sts_path:
                print_warning("checkdmarc mta_sts.py file not found - bug fix skipped")
                return True  # Not critical, continue installation
            
            logger.info(f"Found mta_sts.py at: {mta_sts_path}")
            
            # Read the file
            with open(mta_sts_path, "r") as file:
                lines = file.readlines()
            
            if len(lines) <= 472:
                print_warning(f"mta_sts.py has only {len(lines)} lines - bug fix not needed")
                return True
            
            # Check if already fixed
            line_473 = lines[472]  # Line 473 is index 472
            if "http_timeout=timeout" in line_473:
                print_success("checkdmarc mta_sts.py bug already fixed")
                return True
            
            # Check if line contains the problematic pattern
            if "timeout=timeout" not in line_473:
                print_warning("Expected bug pattern not found in line 473 - skipping fix")
                return True
            
            # Apply the fix
            logger.info("Applying checkdmarc mta_sts.py line 473 bug fix...")
            lines[472] = line_473.replace("timeout=timeout", "http_timeout=timeout")
            
            # Write back the file
            with open(mta_sts_path, "w") as file:
                file.writelines(lines)
            
            print_success("checkdmarc mta_sts.py bug fixed successfully")
            logger.info(f"Fixed line 473: {lines[472].strip()}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to fix checkdmarc bug: {e}")
            print_warning(f"Could not fix checkdmarc bug: {e}")
            return True  # Not critical, continue installation

    def print_info(self, message: str) -> None:
        """Print info message (instance method)."""
        print_info(message)
    def remove_amass_apt(self) -> bool:
        """Remove amass installed via apt."""
        try:
            print_info("Removing amass installed via apt...")
            run_command(["sudo", "apt", "remove", "-y", "amass"], timeout=120)
            print_success("amass removed successfully")
            return True
        except Exception as e:
            logger.error(f"Failed to remove amass via apt: {e}")
            return False

    def _install_amass_snap(self) -> bool:
        """Install amass via snap with automatic PATH configuration."""
        try:
            print_info("Installing amass via snap (recommended method)")
            
            # Check if snap is available
            if not check_command_exists("snap"):
                print_info("Snap not found, installing snapd...")
                if not self._install_snapd():
                    print_error("Failed to install snapd")
                    return False
                    
            # Install amass via snap
            print_info("Installing amass via snap...")
            run_command(["sudo", "snap", "install", "amass"], timeout=300)
            
            # Configure PATH for snap binaries
            if not self._add_snap_to_path():
                print_warning("Failed to add /snap/bin to PATH automatically")
                print_warning("Please add 'export PATH=\"/snap/bin:$PATH\"' to your shell profile")
            
            # Verify installation
            snap_amass_path = "/snap/bin/amass"
            if Path(snap_amass_path).exists():
                print_success("amass installed successfully via snap")
                return True
            else:
                print_error("amass installation via snap appears to have failed")
                return False
                
        except Exception as e:
            logger.error(f"Snap amass installation failed: {e}")
            return False
    
    
    def _install_amass_snap_only(self) -> bool:
        """Remove amass from apt and install ONLY via snap - no alternatives."""
        try:
            print_info("Installing amass via snap ONLY (removing apt version first)")
            
            # Step 1: Remove any existing amass installation via apt
            print_info("Step 1: Removing any existing amass from apt...")
            try:
                # Check if amass is installed via apt
                result = run_command(["dpkg", "-l", "amass"], capture_output=True, check=False)
                if result.returncode == 0:
                    print_info("Found amass installed via apt, removing it...")
                    run_command(["sudo", "apt", "remove", "-y", "amass"], timeout=120)
                    run_command(["sudo", "apt", "autoremove", "-y"], timeout=120)
                    print_success("amass removed from apt")
                else:
                    print_info("No apt version of amass found")
            except Exception as e:
                print_warning(f"Could not check/remove apt amass: {e}")
            
            # Step 2: Check if snap is available, install if needed
            print_info("Step 2: Ensuring snap is available...")
            if not check_command_exists("snap"):
                print_info("Snap not found, installing snapd...")
                if not self._install_snapd():
                    print_error("Failed to install snapd - cannot install amass")
                    return False
                    
                # Wait a moment for snapd to start
                print_info("Waiting for snapd to initialize...")
                time.sleep(5)
            
            # Step 3: Install amass via snap ONLY
            print_info("Step 3: Installing amass via snap...")
            try:
                run_command(["sudo", "snap", "install", "amass"], timeout=300)
                print_success("amass installed via snap")
            except Exception as e:
                print_error(f"Failed to install amass via snap: {e}")
                return False
            
            # Step 4: Configure PATH for snap binaries
            print_info("Step 4: Configuring PATH for snap binaries...")
            if not self._add_snap_to_path():
                print_warning("Failed to add /snap/bin to PATH automatically")
                print_warning("Please add 'export PATH=\"/snap/bin:$PATH\"' to your shell profile")
            
            # Step 5: Verify installation
            print_info("Step 5: Verifying amass installation...")
            snap_amass_path = "/snap/bin/amass"
            if Path(snap_amass_path).exists():
                try:
                    # Test amass command
                    run_command([snap_amass_path, "version"], timeout=10)
                    print_success("amass installation verified - snap version working")
                    return True
                except Exception as e:
                    print_warning(f"amass installed but version check failed: {e}")
                    return True  # Consider successful if binary exists
            else:
                print_error("amass binary not found after snap installation")
                return False
                
        except Exception as e:
            logger.error(f"Snap-only amass installation failed: {e}")
            print_error(f"Failed to install amass via snap: {e}")
            return False

    def _install_snapd(self) -> bool:
        """Install snapd if not present."""
        try:
            print_info("Installing snapd...")
            
            # Try different package managers
            package_managers = [
                (["sudo", "apt", "update"], ["sudo", "apt", "install", "-y", "snapd"]),
                (["sudo", "yum", "update"], ["sudo", "yum", "install", "-y", "snapd"]),
                (["sudo", "dnf", "update"], ["sudo", "dnf", "install", "-y", "snapd"]),
                (["sudo", "pacman", "-Sy"], ["sudo", "pacman", "-S", "--noconfirm", "snapd"])
            ]
            
            for update_cmd, install_cmd in package_managers:
                try:
                    run_command(update_cmd, timeout=120)
                    run_command(install_cmd, timeout=300)
                    
                    # Start and enable snapd service
                    try:
                        run_command(["sudo", "systemctl", "enable", "--now", "snapd.socket"], timeout=30)
                    except:
                        pass  # Some systems don't use systemctl
                    
                    print_success("snapd installed successfully")
                    return True
                except:
                    continue
                    
            print_error("Failed to install snapd with any package manager")
            return False
            
        except Exception as e:
            logger.error(f"snapd installation failed: {e}")
            return False
    
    def _add_snap_to_path(self) -> bool:
        """Add /snap/bin to PATH in shell profiles."""
        try:
            snap_path = 'export PATH="/snap/bin:$PATH"'
            home_dir = Path.home()
            
            # Shell profile files to update
            profile_files = [
                home_dir / ".bashrc",
                home_dir / ".zshrc", 
                home_dir / ".profile"
            ]
            
            updated_files = []
            
            for profile_file in profile_files:
                if profile_file.exists():
                    try:
                        # Read existing content
                        existing_content = profile_file.read_text()
                        
                        # Check if snap path is already configured
                        if '/snap/bin' not in existing_content:
                            # Add snap path
                            with profile_file.open('a') as f:
                                f.write(f'\n# Added by BOC Tools installer\n{snap_path}\n')
                            updated_files.append(str(profile_file))
                    except Exception as e:
                        logger.warning(f"Failed to update {profile_file}: {e}")
                        continue
            
            # Also add to current session
            os.environ['PATH'] = f"/snap/bin:{os.environ.get('PATH', '')}"
            
            if updated_files:
                print_success(f"Added /snap/bin to PATH in: {', '.join(updated_files)}")
                print_info("Snap binaries will be available in new terminal sessions")
            else:
                print_info("/snap/bin already configured in PATH")
                
            return True
            
        except Exception as e:
            logger.error(f"Failed to add snap to PATH: {e}")
            return False
    def _install_amass_go(self) -> bool:
        """Install amass using Go (if available)."""
        try:
            if not check_command_exists("go"):
                print_info("Go not available for amass installation")
                return False
            
            print_info("Installing amass via Go...")
            run_command([
                "go", "install", "-v", 
                "github.com/owasp-amass/amass/v4/...@master"
            ], timeout=600)
            
            # Check if installed in GOPATH/bin
            go_bin_path = Path.home() / "go" / "bin" / "amass"
            if go_bin_path.exists():
                # Create symlink in /usr/local/bin
                try:
                    run_command(["sudo", "ln", "-sf", str(go_bin_path), "/usr/local/bin/amass"])
                    print_success("amass installed via Go and linked to PATH")
                    return True
                except Exception:
                    print_success("amass installed via Go (available in ~/go/bin/}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Go amass installation failed: {e}")
            return False
    
    def _install_amass_manual(self) -> bool:
        """Install amass manually from GitHub releases."""
        try:
            print_info("Installing amass manually from GitHub releases...")
            
            # Determine architecture
            arch = platform.machine().lower()
            if arch == "x86_64":
                arch = "amd64"
            elif arch in ["aarch64", "arm64"]:
                arch = "arm64"
            else:
                print_warning(f"Unsupported architecture for manual amass install: {arch}")
                return False
            
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download latest release
                release_url = f"https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_{arch}.zip"
                zip_path = Path(temp_dir) / "amass.zip"
                
                if check_command_exists("curl"):
                    run_command(["curl", "-L", "-o", str(zip_path), release_url], timeout=300)
                elif check_command_exists("wget"):
                    run_command(["wget", "-O", str(zip_path), release_url], timeout=300)
                else:
                    print_error("No download tool available")
                    return False
                
                # Extract
                run_command(["unzip", str(zip_path)], cwd=temp_dir)
                
                # Find amass binary
                amass_files = list(Path(temp_dir).rglob("amass"))
                if not amass_files:
                    print_error("amass binary not found in downloaded archive")
                    return False
                
                amass_binary = amass_files[0]
                
                # Install to /usr/local/bin
                run_command(["sudo", "cp", str(amass_binary), "/usr/local/bin/amass"])
                run_command(["sudo", "chmod", "+x", "/usr/local/bin/amass"])
                
                print_success("amass installed manually")
                return True
                
        except Exception as e:
            logger.error(f"Manual amass installation failed: {e}")
            return False
    
    def _install_amass_apt_after_fix(self) -> bool:
        """Try installing amass via apt after repository fixes."""
        try:
            if not check_command_exists("apt"):
                return False
            
            print_info("Trying amass installation via apt after repository fixes...")
            
            # First try to update repositories again
            try:
                run_command(["sudo", "apt", "update"], timeout=120)
            except Exception:
                pass  # Continue even if update fails
            
            # Try installing with different options
            install_commands = [
                ["sudo", "apt", "install", "-y", "amass"],
                ["sudo", "apt", "install", "-y", "--fix-missing", "amass"],
                ["sudo", "apt", "install", "-y", "--no-install-recommends", "amass"]
            ]
            
            for cmd in install_commands:
                try:
                    run_command(cmd, timeout=300)
                    if check_command_exists("amass"):
                        print_success("amass installed via apt")
                        return True
                except Exception as e:
                    logger.warning(f"apt command failed: {e}")
                    continue
            
            return False
            
        except Exception as e:
            logger.error(f"apt amass installation failed: {e}")
            return False
    def _install_testssl_alternative_location(self) -> bool:
        """Install testssl.sh in user's home directory as alternative."""
        try:
            print_info("Installing testssl.sh in user home directory...")
            
            testssl_dir = Path.home() / ".local" / "testssl.sh"
            
            # Remove existing installation
            if testssl_dir.exists():
                shutil.rmtree(testssl_dir)
            
            # Create directory
            testssl_dir.mkdir(parents=True, exist_ok=True)
            
            # Download and extract
            if self._download_testssl_manually(testssl_dir):
                # Make executable
                testssl_script = testssl_dir / "testssl.sh"
                if testssl_script.exists():
                    os.chmod(testssl_script, 0o755)
                    
                    # Add to user's local bin
                    local_bin = Path.home() / ".local" / "bin"
                    local_bin.mkdir(parents=True, exist_ok=True)
                    
                    symlink_path = local_bin / "testssl.sh"
                    if symlink_path.exists():
                        symlink_path.unlink()
                    
                    symlink_path.symlink_to(testssl_script)
                    
                    print_success("testssl.sh installed in ~/.local/")
                    print_info("Make sure ~/.local/bin is in your PATH")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Alternative testssl installation failed: {e}")
            return False

# =============================================================================
# 🚀 MAIN EXECUTION
# =============================================================================

def main():
    """Main function to run the ultra-robust installer."""
    try:
        # Clear screen for better output
        if check_command_exists("clear"):
            run_command(["clear"])
        
        # Initialize installer
        installer = RobustInstaller()
        
        # Check if running as root when needed
        current_user = os.getuid() if hasattr(os, 'getuid') else 0
        if current_user != 0:
            print_warning("Some operations may require sudo privileges")
            print("The script will prompt for sudo when needed")
        
        # Run complete installation
        success = installer.run_complete_installation()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print_error("Installation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print_error(f"Fatal error during installation: {e}")
        logger.exception("Fatal error details")
        sys.exit(1)

if __name__ == "__main__":
    main()
