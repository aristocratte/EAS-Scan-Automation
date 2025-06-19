# automation.py

**Automated domain reconnaissance toolkit with 6 integrated security tools**

## Quick Start

```bash
python3 automation.py
```

## What it does

Runs a complete security analysis workflow on any domain through 6 configurable steps:

1. **INTEL GATHERING** - WHOIS + ViewDNS.info domain investigation
2. **SUBFINDER** - Fast subdomain discovery with API integration
3. **AMASS ENUM** - Advanced subdomain enumeration with graph database
4. **NMAP** - Port scanning (passive/active modes) with visualization
5. **CheckDMARC** - Email security analysis (SPF/DMARC/DKIM) with Excel reports
6. **TestSSL** - SSL/TLS security audit with progress tracking and Excel analysis

## Key Features

- **Interactive workflow** - Choose passive or active scanning for each tool
- **Skip any step** - Each tool can be run independently with confirmation prompts
- **Smart file management** - Detects existing scans and offers skip/overwrite options
- **Progress tracking** - Real-time progress bars and scan summaries
- **Multiple output formats** - JSON, CSV, HTML, XML outputs with Excel report generation
- **Colored terminal output** - Clear visual feedback with status icons

## Prerequisites

```bash
# Install required tools
python3 install-tools.py

# Required tools: amass, nmap, testssl, checkdmarc, subfinder
# Python dependencies: psutil, concurrent.futures (built-in)
```

## Output Structure

```
output/domain.com/
├── amass/           # Intel gathering + subdomain enumeration
│   ├── intel_output.txt      # Related domains from WHOIS/ViewDNS
│   ├── amass_output.txt      # Subdomain enumeration results
│   └── [graph database]     # Amass graph data + D3 visualization
├── subfinder/       # Fast subdomain discovery
│   └── subfinder_output.json
├── nmap/            # Port scanning results
│   ├── nmap.nmap, nmap.xml, nmap.gnmap
│   └── nmap.html (optional visualization)
├── checkdmarc/      # Email security analysis
│   ├── domain.com.json (per domain)
│   └── [Excel reports]
└── testssl/         # SSL/TLS security audit
    ├── domain_com.csv/json/html (per target)
    └── [Excel analysis reports]
```

## Key Workflow Features

**Intel Gathering (Step 1):**

- WHOIS organization extraction
- ViewDNS.info related domain discovery
- Builds intel_output.txt for subsequent tools

**Subfinder Integration (Step 2):**

- API-based subdomain discovery
- JSON output format
- Requires API configuration for optimal results

**Advanced File Management:**

- Pre-scan detection of existing files
- Options to skip/overwrite/report-only
- Progress tracking with scan summaries

## Advanced Usage

**Directory Management:**

- Automatic timestamp directories for multiple scans
- Choice between skip/overwrite/new directory when conflicts occur

**Scan Modes:**

- **Passive:** Safe reconnaissance (top ports, no intrusive techniques)
- **Active:** Comprehensive scanning with warnings and confirmations

**Report Generation:**

- CheckDMARC: Excel reports via `checkdmarc_enhanced.py`
- TestSSL: Individual and general Excel reports via `testssl-analyzer.py`
- Nmap: HTML visualization with xsltproc

## Target Options

Each tool supports:

1. **Single domain** - Scan just the main domain
2. **Subdomain list** - Use results from previous steps (amass_output.txt)

## Integration

Works seamlessly with companion tools:

- `checkdmarc_enhanced.py` - Enhanced Excel reports for email security
- `testssl-analyzer.py` - Comprehensive SSL/TLS analysis with Excel output
- `install-tools.py` - Automated tool installation and setup

## Example Workflow

```bash
# 1. Run full analysis
python3 automation.py
# Choose: active scan, enter domain.com
# Run all 6 steps with confirmation prompts

# 2. Results automatically organized in output/domain.com/
# 3. Excel reports generated for CheckDMARC and TestSSL
# 4. HTML visualizations for Nmap and Amass (optional)
```

---

_Complete domain security analysis with intelligent workflow management._
