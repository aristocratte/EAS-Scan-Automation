# automation.py - Complete Guide

## Overview

`automation.py` is an advanced Python script that automates the execution of five reconnaissance and security analysis tools. It enables a complete analysis of a domain using a modular approach, with the ability to skip each step individually.

## Main Features

### Smart Workflow

- **5 configurable steps**: Each tool can be executed or skipped individually
- **Continuation logic**: If a step fails or is skipped, the script automatically continues
- **Colored interface**: Messages with color codes for better readability
- **Robust error handling**: Protection against crashes and automatic recovery

### Integrated Tools

1. **AMASS INTEL** - Initial information gathering
2. **AMASS ENUM** - Subdomain enumeration
3. **NMAP** - Port and service scanning
4. **CheckDMARC** - Email configuration analysis
5. **TestSSL** - SSL/TLS audit with advanced parallelism

### New Feature: Parallel TestSSL

The script now includes a parallel processing system for TestSSL with:

- **Real-time system resource monitoring**
- **Automatic crash protection**
- **Smart suggestions** for the optimal number of processes
- **Continuous performance monitoring** during execution

---

## Prerequisites

### Required System Tools

```bash
# Automatically checked at runtime
amass       # Subdomain reconnaissance
nmap        # Port and service scanning
testssl     # SSL/TLS audit
checkdmarc  # Email configuration analysis
```

### Python Dependencies

```bash
pip3 install psutil concurrent.futures
```

### Tool Installation

```bash
# Use the provided installation script
python3 install-tools.py
```

---

## Usage

### Basic Launch

```bash
python3 automation.py
```

### Interactive Workflow

1. **Choose scan type**: `passive` or `active`
2. **Enter the domain**: Format without prefix (e.g., `example.com`)
3. **Directory management**: Automatic creation or action choice
4. **Run the 5 steps**: Individual confirmation for each tool

---

## Detailed Step Description

### STEP 1/5: AMASS INTEL

**Gathering information about the target domain**

```bash
Goal   : Discover related domains and organizations
Options: Passive or active mode
Output : intel_output.txt
```

**Features:**

- Automatic WHOIS search
- Discovery of related organizations
- Active mode for in-depth searches
- Real-time result display

### STEP 2/5: AMASS ENUM

**Complete subdomain enumeration**

```bash
Goal   : Discover all accessible subdomains
Source : Single domain or intel list
Output : amass_output.txt + graph database
```

**Advanced options:**

- Custom configuration (config.yaml)
- No-color mode for parsing
- D3 visualizations generation
- Domain list support

### STEP 3/5: NMAP

**Port and service detection scan**

```bash
Goal   : Identify exposed services
Modes  : Passive (top 100 ports) / Active (full scan)
Output : nmap files (XML, nmap, gnmap)
```

**Built-in protections:**

- Warnings for active mode
- Double confirmation for intrusive scans
- HTML visualization generation
- Configurable timeout and retry

### STEP 4/5: CheckDMARC

**Complete email configuration analysis**

```bash
Goal   : Check SPF, DMARC, DKIM
Support: Single domain or subdomain list
Output : Individual JSON files per domain
```

**Analyses performed:**

- SPF (Sender Policy Framework) configuration
- DMARC (Domain-based Message Authentication) policy
- DKIM (DomainKeys Identified Mail) records
- DNS record validation

### STEP 5/5: TestSSL (NEW: Advanced Parallelism)

**SSL/TLS audit with smart parallel processing**

```bash
Goal   : Analyze SSL/TLS security
Support: Parallel processing for domain lists
Output : Detailed JSON files per domain
```

## New TestSSL Features

### System Resource Monitoring

The script automatically monitors:

- **CPU usage**: Real-time percentage
- **Available memory**: Free RAM in GB
- **Load average**: System load
- **Number of cores**: Auto-detection

### Crash Protection

**Protection criteria:**

```python
CPU > 80%           # Stop if CPU overloaded
Memory > 85%        # Stop if RAM is insufficient
Free RAM < 1GB      # Minimum memory protection
Workers > CPU cores # Smart limitation
```

### Smart Suggestions

The system automatically calculates:

```python
Max by CPU    = Cores - 1        # Keep at least 1 core free
Max by RAM    = RAM_GB / 2       # ~2GB per worker
Suggestion    = min(CPU, RAM, 8) # Maximum 8 workers
```

### Parallel Execution

**Advanced features:**

- **ThreadPoolExecutor**: Professional thread management
- **5-minute timeout** per domain
- **Continuous resource monitoring** during execution
- **Sequential fallback** in case of overload
- **Real-time progress display**

**Example run:**

```bash
[?] How many parallel processes do you want? (Suggested: 3, Max safe: 3): 2
[-] System Resources: CPU: 15.2%, Memory: 45.8%, Available RAM: 8.2GB
[-] Running testssl with 2 parallel processes...
[-] Progress: 5/19 (26.3%)
[+] TestSSL output for subdomain1.example.com saved (Duration: 45.2s)
[+] TestSSL output for subdomain2.example.com saved (Duration: 52.1s)
```

---

## Terminal Color Codes

| Color  | Code          | Usage     | Example                           |
| ------ | ------------- | --------- | --------------------------------- |
| Green  | `\033[92m[+]` | Success   | `[+] Scan completed successfully` |
| Red    | `\033[91m[!]` | Errors    | `[!] Command failed`              |
| Yellow | `\033[93m[?]` | Questions | `[?] Do you want to continue?`    |
| Cyan   | `\033[96m[-]` | Info      | `[-] Running nmap scan...`        |
| Blue   | `\033[94m[>]` | Progress  | `[>] Moving to next step...`      |
| Gray   | `\033[90m`    | Debug     | Commands and technical details    |

---

## Output Structure

```
output/
└── example.com/
    ├── amass/
    │   ├── intel_output.txt
    │   ├── amass_output.txt
    │   └── [graph database]
    ├── nmap/
    │   ├── nmap.nmap
    │   ├── nmap.xml
    │   ├── nmap.gnmap
    │   └── nmap.html (optional)
    ├── checkdmarc/
    │   ├── example.com.json
    │   ├── subdomain1.example.com.json
    │   └── subdomain2.example.com.json
    └── testssl/
        ├── example.com.json
        ├── subdomain1.example.com.json
        └── subdomain2.example.com.json
```

---

## Advanced Configuration

### Environment Variables

```bash
export AMASS_CONFIG="/path/to/config.yaml"
export NMAP_TIMING="T3"  # T1-T5
export TESTSSL_TIMEOUT="300"  # Seconds
```

### Performance Optimization

**For Parallel TestSSL:**

- **High-performance systems**: 4-8 workers recommended
- **Limited systems**: 1-2 workers max
- **Continuous monitoring**: The script auto-adjusts

**Hardware recommendations:**

- **Minimum RAM**: 4GB (8GB+ recommended)
- **CPU**: Multi-core recommended for parallelism
- **Storage**: SSD for optimal performance

---

## Troubleshooting

### Common Issues

**1. Missing tools**

```bash
[!] amass is not installed.
Solution: python3 install-tools.py
```

**2. Insufficient permissions**

```bash
[!] Permission denied
Solution: chmod +x automation.py
```

**3. TestSSL memory errors**

```bash
[!] High resource usage detected! CPU: 95.2%, Memory: 92.1%
Action: The script automatically reduces workers
```

**4. TestSSL timeouts**

```bash
[!] TestSSL timeout for subdomain.com
Cause: Domain unreachable or very slow
Action: Continue with other domains
```

### Logs and Debug

**Verbose mode:**

```python
# In the code, enable debug prints
DEBUG = True
```

**Resource monitoring:**

```bash
# While running, monitor in another terminal
htop
# or
watch -n 1 'ps aux | grep testssl'
```

---

## Integration with Other Scripts

### Excel Dashboard Generation

```bash
# After running automation.py
./generate_excel_dashboard.sh
# or directly
python3 excel_security_dashboard.py output/example.com/checkdmarc/
```

### Amass Beautification

```bash
python3 amassbeautifier.py output/example.com/amass/amass_output.txt
```

### Domain Mapping

```bash
python3 domain_mapper.py output/example.com/amass/amass_output.txt
```

---

## Metrics and Performance

### Typical Benchmarks

| Step        | Single Domain | 10 Subdomains       | 50 Subdomains        |
| ----------- | ------------- | ------------------- | -------------------- |
| Amass Intel | 30-60s        | 1-2 min             | 2-5 min              |
| Amass Enum  | 2-10 min      | 5-15 min            | 10-30 min            |
| Nmap        | 1-5 min       | 5-20 min            | 20-60 min            |
| CheckDMARC  | 10-30s        | 2-5 min             | 5-15 min             |
| TestSSL     | 1-3 min       | 3-10 min (parallel) | 10-25 min (parallel) |

### Parallel vs Sequential TestSSL

**Example with 20 subdomains:**

- **Sequential**: ~60 minutes (3 min/domain)
- **Parallel (4 workers)**: ~15 minutes (4x faster)
- **Parallel (8 workers)**: ~8 minutes (7-8x faster)

---

## Development and Contribution

### Code Structure

```python
# Main functions
main()                    # Entry point
run_intel_command()       # Step 1
run_enum_amass()          # Step 2
run_nmap()                # Step 3
run_checkdmarc()          # Step 4
run_testssl()             # Step 5 (with parallelism)

# Utility functions
check_system_resources()  # System monitoring
is_system_overloaded()    # Crash protection
suggest_max_workers()     # Smart suggestions
run_testssl_single()      # Single TestSSL execution
```

### Adding New Tools

1. **Add to list_tools**: `["amass", "nmap", "testssl", "checkdmarc", "new_tool"]`
2. **Create the function**: `run_new_tool(domain, input_dir, output_dir)`
3. **Add in main()**: Call the new function
4. **Test**: Full workflow verification

---

## Resources and References

### Official Documentation

- [Amass Documentation](https://github.com/OWASP/Amass)
- [Nmap Reference Guide](https://nmap.org/book/)
- [TestSSL.sh Documentation](https://testssl.sh/)
- [CheckDMARC Documentation](https://domainaware.github.io/checkdmarc/)

### Useful Links

- [RFC 7208 - SPF](https://tools.ietf.org/html/rfc7208)
- [RFC 7489 - DMARC](https://tools.ietf.org/html/rfc7489)
- [SSL/TLS Best Practices](https://wiki.mozilla.org/Security/Server_Side_TLS)

---

## Changelog

### Version 3.0 (Current)

- Added TestSSL parallelism with smart monitoring
- Automatic crash protection
- Colored interface for all messages
- Continuation logic for all steps
- Real-time resource monitoring

### Version 2.0

- Domain list support for all tools
- Continuation logic to skip steps
- Full CheckDMARC integration
- Nmap improvements with protections

### Version 1.0

- Initial version with 5 integrated tools
- Automatic directory management
- Flexible configuration for each tool

---

## Support

For any questions or issues:

1. **Check** that all tools are installed: `python3 install-tools.py`
2. **Consult** error logs in the terminal
3. **Test** with a simple domain before large lists
4. **Monitor** system resources during execution

---

## Conclusion

`automation.py` now offers a complete and robust workflow for domain security analysis. With the new parallel TestSSL system, smart resource monitoring, and crash protection, you have a professional tool capable of handling large-scale analyses while preserving your system's stability.

**Recommended workflow:**

```bash
1. python3 automation.py          # Complete analysis
2. ./generate_excel_dashboard.sh  # Excel dashboard
3. python3 domain_mapper.py       # Mapping (optional)
```

---

_Last update: June 2025_

Final result -> subdomains.txt + nmap report + testssl + checkdmarc
