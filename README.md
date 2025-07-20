
[![GitHub release](https://img.shields.io/github/release/mugh33ra/Archivespider.svg)](https://github.com/mugh33ra/Archivespider/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub issues](https://img.shields.io/github/issues/mugh33ra/Archivespider.svg)](https://github.com/mugh33ra/Archivespider/issues)
[![GitHub stars](https://img.shields.io/github/stars/mugh33ra/Archivespider.svg)](https://github.com/mugh33ra/Archivespider/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mugh33ra/Archivespider.svg)](https://github.com/mugh33ra/Archivespider/network)

# 🕷️ Archivespider

A powerful and modular **bash-based OSINT reconnaissance framework** to extract, filter, and analyze URLs, JS files, IPs, and hidden endpoints from open sources like **Wayback Machine**, **OTX AlienVault**, and **VirusTotal**.

<h1 align="center">
  <img src="https://github.com/mugh33ra/Archivespider/blob/main/img/ss.jpg" width="700px" alt="screenshot">
  <br>
</h1>

---

## ✨ Features

- 📦 Pulls archived URLs from:
  - Wayback Machine (Internet Archive)
  - VirusTotal domain reports
  - AlienVault OTX (with pagination support)
- 🌐 Supports **wildcard mode** to include all subdomains.
- 🔍 Extracts:
  - IP addresses from VT, OTX, and URLScan
  - JavaScript file URLs
  - Interesting file types (like `.sql`, `.pdf`, `.docx`, `.bak`, `.json`, etc.)
  - Hidden endpoints from alive JS files
- 📊 Generates cleaned lists, reports, and summaries.
- 🔄 Built-in **auto-update** functionality from GitHub.
- 🔧 Resilient to interruptions with a graceful Ctrl+C trap.
- 🧠 Smart filtering for static/media files.
- 🎯 Integrated `httpx-toolkit` and `uro` support.

---

## ⚙️ Requirements

Before running, make sure you have the following installed:

- [`httpx-toolkit`](https://github.com/projectdiscovery/httpx)
- [`uro`](https://github.com/s0md3v/uro)
- `jq`
- `curl`
- `bash`
- `golang`

To install all dependencies:

```bash
bash install.sh
```

---

## 🚀 Usage

```bash
bash Archivespider.sh -d example.com [options]
```

### 🔧 Options

| Flag                    | Description                                                                 |
|-------------------------|-----------------------------------------------------------------------------|
| `-d, --domain`          | **(Required)** Target domain to scan                                       |
| `-m, --mode`            | Operation mode: `sd` (single domain) or `wc` (wildcard for subdomains)     |
| `-ips`                  | Enable IP scanning (VT, OTX, URLScan)                                      |
| `-o, --output`          | Custom output directory for saving results                                 |
| `-up, --update`         | Update the script from the official GitHub repository                      |
| `-h, --help`            | Show usage guide                                                            |

---

## 🧪 Example Usage

### Basic

```bash
bash Archivespider.sh -d example.com
```

### Wildcard Subdomain Mode

```bash
bash Archivespider.sh -d example.com -m wc
```

### IP Discovery Only

```bash
bash Archivespider.sh -d example.com -ips
```

### Custom Output Directory

```bash
bash Archivespider.sh -d example.com -o ./output_dir
```

---

## 📁 Output Structure

After execution, results will be saved in a folder named after the domain or your custom directory.

| File               | Description                                                                 |
|--------------------|-----------------------------------------------------------------------------|
| `waybackdata.txt`  | Raw URLs from the Wayback Machine                                           |
| `alienVault.txt`   | URLs pulled from AlienVault                                                 |
| `vt.txt`           | URLs retrieved from VirusTotal                                              |
| `juicy.txt`        | URLs pointing to sensitive filetypes (PDF, SQL, JSON, etc.)                 |
| `cleanUrls.txt`    | URLs filtered to remove static/media noise                                  |
| `js.txt`           | JavaScript URLs extracted from `cleanUrls.txt`                              |
| `alivejs.txt`      | Verified reachable JS files using `httpx-toolkit`                           |
| `endpoints.txt`    | Hidden API endpoints discovered inside JS files                             |
| `<domain>_ips.txt` | Aggregated IPs from VT, AlienVault, URLScan, and URL content                |

---

## 📸 Sample Output

```bash
[✓] Found 1287 URLs from Wayback Machine
[✓] Found 412 URLs from AlienVault
[✓] Found 99 URLs from VirusTotal
[+] Filtered 56 juicy files -> juicy.txt
[✓] JS Files Detected: 33 -> js.txt
[✓] Alive JS files: 25 -> alivejs.txt
[✓] Extracted 60 hidden endpoints -> endpoints.txt
[✓] Found 17 unique IP addresses -> example.com_ips.txt
```

---

## 🛠 Update

To update the script to the latest version:

```bash
bash Archivespider.sh -up
```

---

## 👨‍💻 Author

**mugh33ra**

- Twitter/X: [@mugh33ra](https://x.com/mugh33ra)
- GitHub: [mugh33ra](https://github.com/mugh33ra)

---

## 📜 License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).

---

## 🙏 Contributions

PRs, issues, and suggestions are welcome! If you find bugs or have ideas for improvement, feel free to contribute.
