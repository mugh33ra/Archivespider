[![GitHub release](https://img.shields.io/github/release/mugh33ra/Archive-Data.svg)](https://github.com/mugh33ra/Archive-Data/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub issues](https://img.shields.io/github/issues/mugh33ra/Archive-Data.svg)](https://github.com/mugh33ra/Archive-Data/issues)
[![GitHub stars](https://img.shields.io/github/stars/mugh33ra/Archive-Data.svg)](https://github.com/mugh33ra/Archive-Data/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/mugh33ra/Archive-Data.svg)](https://github.com/mugh33ra/Archive-Data/network)

# Archive-Data

A Bash Script that Pulls Data from Wayback Machine, Alien_Vault & Virus Total

<h1 align="center">
  <img src="https://github.com/mugh33ra/Archive-Data/blob/main/img/ss.jpg" width="700px">
  <br>
</h1>

## Required Tools

- Httpx
- uro
- golang
- curl
- jq

---

## Features

Since this is only Version 1.0, we will upgrade this script over time and add more advanced techniques to find XSS, SQLi, open redirect, etc.

- Downloads data from Internet Archive (Wayback Machine), VirusTotal & OTX AlienVault.
- Filters URLs for juicy extensions and separates them into `juicy.txt`.
- Cleans URLs from image and other irrelevant extensions (`jpg`, `png`, `gif`, etc.) producing `cleanUrls.txt`.
- Filters JavaScript files from URLs and stores them into `js.txt` for further testing.
- Runs `httpx-toolkit` to filter alive JavaScript files.
- Extracts hidden endpoints from alive JS files and saves them into `endpoints.txt`.

---

## Installation

Make sure to run the provided `install.sh` script before running the main script to install dependencies.

```bash
bash install.sh
```

## Usage

Run the script with a domain as the argument:

```bash
bash Archive_Data.sh example.com
```
The script will create a directory named after the domain and save all output files inside it.

## Output Files

- juicy.txt — `Filtered URLs with juicy file extensions.`
- cleanUrls.txt — `Combined and cleaned URLs.`
- js.txt — `JavaScript file URLs extracted from cleanUrls.txt.`
- alivejs.txt — `Alive JavaScript URLs after httpx-toolkit scan.`
- endpoints.txt — `Extracted endpoints from alive JS files.`

## Example Output

```bash
[✓] URLs fetched from Wayback: 1234
[✓] URLs fetched from Alien Vault: 567
[✓] URLs fetched from VirusTotal: 89
[+] Filter Result saved to juicy.txt👌
[+] Total Js Files: 45
[✓] Endpoints extracted from js files are saved to endpoints.txt😎
```

## Author

https://x.com/mugh33ra

Feel free to open issues or reach out for questions and suggestions!
