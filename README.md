# Archive-Data
A Bash Script that Pulls Data from Wayback Machine, Alien_Vault &amp; Virus Total
![alt_text]()

# Required Tools
* Httpx
* uro
* golang

# Features
Since this is only Version 1.0 We will upgrade this script time by time and add some more advance techniques to find xss, sqli, open_redirect ect..
* It Download Data from Internet Archive, Virus_Total & OTX_Alien_Vault
* It filters the urls for juicy extension and separte them into `juicy.txt` file
* it cleans the urls from `jpg, png, gif....etc` and gives you clean urls.
* it filter javascript files from urls and store them into `js.txt` for further testing.
* Then it runs `HTTPx` to filter alive Javascript files.
* Then it use the `js` files and extract hidden endpoints from `js` files and save them into `endpoints.txt`

# Usage
* Make sure you run `install.sh` before running the script.
* `bash Archive_Data.sh example.com`
