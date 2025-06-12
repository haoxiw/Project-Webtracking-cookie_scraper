# Cookie Scraper

Use this tool to download and save cookies from websites using both Scrapy and Selenium. This tool helps analyze cookie usage across different websites, which can be useful for privacy research and compliance checks.

## Features

- **Selenium Integration**: Captures JavaScript-set cookies that basic HTTP requests might miss
- **Dual-mode Operation**: Can run with or without Selenium as needed
- **Multi-site Scraping**: Scrape cookies from multiple websites in a single run
- **Comprehensive Cookie Extraction**: Captures all cookie attributes (name, value, domain, path, expires, secure, httponly, samesite)
- **Structured Storage**: Saves cookies in JSON format for easy analysis
- **Analysis Tools**: Includes utilities for analyzing cookie statistics
- **Data Export**: Export cookies to CSV for further analysis

## Installation

1. Clone the repository
2. Install the required dependencies:

```bash
pip install -r requirements.txt
```

3. For Selenium support, you'll need Chrome or Chromium browser installed

## Usage

### Running the Spider

Run the spider with default settings (uses Selenium in headless mode):

```bash
python run.py
```

Specify custom websites to scrape:

```bash
python run.py --urls "google.com,facebook.com,twitter.com"
```

### Selenium Options

Run with visible browser (non-headless mode):

```bash
python run.py --no-headless
```

Increase wait time for JavaScript execution (default is 5 seconds):

```bash
python run.py --wait-time 10
```

Disable Selenium and use only Scrapy (faster but may miss JavaScript-set cookies):

```bash
python run.py --no-selenium
```

### Other Options

Customize the output file:

```bash
python run.py --output my_cookies_results.json
```

Set the log level:

```bash
python run.py --log-level DEBUG
```

### Analyzing Cookies

After collecting cookies, you can analyze them using the utility script:

```bash
python cookie_utils.py
```

Export cookies to CSV for further analysis:

```bash
python cookie_utils.py --export cookies_export.csv
```

## Cookie Storage

Cookies are saved in the `cookies` directory in JSON format. Each file is named using the pattern `domain_timestamp.json` (e.g., `www_google_com_20250524_123456.json`).

The JSON structure includes:
- URL of the website
- Timestamp of collection
- Array of cookies with detailed attributes

## Cookie Attributes Collected

For each cookie, the following attributes are collected:
- Name
- Value
- Domain
- Path
- Expiration date
- Secure flag
- HttpOnly flag
- SameSite policy

## Requirements

- Python 3.6+
- Scrapy
- pandas (for analysis)
- tabulate (for pretty printing)
