"""
Scrapy settings for cookie_scraper project
"""

BOT_NAME = 'cookie_scraper'

SPIDER_MODULES = ['cookie_scraper.spiders']
NEWSPIDER_MODULE = 'cookie_scraper.spiders'

# Crawl responsibly by identifying yourself on the user-agent
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'

# Obey robots.txt rules (set to False to ignore robots.txt)
ROBOTSTXT_OBEY = False

# Configure maximum concurrent requests
CONCURRENT_REQUESTS = 16

# Configure a delay for requests for the same website
DOWNLOAD_DELAY = 1

# Enable cookies
COOKIES_ENABLED = True
COOKIES_DEBUG = True

# Disable Telnet Console
TELNETCONSOLE_ENABLED = False

# Override the default request headers
DEFAULT_REQUEST_HEADERS = {
   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
   'Accept-Language': 'en',
}

# Enable or disable spider middlewares
SPIDER_MIDDLEWARES = {
}

# Enable or disable downloader middlewares
DOWNLOADER_MIDDLEWARES = {
}

# Configure item pipelines
ITEM_PIPELINES = {
}

# Set settings whose default value is deprecated to a future-proof value
REQUEST_FINGERPRINTER_IMPLEMENTATION = "2.7"
TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"
FEED_EXPORT_ENCODING = "utf-8"
