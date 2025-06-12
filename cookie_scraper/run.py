#!/usr/bin/env python3
"""
Script to run the cookie spider with command line arguments.
Supports both regular Scrapy and Selenium-enhanced cookie extraction.
"""
import argparse
import os
import sys
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings
from spiders.cookie_spider import CookieSpider


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Run cookie spider to collect cookies from websites')
    parser.add_argument('--urls', type=str, help='Comma-separated list of URLs to scrape')
    parser.add_argument('--output', type=str, default='cookies_output.json', 
                        help='Output file for scrapy results (default: cookies_output.json)')
    parser.add_argument('--log-level', type=str, default='INFO', 
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Log level (default: INFO)')
    
    # Selenium-specific arguments
    parser.add_argument('--no-selenium', action='store_true', 
                        help='Disable Selenium and use only Scrapy for cookie extraction')
    parser.add_argument('--no-headless', action='store_true', 
                        help='Run Selenium in non-headless mode (shows browser UI)')
    parser.add_argument('--wait-time', type=int, default=5, 
                        help='Time to wait (in seconds) for JavaScript execution (default: 5)')
    
    args = parser.parse_args()

    # Configure settings
    settings = get_project_settings()
    settings.update({
        'LOG_LEVEL': args.log_level,
        'FEEDS': {
            args.output: {
                'format': 'json',
                'encoding': 'utf8',
                'indent': 4,
                'overwrite': True,
            },
        },
        'USER_AGENT': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
        'ROBOTSTXT_OBEY': False,
        'COOKIES_ENABLED': True,
        'COOKIES_DEBUG': True,
        'DOWNLOAD_TIMEOUT': 60,
        'SELENIUM_DRIVER_ARGUMENTS': ['--no-sandbox', '--disable-dev-shm-usage']
    })

    # Create and run crawler process
    process = CrawlerProcess(settings)
    
    # Configure spider parameters based on command line arguments
    spider_kwargs = {
        'urls': args.urls,
        'headless': not args.no_headless,
        'wait_time': args.wait_time,
        'no_selenium': args.no_selenium
    }
    
    # If --no-selenium is specified, modify the spider class to skip Selenium setup
    if args.no_selenium:
        print("Running without Selenium (using only Scrapy for cookie extraction)")
        # We'll handle this in the spider by checking if driver is None
        spider_kwargs['headless'] = False  # This will cause the driver not to be initialized
    
    # Start the crawler
    process.crawl(CookieSpider, **spider_kwargs)
    process.start()
    
    # Print summary after completion
    cookies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cookies')
    cookie_files = os.listdir(cookies_dir) if os.path.exists(cookies_dir) else []
    print(f"\nSummary:")
    print(f"Cookies saved to: {cookies_dir}")
    print(f"Total cookie files: {len(cookie_files)}")
    print(f"Spider results saved to: {args.output}")
    
    # Print Selenium status
    if not args.no_selenium:
        print(f"Selenium mode: {'Headless' if not args.no_headless else 'Visible browser'}")
        print(f"JavaScript wait time: {args.wait_time} seconds")


if __name__ == "__main__":
    main()
