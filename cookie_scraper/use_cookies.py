#!/usr/bin/env python3
"""
Script to load saved cookies and use them for making requests.
This demonstrates how to use the cookies collected by the cookie_spider.
"""
import os
import json
import argparse
import requests
from urllib.parse import urlparse


def load_cookies_for_domain(cookies_dir, target_domain):
    """
    Load cookies for a specific domain from the cookies directory.
    Returns the most recent cookie file for the domain.
    """
    if not os.path.exists(cookies_dir):
        print(f"Error: Cookie directory '{cookies_dir}' does not exist")
        return None
    
    # Normalize target domain
    if target_domain.startswith(('http://', 'https://')):
        target_domain = urlparse(target_domain).netloc
    
    # Find cookie files for the domain
    domain_files = []
    for filename in os.listdir(cookies_dir):
        if filename.startswith(target_domain.replace('.', '_')) and filename.endswith('.json'):
            filepath = os.path.join(cookies_dir, filename)
            domain_files.append((filepath, os.path.getmtime(filepath)))
    
    # Sort by modification time (newest first)
    domain_files.sort(key=lambda x: x[1], reverse=True)
    
    if not domain_files:
        print(f"No cookie files found for domain: {target_domain}")
        return None
    
    # Load the most recent cookie file
    filepath = domain_files[0][0]
    try:
        with open(filepath, 'r') as f:
            cookie_data = json.load(f)
        print(f"Loaded cookies from: {filepath}")
        return cookie_data
    except Exception as e:
        print(f"Error loading cookie file: {e}")
        return None


def make_request_with_cookies(url, cookie_data):
    """Make a request to the URL using the loaded cookies."""
    if not cookie_data or 'cookies' not in cookie_data:
        print("No valid cookie data provided")
        return None
    
    # Convert cookies to requests format
    cookies_dict = {}
    for cookie in cookie_data['cookies']:
        cookies_dict[cookie['name']] = cookie['value']
    
    # Make the request
    try:
        print(f"Making request to {url} with {len(cookies_dict)} cookies")
        response = requests.get(url, cookies=cookies_dict, 
                               headers={'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'})
        return response
    except Exception as e:
        print(f"Error making request: {e}")
        return None


def save_response(response, output_file):
    """Save the response content to a file."""
    if response is None:
        return
    
    try:
        with open(output_file, 'wb') as f:
            f.write(response.content)
        print(f"Response saved to: {output_file}")
    except Exception as e:
        print(f"Error saving response: {e}")


def main():
    parser = argparse.ArgumentParser(description='Use saved cookies to make HTTP requests')
    parser.add_argument('--url', type=str, required=True,
                        help='URL to make request to')
    parser.add_argument('--cookies-dir', type=str, default='cookies',
                        help='Directory containing cookie JSON files (default: cookies)')
    parser.add_argument('--output', type=str, default='response.html',
                        help='File to save response to (default: response.html)')
    args = parser.parse_args()
    
    # Resolve cookies directory path
    cookies_dir = args.cookies_dir
    if not os.path.isabs(cookies_dir):
        cookies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), cookies_dir)
    
    # Extract domain from URL
    domain = urlparse(args.url).netloc
    
    # Load cookies for the domain
    cookie_data = load_cookies_for_domain(cookies_dir, domain)
    
    if cookie_data:
        # Make request with cookies
        response = make_request_with_cookies(args.url, cookie_data)
        
        if response:
            print(f"Request successful: Status code {response.status_code}")
            
            # Save response to file
            save_response(response, args.output)
            
            # Check for new cookies in the response
            if response.cookies:
                print(f"Received {len(response.cookies)} new cookies in the response")
                for cookie in response.cookies:
                    print(f"  {cookie.name}: {cookie.value[:30]}...")


if __name__ == "__main__":
    main()
