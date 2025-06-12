#!/usr/bin/env python3
"""
Utility functions for analyzing and managing cookies collected by the cookie spider.
"""
import os
import json
import argparse
from datetime import datetime
import pandas as pd
from tabulate import tabulate
import matplotlib.pyplot as plt
import numpy as np
import matplotlib
import collections
from urllib.parse import urlparse, unquote
import re
import tldextract  # For better domain parsing
matplotlib.use('Agg')  # Use non-interactive backend


def load_cookie_files(cookies_dir):
    """Load all cookie files from the specified directory."""
    cookie_files = []
    for filename in os.listdir(cookies_dir):
        if filename.endswith('.json'):
            filepath = os.path.join(cookies_dir, filename)
            try:
                with open(filepath, 'r') as f:
                    cookie_data = json.load(f)
                    cookie_data['file'] = filename
                    cookie_files.append(cookie_data)
            except Exception as e:
                print(f"Error loading {filename}: {e}")
    return cookie_files


def analyze_xss_vulnerabilities(cookie_files):
    """Analyze cookie values for potential XSS vulnerabilities.
    
    Args:
        cookie_files: List of cookie data files
        
    Returns:
        Dictionary containing XSS vulnerability statistics and findings
    """
    if not cookie_files:
        return {
            'total_cookies_analyzed': 0,
            'potentially_vulnerable_cookies': 0,
            'xss_findings': [],
            'vulnerable_domains': {}
        }
    
    # Initialize stats dictionary
    stats = _initialize_xss_stats()
    
    # Get compiled XSS patterns
    compiled_patterns, xss_patterns = _get_xss_patterns()
    
    # Process each cookie file
    for data in cookie_files:
        url = data.get('url', 'unknown')
        domain = urlparse(url).netloc
        
        # Process all cookies in this file
        _process_cookies_for_xss(data, domain, stats, compiled_patterns, xss_patterns)
    
    return stats

def _initialize_xss_stats():
    """Initialize the XSS statistics dictionary.
    
    Returns:
        Dictionary with initialized XSS statistics
    """
    return {
        'total_cookies_analyzed': 0,
        'potentially_vulnerable_cookies': 0,
        'xss_findings': [],
        'vulnerable_domains': {}
    }

def _get_xss_patterns():
    """Define and compile XSS detection patterns.
    
    Returns:
        Tuple of (compiled_patterns, raw_patterns)
    """
    # Common XSS payload patterns to check for
    xss_patterns = [
        r'<script[^>]*>',                      # Basic script tags
        r'javascript\s*:',                      # JavaScript protocol
        r'\bon\w+\s*=',                         # Event handlers (onclick, onload, etc.)
        r'\beval\s*\(',                         # eval() function
        r'document\.cookie',                    # Cookie manipulation
        r'document\.location',                  # Location manipulation
        r'<img[^>]*\bonerror\b[^>]*>',          # Image onerror
        r'<iframe[^>]*>',                       # iframes
        r'\balert\s*\(',                        # alert() function
        r'\bprompt\s*\(',                       # prompt() function
        r'\bconfirm\s*\(',                      # confirm() function
        r'\bdocument\.write\s*\(',              # document.write()
        r'\bdocument\.domain',                  # document.domain manipulation
        r'\blocation\.href',                    # location.href manipulation
        r'\blocation\.replace\s*\(',            # location.replace()
        r'\bwindow\.open\s*\(',                 # window.open()
        r'data:text/html',                      # Data URI with HTML
        r'&#x[0-9a-fA-F]+;',                    # Hex entity encoding
        r'&#[0-9]+;',                           # Decimal entity encoding
        r'\\x[0-9a-fA-F]{2}',                   # Hex escape sequences
        r'\\u[0-9a-fA-F]{4}'                    # Unicode escape sequences
    ]
    
    # Compile all patterns for efficiency
    compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in xss_patterns]
    return compiled_patterns, xss_patterns

def _process_cookies_for_xss(data, domain, stats, compiled_patterns, xss_patterns):
    """Process cookies from a single data file for XSS vulnerabilities.
    
    Args:
        data: Cookie data file content
        domain: Domain being analyzed
        stats: Statistics dictionary to update
        compiled_patterns: Compiled regex patterns for XSS detection
        xss_patterns: Raw XSS patterns for reporting
    """
    for cookie in data.get('cookies', []):
        stats['total_cookies_analyzed'] += 1
        cookie_name = cookie.get('name', 'unknown')
        cookie_value = cookie.get('value', '')
        cookie_domain = cookie.get('domain', domain)
        
        # Skip empty values
        if not cookie_value:
            continue
        
        # Check for XSS in this cookie
        matched_patterns = _check_cookie_for_xss(cookie_value, compiled_patterns, xss_patterns)
        
        # If vulnerable, update statistics
        if matched_patterns:
            _update_xss_stats(stats, domain, cookie, cookie_name, cookie_domain, matched_patterns)

def _check_cookie_for_xss(cookie_value, compiled_patterns, xss_patterns):
    """Check a cookie value for XSS patterns.
    
    Args:
        cookie_value: The cookie value to check
        compiled_patterns: Compiled regex patterns
        xss_patterns: Raw XSS patterns for reporting
        
    Returns:
        List of matched patterns or empty list if none
    """
    # URL decode the value to check for encoded payloads
    try:
        decoded_value = unquote(cookie_value)
    except (TypeError, ValueError) as e:
        # Specify exact exceptions to catch
        decoded_value = cookie_value
    
    # Check for potential XSS patterns
    matched_patterns = []
    
    for i, pattern in enumerate(compiled_patterns):
        if pattern.search(decoded_value):
            matched_patterns.append(xss_patterns[i])
    
    return matched_patterns

def _update_xss_stats(stats, domain, cookie, cookie_name, cookie_domain, matched_patterns):
    """Update XSS statistics when a vulnerable cookie is found.
    
    Args:
        stats: Statistics dictionary to update
        domain: Domain being analyzed
        cookie: Cookie object
        cookie_name: Name of the cookie
        cookie_domain: Domain of the cookie
        matched_patterns: List of XSS patterns matched
    """
    stats['potentially_vulnerable_cookies'] += 1
    
    # Add to vulnerable domains
    if domain not in stats['vulnerable_domains']:
        stats['vulnerable_domains'][domain] = {
            'count': 0,
            'cookies': []
        }
    
    stats['vulnerable_domains'][domain]['count'] += 1
    stats['vulnerable_domains'][domain]['cookies'].append({
        'name': cookie_name,
        'matched_patterns': matched_patterns,
        'httponly': cookie.get('httpOnly', False),
        'secure': cookie.get('secure', False)
    })
    
    # Add to findings list
    finding = {
        'domain': domain,
        'cookie_domain': cookie_domain,
        'cookie_name': cookie_name,
        'matched_patterns': matched_patterns,
        'httponly': cookie.get('httpOnly', False),
        'secure': cookie.get('secure', False),
        'path': cookie.get('path', '/'),
        'sameSite': cookie.get('sameSite', 'None')
    }
    stats['xss_findings'].append(finding)


def analyze_domain_relationships(cookie_files):
    """Analyze domain relationships between first-party and third-party cookies.
    
    Args:
        cookie_files: List of cookie data files
        
    Returns:
        Dictionary containing domain relationship statistics
    """
    if not cookie_files:
        return {
            'domain_relationships': {},
            'third_party_domains': {},
            'third_party_purposes': {},
            'top_trackers': []
        }
    
    # Initialize statistics
    stats = {
        'domain_relationships': {},  # Maps first-party domains to their third-party trackers
        'third_party_domains': {},   # Count of third-party domains across all sites
        'third_party_purposes': {},  # Tracking purposes by domain
        'top_trackers': []           # Most common third-party trackers
    }
    
    # Process each cookie file
    for data in cookie_files:
        url = data.get('url', 'unknown')
        first_party_domain = urlparse(url).netloc
        
        # Extract registered domain (e.g., example.com from www.example.com)
        try:
            extract = tldextract.extract(first_party_domain)
            first_party_registered = f"{extract.domain}.{extract.suffix}"
        except:
            first_party_registered = first_party_domain
        
        # Initialize domain relationship entry if it doesn't exist
        if first_party_registered not in stats['domain_relationships']:
            stats['domain_relationships'][first_party_registered] = {
                'third_parties': {},
                'total_third_party_cookies': 0
            }
        
        # Process explicitly identified third-party cookies if available
        third_party_cookies = data.get('third_party_cookies', [])
        if third_party_cookies:
            for cookie in third_party_cookies:
                cookie_domain = cookie.get('domain', '')
                if not cookie_domain:
                    continue
                    
                # Remove leading dot if present
                if cookie_domain.startswith('.'):
                    cookie_domain = cookie_domain[1:]
                
                # Extract registered domain
                try:
                    extract = tldextract.extract(cookie_domain)
                    third_party_registered = f"{extract.domain}.{extract.suffix}"
                except:
                    third_party_registered = cookie_domain
                
                # Skip if it's actually the same domain
                if third_party_registered == first_party_registered:
                    continue
                
                # Update domain relationships
                if third_party_registered not in stats['domain_relationships'][first_party_registered]['third_parties']:
                    stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered] = {
                        'count': 0,
                        'purposes': set(),
                        'cookie_names': []
                    }
                
                # Update counts and details
                stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered]['count'] += 1
                stats['domain_relationships'][first_party_registered]['total_third_party_cookies'] += 1
                
                # Track cookie name
                cookie_name = cookie.get('name', 'unknown')
                stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered]['cookie_names'].append(cookie_name)
                
                # Track purpose if available
                purpose = cookie.get('tracking_purpose', 'Unknown')
                stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered]['purposes'].add(purpose)
                
                # Update global third-party domain counts
                stats['third_party_domains'][third_party_registered] = stats['third_party_domains'].get(third_party_registered, 0) + 1
                
                # Update tracking purposes
                if third_party_registered not in stats['third_party_purposes']:
                    stats['third_party_purposes'][third_party_registered] = {}
                
                stats['third_party_purposes'][third_party_registered][purpose] = stats['third_party_purposes'].get(third_party_registered, {}).get(purpose, 0) + 1
        
        # Fall back to analyzing all cookies if no explicit third-party cookies are identified
        elif 'cookies' in data:
            for cookie in data.get('cookies', []):
                cookie_domain = cookie.get('domain', '')
                if not cookie_domain:
                    continue
                
                # Check if this is a third-party cookie
                is_third_party = cookie.get('is_third_party', False)
                if not is_third_party:
                    # Try to determine if it's third-party by comparing domains
                    if cookie_domain.startswith('.'):
                        cookie_domain = cookie_domain[1:]
                    
                    try:
                        extract = tldextract.extract(cookie_domain)
                        third_party_registered = f"{extract.domain}.{extract.suffix}"
                        is_third_party = third_party_registered != first_party_registered
                    except:
                        is_third_party = cookie_domain != first_party_domain
                
                if is_third_party:
                    # Process as third-party cookie
                    try:
                        extract = tldextract.extract(cookie_domain)
                        third_party_registered = f"{extract.domain}.{extract.suffix}"
                    except:
                        third_party_registered = cookie_domain
                    
                    # Update domain relationships
                    if third_party_registered not in stats['domain_relationships'][first_party_registered]['third_parties']:
                        stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered] = {
                            'count': 0,
                            'purposes': set(),
                            'cookie_names': []
                        }
                    
                    # Update counts and details
                    stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered]['count'] += 1
                    stats['domain_relationships'][first_party_registered]['total_third_party_cookies'] += 1
                    
                    # Track cookie name
                    cookie_name = cookie.get('name', 'unknown')
                    stats['domain_relationships'][first_party_registered]['third_parties'][third_party_registered]['cookie_names'].append(cookie_name)
                    
                    # Update global third-party domain counts
                    stats['third_party_domains'][third_party_registered] = stats['third_party_domains'].get(third_party_registered, 0) + 1
    
    # Convert sets to lists for JSON serialization
    for first_party in stats['domain_relationships']:
        for third_party in stats['domain_relationships'][first_party]['third_parties']:
            stats['domain_relationships'][first_party]['third_parties'][third_party]['purposes'] = \
                list(stats['domain_relationships'][first_party]['third_parties'][third_party]['purposes'])
    
    # Calculate top trackers
    top_trackers = sorted(stats['third_party_domains'].items(), key=lambda x: x[1], reverse=True)[:10]
    stats['top_trackers'] = [{'domain': domain, 'count': count} for domain, count in top_trackers]
    
    return stats


def analyze_cookies(cookie_files):
    """Analyze cookies and storage data and return statistics."""
    if not cookie_files:
        return {
            'total_domains': 0,
            'total_cookies': 0,
            'total_localStorage': 0,
            'total_sessionStorage': 0,
            'cookies_per_domain': {},
            'storage_per_domain': {},
            'common_cookie_names': {},
            'common_storage_keys': {},
            'secure_cookies': 0,
            'httponly_cookies': 0,
            'third_party_cookies': 0,
            'session_cookies': 0,
            'persistent_cookies': 0,
            'cookie_age_categories': {
                'session': 0,
                'short_term': 0,  # Less than 1 day
                'medium_term': 0,  # 1-30 days
                'long_term': 0,    # More than 30 days
                'expired': 0       # Already expired
            },
            'avg_cookie_age_days': 0,
            'max_cookie_age_days': 0,
            'domain_analysis': {},
            'samesite_stats': {
                'None': 0,
                'Lax': 0,
                'Strict': 0,
                'unspecified': 0
            },
            'samesite_by_domain': {}
        }
    
    stats = {
        'total_domains': len(cookie_files),
        'total_cookies': sum(len(data.get('cookies', [])) for data in cookie_files),
        'total_localStorage': sum(len(data.get('localStorage', {})) for data in cookie_files),
        'total_sessionStorage': sum(len(data.get('sessionStorage', {})) for data in cookie_files),
        'cookies_per_domain': {},
        'storage_per_domain': {},
        'common_cookie_names': {},
        'common_storage_keys': {},
        'secure_cookies': 0,
        'httponly_cookies': 0,
        'third_party_cookies': 0,
        'session_cookies': 0,
        'persistent_cookies': 0,
        'cookie_age_categories': {
            'session': 0,
            'short_term': 0,  # Less than 1 day
            'medium_term': 0,  # 1-30 days
            'long_term': 0,    # More than 30 days
            'expired': 0       # Already expired
        },
        'avg_cookie_age_days': 0,
        'max_cookie_age_days': 0,
        'cookie_age_distribution': {},
        'samesite_stats': {
            'None': 0,
            'Lax': 0,
            'Strict': 0,
            'unspecified': 0
        },
        'samesite_by_domain': {}
    }
    
    for data in cookie_files:
        domain = data.get('url', 'unknown')
        cookies = data.get('cookies', [])
        local_storage = data.get('localStorage', {})
        session_storage = data.get('sessionStorage', {})
        
        # Count cookies and storage items per domain
        stats['cookies_per_domain'][domain] = len(cookies)
        stats['storage_per_domain'][domain] = len(local_storage) + len(session_storage)
        
        main_domain = '.'.join(urlparse(domain).netloc.split('.')[-2:]) if 'url' in data else 'unknown'
        
        # Analyze cookies
        for cookie in cookies:
            # Count cookie names
            name = cookie.get('name', '')
            stats['common_cookie_names'][name] = stats['common_cookie_names'].get(name, 0) + 1
            
            # Count secure and httponly cookies
            if cookie.get('secure', False):
                stats['secure_cookies'] += 1
            if cookie.get('httponly', False):
                stats['httponly_cookies'] += 1
            
            # Count third-party cookies
            cookie_domain = cookie.get('domain', '')
            if cookie_domain and not cookie_domain.endswith(main_domain) and not main_domain.endswith(cookie_domain):
                stats['third_party_cookies'] += 1
                
            # Analyze cookie age
            age_info = cookie.get('age', {})
            
            if age_info:
                # Categorize cookies by session vs persistent
                if age_info.get('is_session', True):
                    stats['session_cookies'] += 1
                    stats['cookie_age_categories']['session'] += 1
                else:
                    stats['persistent_cookies'] += 1
                    
                    # Get age in days
                    age_days = age_info.get('days')
                    
                    if age_days is not None:
                        # Categorize by age range
                        if age_days <= 0:
                            stats['cookie_age_categories']['expired'] += 1
                        elif age_days < 1:
                            stats['cookie_age_categories']['short_term'] += 1
                        elif age_days <= 30:
                            stats['cookie_age_categories']['medium_term'] += 1
                        else:
                            stats['cookie_age_categories']['long_term'] += 1
                            
                        # Round age to nearest day for distribution
                        rounded_age = max(0, int(age_days))
                        stats['cookie_age_distribution'][rounded_age] = stats['cookie_age_distribution'].get(rounded_age, 0) + 1
                        
            # Analyze SameSite attribute
            samesite = cookie.get('samesite', '')
            if not samesite:
                samesite = 'unspecified'
            elif samesite.lower() not in ['none', 'lax', 'strict']:
                samesite = 'unspecified'
            else:
                # Capitalize first letter for consistency
                samesite = samesite.capitalize()
                
            # Update global SameSite stats
            stats['samesite_stats'][samesite] += 1
            
            # Update domain-specific SameSite stats
            if domain not in stats['samesite_by_domain']:
                stats['samesite_by_domain'][domain] = {
                    'None': 0,
                    'Lax': 0,
                    'Strict': 0,
                    'unspecified': 0
                }
            stats['samesite_by_domain'][domain][samesite] += 1
        
        # Analyze localStorage and sessionStorage
        for key in local_storage:
            stats['common_storage_keys'][f'localStorage:{key}'] = stats['common_storage_keys'].get(f'localStorage:{key}', 0) + 1
            
        for key in session_storage:
            stats['common_storage_keys'][f'sessionStorage:{key}'] = stats['common_storage_keys'].get(f'sessionStorage:{key}', 0) + 1
    
    # Sort common cookie names by frequency
    stats['common_cookie_names'] = dict(sorted(
        stats['common_cookie_names'].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10])
    
    # Sort common storage keys by frequency
    stats['common_storage_keys'] = dict(sorted(
        stats['common_storage_keys'].items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10])
    
    # Calculate average and maximum cookie age
    persistent_ages = [age for age, count in stats['cookie_age_distribution'].items() 
                      for _ in range(count) if age > 0]
    
    if persistent_ages:
        stats['avg_cookie_age_days'] = sum(persistent_ages) / len(persistent_ages)
        stats['max_cookie_age_days'] = max(persistent_ages)
    
    # Sort age distribution for better display
    stats['cookie_age_distribution'] = dict(sorted(
        stats['cookie_age_distribution'].items(), 
        key=lambda x: x[0]
    ))
    
    return stats


def export_cookies_to_csv(cookie_files, output_file):
    """Export all cookies and storage data to a CSV file for further analysis."""
    # Create separate dataframes for cookies and storage
    cookie_rows = []
    storage_rows = []
    
    for data in cookie_files:
        domain = data.get('url', 'unknown')
        timestamp = data.get('timestamp', datetime.now().isoformat())
        source = data.get('source', 'unknown')
        
        # Process cookies
        for cookie in data.get('cookies', []):
            cookie_rows.append({
                'type': 'cookie',
                'domain': domain,
                'timestamp': timestamp,
                'source': source,
                'name': cookie.get('name', ''),
                'value': cookie.get('value', '')[:30] + '...' if len(cookie.get('value', '')) > 30 else cookie.get('value', ''),
                'storage_domain': cookie.get('domain', ''),
                'path': cookie.get('path', ''),
                'expires': cookie.get('expires', ''),
                'secure': cookie.get('secure', False),
                'httponly': cookie.get('httponly', False),
                'samesite': cookie.get('samesite', ''),
                'storage_type': 'N/A'
            })
        
        # Process localStorage
        for key, value in data.get('localStorage', {}).items():
            storage_rows.append({
                'type': 'storage',
                'domain': domain,
                'timestamp': timestamp,
                'source': source,
                'name': key,
                'value': str(value)[:30] + '...' if len(str(value)) > 30 else str(value),
                'storage_domain': domain,
                'path': '/',
                'expires': 'persistent',
                'secure': False,
                'httponly': False,
                'samesite': '',
                'storage_type': 'localStorage'
            })
        
        # Process sessionStorage
        for key, value in data.get('sessionStorage', {}).items():
            storage_rows.append({
                'type': 'storage',
                'domain': domain,
                'timestamp': timestamp,
                'source': source,
                'name': key,
                'value': str(value)[:30] + '...' if len(str(value)) > 30 else str(value),
                'storage_domain': domain,
                'path': '/',
                'expires': 'session',
                'secure': False,
                'httponly': False,
                'samesite': '',
                'storage_type': 'sessionStorage'
            })
    
    # Combine all rows
    all_rows = cookie_rows + storage_rows
    
    if all_rows:
        df = pd.DataFrame(all_rows)
        df.to_csv(output_file, index=False)
        print(f"Exported {len(cookie_rows)} cookies and {len(storage_rows)} storage items to {output_file}")
    else:
        print("No data to export")


def generate_charts(stats, output_dir='charts'):
    """Generate visual charts for cookie statistics."""
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Only generate charts if we have cookies
    if stats['total_cookies'] == 0:
        return
    
    # 1. Cookie Security Bar Chart
    plt.figure(figsize=(10, 6))
    security_data = [
        stats['secure_cookies'],
        stats['httponly_cookies'],
        stats['third_party_cookies'],
        stats['session_cookies'],
        stats['persistent_cookies']
    ]
    labels = ['Secure', 'HttpOnly', 'Third-Party', 'Session', 'Persistent']
    colors = ['#4CAF50', '#2196F3', '#FFC107', '#9C27B0', '#F44336']
    
    bars = plt.bar(labels, security_data, color=colors)
    plt.title('Cookie Security Analysis', fontsize=16)
    plt.ylabel('Number of Cookies', fontsize=12)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    
    # Add data labels on top of bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height + 0.1,
                f'{height}', ha='center', va='bottom')
    
    # Add percentage labels inside bars
    for i, bar in enumerate(bars):
        height = bar.get_height()
        if height > 0:
            percentage = (height / stats['total_cookies']) * 100
            plt.text(bar.get_x() + bar.get_width()/2., height/2,
                    f'{percentage:.1f}%', ha='center', va='center', 
                    color='white', fontweight='bold')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'cookie_security.png'))
    plt.close()
    
    # 2. Cookie Age Categories Pie Chart
    if stats['persistent_cookies'] > 0:
        plt.figure(figsize=(10, 8))
        categories = stats['cookie_age_categories']
        labels = []
        sizes = []
        
        for category, count in categories.items():
            if count > 0:
                labels.append(category.replace('_', ' ').title())
                sizes.append(count)
        
        # Use a nice color palette
        colors = plt.cm.Paired(np.linspace(0, 1, len(labels)))
        
        # Create pie chart with a hole in the middle (donut chart)
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', 
                startangle=90, shadow=True, wedgeprops={'edgecolor': 'w'})
        plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
        plt.title('Cookie Age Distribution', fontsize=16)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'cookie_age_pie.png'))
        plt.close()
        
        # 3. Cookie Age Distribution Line Chart
        if len(stats['cookie_age_distribution']) > 1:
            plt.figure(figsize=(12, 6))
            
            # Group by ranges for better display if we have many different ages
            if len(stats['cookie_age_distribution']) > 10:
                # Create age ranges
                ranges = [(0, 1), (1, 7), (7, 30), (30, 90), (90, 180), (180, 365), (365, float('inf'))]
                range_labels = ["<1 day", "1-7 days", "7-30 days", "1-3 months", "3-6 months", "6-12 months", ">1 year"]
                range_counts = [0] * len(ranges)
                
                for age, count in stats['cookie_age_distribution'].items():
                    for i, (min_age, max_age) in enumerate(ranges):
                        if min_age <= age < max_age:
                            range_counts[i] += count
                            break
                
                plt.bar(range_labels, range_counts, color='#3F51B5', alpha=0.7)
                plt.plot(range_labels, range_counts, 'o-', color='#E91E63', linewidth=2, markersize=8)
            else:
                # Use individual days
                ages = list(stats['cookie_age_distribution'].keys())
                counts = list(stats['cookie_age_distribution'].values())
                
                plt.bar(ages, counts, color='#3F51B5', alpha=0.7)
                plt.plot(ages, counts, 'o-', color='#E91E63', linewidth=2, markersize=8)
            
            plt.title('Cookie Age Distribution', fontsize=16)
            plt.xlabel('Cookie Age', fontsize=12)
            plt.ylabel('Number of Cookies', fontsize=12)
            plt.grid(linestyle='--', alpha=0.7)
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'cookie_age_distribution.png'))
            plt.close()
    
    # 4. SameSite Statistics Pie Chart
    plt.figure(figsize=(10, 8))
    samesite_data = []
    labels = []
    
    for samesite_type, count in stats['samesite_stats'].items():
        if count > 0:
            samesite_data.append(count)
            labels.append(samesite_type)
    
    # Use a nice color palette
    colors = plt.cm.tab10(np.linspace(0, 1, len(labels)))
    
    # Create pie chart
    plt.pie(samesite_data, labels=labels, colors=colors, autopct='%1.1f%%', 
            startangle=90, shadow=True, wedgeprops={'edgecolor': 'w'})
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
    plt.title('SameSite Cookie Distribution', fontsize=16)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'samesite_distribution.png'))
    plt.close()
    
    # 5. SameSite by Domain Stacked Bar Chart (for top domains)
    if stats['samesite_by_domain']:
        plt.figure(figsize=(14, 10))
        
        # Get top domains by total cookie count (limit to top 10 for readability)
        top_domains = sorted(stats['samesite_by_domain'].items(), 
                           key=lambda x: sum(x[1].values()), 
                           reverse=True)[:10]
        
        domains = [d[0] for d in top_domains]
        # Shorten domain names if they're too long
        domains = [d[-30:] if len(d) > 30 else d for d in domains]
        
        # Prepare data for stacked bar chart
        none_values = [d[1].get('None', 0) for d in top_domains]
        lax_values = [d[1].get('Lax', 0) for d in top_domains]
        strict_values = [d[1].get('Strict', 0) for d in top_domains]
        unspecified_values = [d[1].get('unspecified', 0) for d in top_domains]
        
        # Create stacked bar chart
        bar_width = 0.8
        indices = np.arange(len(domains))
        
        p1 = plt.bar(indices, none_values, bar_width, label='None', color='#FF9800')
        p2 = plt.bar(indices, lax_values, bar_width, bottom=none_values, label='Lax', color='#4CAF50')
        
        # Add the strict values on top of none and lax
        bottom_values = [n + l for n, l in zip(none_values, lax_values)]
        p3 = plt.bar(indices, strict_values, bar_width, bottom=bottom_values, label='Strict', color='#2196F3')
        
        # Add the unspecified values on top of the rest
        bottom_values = [n + l + s for n, l, s in zip(none_values, lax_values, strict_values)]
        p4 = plt.bar(indices, unspecified_values, bar_width, bottom=bottom_values, label='Unspecified', color='#9E9E9E')
        
        # Customize the chart
        plt.xlabel('Domain', fontsize=14)
        plt.ylabel('Number of Cookies', fontsize=14)
        plt.title('SameSite Cookie Settings by Domain (Top 10)', fontsize=16)
        plt.xticks(indices, domains, rotation=45, ha='right', fontsize=10)
        plt.legend()
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'samesite_by_domain.png'))
        plt.close()
    
    # 6. Top Cookie Names Bar Chart
    if stats['common_cookie_names']:
        plt.figure(figsize=(12, 8))
        names = list(stats['common_cookie_names'].keys())
        counts = list(stats['common_cookie_names'].values())
        
        # Sort by count
        sorted_indices = np.argsort(counts)
        names = [names[i] for i in sorted_indices]
        counts = [counts[i] for i in sorted_indices]
        
        # Horizontal bar chart
        bars = plt.barh(names, counts, color='#009688')
        plt.title('Top Cookie Names', fontsize=16)
        plt.xlabel('Count', fontsize=12)
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        
        # Add count labels
        for bar in bars:
            width = bar.get_width()
            plt.text(width + 0.1, bar.get_y() + bar.get_height()/2,
                    f'{width}', ha='left', va='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'top_cookie_names.png'))
        plt.close()
    
    # 5. Per-Domain Statistics
    domain_data = []
    for domain in set(list(stats['cookies_per_domain'].keys()) + list(stats['storage_per_domain'].keys())):
        cookie_count = stats['cookies_per_domain'].get(domain, 0)
        storage_count = stats['storage_per_domain'].get(domain, 0)
        domain_data.append((domain, cookie_count, storage_count))
    
    # Sort by total count
    domain_data.sort(key=lambda x: x[1] + x[2], reverse=True)
    
    # Take top 10 domains
    domain_data = domain_data[:10]
    
    if domain_data:
        plt.figure(figsize=(12, 8))
        domains = [d[0] for d in domain_data]
        cookie_counts = [d[1] for d in domain_data]
        storage_counts = [d[2] for d in domain_data]
        
        # Shorten domain names if they're too long
        shortened_domains = []
        for domain in domains:
            if len(domain) > 30:
                shortened_domains.append(domain[:27] + '...')
            else:
                shortened_domains.append(domain)
        
        # Create stacked bar chart
        bar_width = 0.8
        plt.barh(shortened_domains, cookie_counts, bar_width, label='Cookies', color='#FF5722')
        plt.barh(shortened_domains, storage_counts, bar_width, left=cookie_counts, label='Storage Items', color='#673AB7')
        
        plt.title('Storage Items per Domain (Top 10)', fontsize=16)
        plt.xlabel('Number of Items', fontsize=12)
        plt.legend(loc='best')
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'domain_statistics.png'))
        plt.close()
    
    print(f"\nCharts have been generated in the '{output_dir}' directory.")
    return output_dir


def print_stats(stats):
    """Print cookie and storage statistics."""
    print("=== Browser Storage Statistics ===")
    print(f"Total domains analyzed: {stats['total_domains']}")
    print()
    
    print("--- Cookie Statistics ---")
    print(f"Total cookies found: {stats['total_cookies']}")
    print(f"Secure cookies: {stats['secure_cookies']} ({stats['secure_cookies']/stats['total_cookies']*100:.1f}% of total)")
    print(f"HttpOnly cookies: {stats['httponly_cookies']} ({stats['httponly_cookies']/stats['total_cookies']*100:.1f}% of total)")
    print(f"Third-party cookies: {stats['third_party_cookies']} ({stats['third_party_cookies']/stats['total_cookies']*100:.1f}% of total)")
    
    # Print SameSite statistics
    print("\n--- SameSite Cookie Statistics ---")
    for samesite_type, count in stats['samesite_stats'].items():
        if stats['total_cookies'] > 0:
            percentage = (count / stats['total_cookies']) * 100
            print(f"{samesite_type}: {count} ({percentage:.1f}% of total)")
    
    # Print SameSite statistics by domain
    print("\nSameSite Statistics by Domain:")
    for domain, samesite_counts in stats['samesite_by_domain'].items():
        print(f"\n  {domain}:")
        total_domain_cookies = sum(samesite_counts.values())
        for samesite_type, count in samesite_counts.items():
            if count > 0:
                percentage = (count / total_domain_cookies) * 100
                print(f"    {samesite_type}: {count} ({percentage:.1f}%)")
    
    # Print XSS vulnerability statistics if available
    if 'xss_analysis' in stats and stats['xss_analysis']:
        print()
        print("--- XSS Vulnerability Analysis ---")
        xss_stats = stats['xss_analysis']
        print(f"Total cookies analyzed for XSS: {xss_stats['total_cookies_analyzed']}")
        print(f"Potentially vulnerable cookies: {xss_stats['potentially_vulnerable_cookies']} "
              f"({xss_stats['potentially_vulnerable_cookies']/xss_stats['total_cookies_analyzed']*100:.1f}% of total)")
        
        if xss_stats['vulnerable_domains']:
            print("\nVulnerable domains:")
            for domain, data in xss_stats['vulnerable_domains'].items():
                print(f"  {domain}: {data['count']} potentially vulnerable cookies")
                for cookie in data['cookies'][:3]:  # Show only first 3 cookies per domain
                    print(f"    - {cookie['name']} (HttpOnly: {cookie['httponly']}, Secure: {cookie['secure']})")
                if len(data['cookies']) > 3:
                    print(f"    ... and {len(data['cookies']) - 3} more")
    
    print()    
    # Cookie age statistics
    print("\n--- Cookie Age Statistics ---")
    print(f"Session cookies: {stats['session_cookies']} ({stats['session_cookies']/stats['total_cookies']*100:.1f}% of total)")
    print(f"Persistent cookies: {stats['persistent_cookies']} ({stats['persistent_cookies']/stats['total_cookies']*100:.1f}% of total)")
    
    if stats['persistent_cookies'] > 0:
        print(f"Average age of persistent cookies: {stats['avg_cookie_age_days']:.1f} days")
        print(f"Maximum age of persistent cookies: {stats['max_cookie_age_days']:.1f} days")
        
        print("\nCookie age categories:")
        categories = stats['cookie_age_categories']
        for category, count in categories.items():
            if count > 0:
                percentage = (count / stats['total_cookies']) * 100
                print(f"  {category.capitalize()}: {count} ({percentage:.1f}% of total)")
        
        # Print age distribution histogram if we have enough data
        if len(stats['cookie_age_distribution']) > 1:
            print("\nCookie Age Distribution (days):")
            try:
                # Create ASCII histogram
                distribution = stats['cookie_age_distribution']
                max_count = max(distribution.values())
                scale = min(40, max_count)  # Scale to fit terminal width
                
                # Group by ranges for better display if we have many different ages
                if len(distribution) > 10:
                    # Create age ranges
                    ranges = [(0, 1), (1, 7), (7, 30), (30, 90), (90, 180), (180, 365), (365, float('inf'))]
                    range_labels = ["<1 day", "1-7 days", "7-30 days", "1-3 months", "3-6 months", "6-12 months", ">1 year"]
                    range_counts = [0] * len(ranges)
                    
                    for age, count in distribution.items():
                        for i, (min_age, max_age) in enumerate(ranges):
                            if min_age <= age < max_age:
                                range_counts[i] += count
                                break
                    
                    # Print histogram
                    for i, label in enumerate(range_labels):
                        count = range_counts[i]
                        if count > 0:
                            bar_length = int((count / max_count) * scale)
                            bar = '█' * bar_length
                            print(f"  {label:10s} | {bar} {count}")
                else:
                    # Print individual days
                    for age, count in sorted(distribution.items()):
                        bar_length = int((count / max_count) * scale)
                        bar = '█' * bar_length
                        print(f"  {age:10d} | {bar} {count}")
            except Exception as e:
                # Fall back to simple text
                print(f"Could not create ASCII histogram: {e}")
                for age, count in sorted(stats['cookie_age_distribution'].items()):
                    print(f"  {age} days: {count} cookies")
        
        print("\nTop 10 most common cookie names:")
        for name, count in stats['common_cookie_names'].items():
            print(f"  {name}: {count}")
    else:
        print("No cookies found")
    
    # Web Storage statistics
    total_storage = stats['total_localStorage'] + stats['total_sessionStorage']
    if total_storage > 0:
        print("\n--- Web Storage Statistics ---")
        print(f"Total localStorage items: {stats['total_localStorage']}")
        print(f"Total sessionStorage items: {stats['total_sessionStorage']}")
        
        print("\nTop 10 most common storage keys:")
        for key, count in stats['common_storage_keys'].items():
            print(f"  {key}: {count}")
    else:
        print("\nNo Web Storage items found")
    
    # Per-domain statistics
    print("\n--- Per-Domain Statistics ---")
    domain_table = []
    for domain in set(list(stats['cookies_per_domain'].keys()) + list(stats['storage_per_domain'].keys())):
        cookie_count = stats['cookies_per_domain'].get(domain, 0)
        storage_count = stats['storage_per_domain'].get(domain, 0)
        domain_table.append((domain, cookie_count, storage_count, cookie_count + storage_count))
    
    # Sort by total count
    domain_table.sort(key=lambda x: x[3], reverse=True)
    
    print(tabulate(domain_table, 
                  headers=["Domain", "Cookies", "Storage Items", "Total Items"], 
                  tablefmt="grid"))


def main():
    """Main function to analyze cookie files."""
    parser = argparse.ArgumentParser(description='Analyze cookie files')
    parser.add_argument('--cookies-dir', default='cookies', help='Directory containing cookie files')
    parser.add_argument('--charts', action='store_true', help='Generate charts')
    parser.add_argument('--charts-dir', default='charts', help='Directory to save charts')
    parser.add_argument('--export', help='Export cookies to CSV file')
    parser.add_argument('--xss-analysis', action='store_true', help='Perform XSS vulnerability analysis on cookie values')
    args = parser.parse_args()
    
    # Check if cookies directory exists
    cookies_dir = args.cookies_dir
    if not os.path.isabs(cookies_dir):
        cookies_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), cookies_dir)
    
    if not os.path.exists(cookies_dir):
        print(f"Error: Cookies directory '{cookies_dir}' does not exist.")
        return
    
    # Load and analyze cookies
    cookie_files = load_cookie_files(cookies_dir)
    stats = analyze_cookies(cookie_files)
    
    # Perform XSS analysis if requested
    if args.xss_analysis:
        print("Performing XSS vulnerability analysis...")
        xss_stats = analyze_xss_vulnerabilities(cookie_files)
        stats['xss_analysis'] = xss_stats
    
    # Print statistics
    print_stats(stats)
    
    # Generate charts if requested
    if args.charts:
        charts_dir = args.charts_dir
        if not os.path.isabs(charts_dir):
            charts_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), charts_dir)
        generate_charts(stats, charts_dir)
    
    # Export to CSV if requested
    if args.export:
        export_cookies_to_csv(cookie_files, args.export)


if __name__ == "__main__":
    from urllib.parse import urlparse
    main()
