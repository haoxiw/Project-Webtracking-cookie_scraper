import json
import os
import time
import random
import scrapy
from scrapy.http import Request
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.common.exceptions import WebDriverException, TimeoutException, NoSuchElementException, ElementNotInteractableException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.keys import Keys
from webdriver_manager.chrome import ChromeDriverManager
from datetime import datetime, timedelta
import tldextract  # For better domain parsing

class CookieSpider(scrapy.Spider):
    name = "cookie_spider"
    
    def __init__(self, urls=None, headless=False, wait_time=5, interact=True, no_selenium=False, *args, **kwargs):
        super(CookieSpider, self).__init__(*args, **kwargs)
        # Create cookies directory if it doesn't exist
        self.cookies_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'cookies')
        os.makedirs(self.cookies_dir, exist_ok=True)
        
        # Parse URLs from command line or use default
        self.start_urls = []
        if urls:
            for url in urls.split(','):
                url = url.strip()
                if not url.startswith(('http://', 'https://')):
                    url = 'https://' + url
                self.start_urls.append(url)
        else:
            # Default URLs to scrape
            self.start_urls = [
                'https://www.google.com',
                'https://www.amazon.com',
                'https://www.facebook.com',
                'https://www.x.com',
                'https://www.reddit.com',
                'https://chatgpt.com',
                'https://www.youtube.com',
                'https://www.deepseek.com',
                'https://grok.com',
            ]
        
        # Selenium setup
        self.headless = headless
        self.wait_time = int(wait_time)  # Time to wait for JavaScript execution
        self.driver = None
        self.interact = interact  # Whether to interact with forms and inputs
        self.no_selenium = no_selenium
        
        # Sample data for form filling
        self.sample_data = {
            'text': ['example', 'test123', 'user@example.com', 'John Doe', 'sample text'],
            'email': ['user@example.com', 'test@test.com', 'john.doe@example.org'],
            'password': ['Password123!', 'SecurePass2023', 'TestPassword'],
            'search': ['news', 'weather', 'products', 'information', 'help'],
            'number': ['1234567890', '555-123-4567', '12345'],
            'date': ['2023-01-01', '01/01/2023', '2023-05-15'],
        }
        
        self.logger.info(f"Spider will scrape the following URLs: {self.start_urls}")
    
    def setup_selenium(self):
        """Set up the Selenium WebDriver"""
        try:
            chrome_options = Options()
            if self.headless:
                chrome_options.add_argument("--headless")
                self.logger.info("Running in headless mode")
            else:
                self.logger.info("Running with visible browser window")
            
            # Add additional options for better performance and stability
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--window-size=1920,1080")
            
            # Set user agent
            chrome_options.add_argument("user-agent=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36")
            
            # Enable cookies
            chrome_options.add_argument("--enable-cookies")
            # Enable third-party cookies (disable privacy restrictions)
            chrome_options.add_argument("--disable-features=BlockThirdPartyCookies")
            
            # Optional: Disable same-site cookie restrictions
            chrome_options.add_argument("--disable-features=SameSiteByDefaultCookies")
            
            # Initialize the WebDriver
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            
            # Set page load timeout
            driver.set_page_load_timeout(30)
            
            return driver
        except Exception as e:
            self.logger.error(f"Error setting up Selenium: {e}")
            return None
    
    def start_requests(self):
        # Initialize Selenium WebDriver
        if not self.no_selenium:
            self.driver = self.setup_selenium()
        if not self.driver:
            self.logger.error("Failed to initialize Selenium WebDriver. Falling back to regular Scrapy requests.")
            for url in self.start_urls:
                # Include error status codes in the allowed list and allow redirects
                yield Request(
                    url=url, 
                    callback=self.parse_without_selenium, 
                    meta={
                        'dont_redirect': False,  # Allow redirects
                        'handle_httpstatus_list': [200, 301, 302, 400, 403, 404, 500]
                    },
                    errback=self.handle_error
                )
        else:
            # Use Selenium for all URLs
            for url in self.start_urls:
                yield Request(
                    url=url, 
                    callback=self.parse_with_selenium, 
                    meta={
                        'selenium': True,
                        'dont_redirect': False,  # Allow redirects
                        'handle_httpstatus_list': [200, 301, 302, 400, 403, 404, 500]
                    },
                    errback=self.handle_error
                )
    
    def closed(self, reason):
        # Clean up Selenium WebDriver when spider closes
        if self.driver:
            self.logger.info("Closing Selenium WebDriver")
            try:
                self.driver.quit()
            except Exception as e:
                self.logger.error(f"Error closing WebDriver: {e}")
    
    def handle_error(self, failure):
        """Handle request errors"""
        request = failure.request
        url = request.url
        domain = urlparse(url).netloc
        
        self.logger.error(f"Error processing {url}: {repr(failure)}")
        
        # Try to use Selenium as a fallback for failed requests
        if self.driver and 'selenium' not in request.meta:
            self.logger.info(f"Attempting to use Selenium as fallback for {url}")
            try:
                # Navigate directly with Selenium
                self.driver.get(url)
                time.sleep(self.wait_time)
                
                # Process with selenium method directly
                return self.process_selenium_page(url, domain)
            except Exception as e:
                self.logger.error(f"Selenium fallback also failed for {url}: {e}")
        
        # Return empty result if all attempts fail
        return {
            'domain': domain,
            'url': url,
            'error': str(failure),
            'cookies_count': 0,
            'file_saved': None
        }
    
    def parse_with_selenium(self, response):
        """Parse using Selenium to capture JavaScript-set cookies"""
        url = response.url
        domain = urlparse(url).netloc
        
        # Handle error status codes
        if response.status in [400, 403, 404, 500]:
            self.logger.warning(f"Received {response.status} status code for {url}, but continuing with Selenium")
        
        self.logger.info(f"Processing {url} with Selenium")
        
        try:
            return self.process_selenium_page(url, domain)
        except WebDriverException as e:
            self.logger.error(f"Selenium error for {url}: {e}")
            # Fall back to non-Selenium parsing
            return Request(url=url, callback=self.parse_without_selenium, meta={'dont_redirect': False, 'handle_httpstatus_list': [200, 301, 302, 400, 403, 404, 500]})
        except Exception as e:
            self.logger.error(f"Unexpected error for {url}: {e}")
            return {
                'domain': domain,
                'url': url,
                'error': str(e),
                'cookies_count': 0,
                'file_saved': None
            }
            
    def is_third_party_cookie(self, cookie_domain, page_domain):
        """Determine if a cookie is from a third-party domain
        
        Args:
            cookie_domain (str): The domain of the cookie
            page_domain (str): The domain of the page being visited
            
        Returns:
            bool: True if the cookie is from a third-party domain, False otherwise
            str: The extracted domain information for both domains
        """
        if not cookie_domain:
            return False, "No cookie domain"
            
        # Remove leading dot if present
        if cookie_domain.startswith('.'):
            cookie_domain = cookie_domain[1:]
            
        # Extract domains using tldextract for more accurate comparison
        try:
            page_extract = tldextract.extract(page_domain)
            cookie_extract = tldextract.extract(cookie_domain)
            
            page_registered_domain = f"{page_extract.domain}.{page_extract.suffix}"
            cookie_registered_domain = f"{cookie_extract.domain}.{cookie_extract.suffix}"
            
            # Check if domains match at the registered domain level
            is_third_party = page_registered_domain != cookie_registered_domain
            
            domain_info = f"Page: {page_registered_domain}, Cookie: {cookie_registered_domain}"
            
            return is_third_party, domain_info
        except Exception as e:
            self.logger.error(f"Error comparing domains: {e}")
            return False, f"Error: {e}"
    
    def identify_tracking_purpose(self, cookie_name, cookie_value):
        """Attempt to identify the tracking purpose of a cookie based on its name and value
        
        Args:
            cookie_name (str): The name of the cookie
            cookie_value (str): The value of the cookie
            
        Returns:
            str: The likely purpose of the cookie
        """
        # Common tracking cookie names and keywords
        analytics_keywords = ['analytics', 'ga', '_ga', 'gtm', 'pixel', 'stats', 'track', 'visit']
        ad_keywords = ['ad', 'ads', 'advert', 'campaign', 'promo', 'promotion', 'marketing']
        session_keywords = ['session', 'sid', 'user', 'auth', 'login', 'account']
        preference_keywords = ['pref', 'setting', 'consent', 'accept', 'agree']
        functional_keywords = ['func', 'feature', 'ui', 'display', 'layout', 'theme']
        
        name_lower = cookie_name.lower()
        
        # Check for common tracking services
        if any(kw in name_lower for kw in analytics_keywords):
            return 'Analytics'
        elif any(kw in name_lower for kw in ad_keywords):
            return 'Advertising'
        elif any(kw in name_lower for kw in session_keywords):
            return 'Session/Authentication'
        elif any(kw in name_lower for kw in preference_keywords):
            return 'Preferences/Consent'
        elif any(kw in name_lower for kw in functional_keywords):
            return 'Functional'
        
        # Check for specific known trackers
        if name_lower in ['_fbp', 'fr']:
            return 'Facebook Tracking'
        elif name_lower in ['_gid', '_ga', '_gat']:
            return 'Google Analytics'
        elif name_lower in ['__utma', '__utmb', '__utmc', '__utmz']:
            return 'Google Analytics (Legacy)'
        elif name_lower in ['_hjid', '_hjSessionUser']:
            return 'Hotjar Analytics'
        elif name_lower in ['_pin_unauth', '_pinterest_sess']:
            return 'Pinterest Tracking'
        elif name_lower in ['_twitter_sess', 'ct0']:
            return 'Twitter Tracking'
        
        # Default if no match
        return 'Unknown'
    
    def process_selenium_page(self, url, domain):
        """Process a page with Selenium to extract cookies and storage data"""
        try:
            # Navigate to the URL
            self.driver.get(url)
            
            # Wait for JavaScript to execute and set initial cookies
            self.logger.info(f"Waiting {self.wait_time} seconds for JavaScript execution")
            time.sleep(self.wait_time)
            
            # Get initial cookies from Selenium
            initial_cookies = self.driver.get_cookies()
            self.logger.info(f"Found {len(initial_cookies)} initial cookies with Selenium for {domain}")
            
            # Interact with the page if enabled
            if self.interact:
                self.interact_with_page(domain)
            
            # Get all cookies from Selenium after interaction
            selenium_cookies = self.driver.get_cookies()
            self.logger.info(f"Found {len(selenium_cookies)} cookies after interaction for {domain}")
            
            # Extract the main domain for third-party cookie detection
            parsed_url = urlparse(url)
            main_domain = parsed_url.netloc
            
            # Process cookies
            cookie_data = []
            third_party_cookies = []
            current_time = time.time()
            
            for cookie in selenium_cookies:
                # Get expiry timestamp
                expiry = cookie.get('expiry')
                
                # Calculate cookie age in seconds, days, and human-readable format
                age_info = self.calculate_cookie_age(expiry, current_time)
                
                # Check if this is a third-party cookie
                cookie_domain = cookie.get('domain', '')
                is_third_party, domain_info = self.is_third_party_cookie(cookie_domain, main_domain)
                
                # Identify tracking purpose
                tracking_purpose = self.identify_tracking_purpose(cookie.get('name', ''), cookie.get('value', ''))
                
                cookie_info = {
                    'name': cookie.get('name', ''),
                    'value': cookie.get('value', ''),
                    'domain': cookie_domain,
                    'path': cookie.get('path', '/'),
                    'expires': cookie.get('expiry', ''),
                    'secure': cookie.get('secure', False),
                    'httponly': cookie.get('httpOnly', False),
                    'samesite': cookie.get('sameSite', ''),
                    'age': age_info,
                    'is_third_party': is_third_party,
                    'domain_info': domain_info,
                    'tracking_purpose': tracking_purpose
                }
                
                cookie_data.append(cookie_info)
                
                # Collect third-party cookies separately for reporting
                if is_third_party:
                    third_party_cookies.append(cookie_info)
                    self.logger.info(f"Third-party cookie detected: {cookie.get('name', '')} from {cookie_domain} (Purpose: {tracking_purpose})")
                
            # Get localStorage data
            try:
                local_storage = self.driver.execute_script("""
                    var items = {};
                    for (var i = 0, len = localStorage.length; i < len; i++) {
                        var key = localStorage.key(i);
                        items[key] = localStorage.getItem(key);
                    }
                    return items;
                """)
                self.logger.info(f"Found {len(local_storage)} localStorage items for {domain}")
            except Exception as e:
                self.logger.error(f"Error getting localStorage: {e}")
                local_storage = {}
                
            # Get sessionStorage data
            try:
                session_storage = self.driver.execute_script("""
                    var items = {};
                    for (var i = 0, len = sessionStorage.length; i < len; i++) {
                        var key = sessionStorage.key(i);
                        items[key] = sessionStorage.getItem(key);
                    }
                    return items;
                """)
                self.logger.info(f"Found {len(session_storage)} sessionStorage items for {domain}")
            except Exception as e:
                self.logger.error(f"Error getting sessionStorage: {e}")
                session_storage = {}
            
            # Save cookies and storage data to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{domain.replace('.', '_')}_{timestamp}.json"
            filepath = os.path.join(self.cookies_dir, filename)
            
            # Prepare data to save
            data_to_save = {
                'url': url,
                'timestamp': datetime.now().isoformat(),
                'cookies': cookie_data,
                'localStorage': local_storage,
                'sessionStorage': session_storage,
                'source': 'selenium',
                'third_party_cookies': third_party_cookies,
                'third_party_count': len(third_party_cookies)
            }
            
            with open(filepath, 'w') as f:
                json.dump(data_to_save, f, indent=4)
            
            # Calculate total items for reporting
            total_items = len(cookie_data) + len(local_storage) + len(session_storage)
            
            self.logger.info(f"Saved data to {filepath}")
            return {
                'domain': domain,
                'url': url,
                'cookies_count': len(cookie_data),
                'localStorage_count': len(local_storage),
                'sessionStorage_count': len(session_storage),
                'total_items': total_items,
                'file_saved': filepath,
                'source': 'selenium'
            }
                
        except WebDriverException as e:
            self.logger.error(f"Selenium error for {url}: {e}")
            # Fall back to non-Selenium parsing
            return Request(url=url, callback=self.parse_without_selenium, meta={'dont_redirect': True, 'handle_httpstatus_list': [302, 301]})
        except Exception as e:
            self.logger.error(f"Unexpected error for {url}: {e}")
            return {
                'domain': domain,
                'url': url,
                'error': str(e),
                'cookies_count': 0,
                'file_saved': None
            }
    
    def interact_with_page(self, domain):
        """Find and interact with forms, inputs, and buttons on the page"""
        self.logger.info(f"Attempting to interact with elements on {domain}")
        
        try:
            # 1. Try to handle cookie consent dialogs first
            self.handle_cookie_consent()
            
            # 2. Find and interact with search forms
            if self.interact_with_search_forms():
                self.logger.info(f"Successfully interacted with search form on {domain}")
            
            # 3. Find and interact with login/signup forms
            elif self.interact_with_login_forms():
                self.logger.info(f"Successfully interacted with login/signup form on {domain}")
            
            # 4. Find and interact with general forms
            elif self.interact_with_general_forms():
                self.logger.info(f"Successfully interacted with general form on {domain}")
            
            # 5. Click on buttons/links to navigate deeper (passing domain to ensure same-domain clicks)
            elif self.click_interactive_elements(domain):
                self.logger.info(f"Successfully clicked on interactive elements on {domain}")
            
            else:
                self.logger.info(f"No interactive elements found or interaction failed on {domain}")
            
            # Wait for any resulting page changes and cookie updates
            time.sleep(self.wait_time)
            
        except Exception as e:
            self.logger.error(f"Error during page interaction on {domain}: {e}")
    
    def handle_cookie_consent(self):
        """Attempt to accept cookie consent dialogs"""
        # Common cookie consent button selectors
        consent_selectors = [
            "//button[contains(., 'Accept') or contains(., 'accept') or contains(., 'Allow') or contains(., 'allow')]" ,
            "//button[contains(., 'Agree') or contains(., 'agree') or contains(., 'Consent') or contains(., 'consent')]",
            "//a[contains(., 'Accept') or contains(., 'accept') or contains(., 'Allow') or contains(., 'allow')]",
            "//*[contains(@id, 'cookie') or contains(@class, 'cookie')]//button",
            "//*[contains(@id, 'consent') or contains(@class, 'consent')]//button",
            "//button[contains(@id, 'accept') or contains(@id, 'agree')]"
        ]
        
        for selector in consent_selectors:
            try:
                buttons = self.driver.find_elements(By.XPATH, selector)
                for button in buttons:
                    if button.is_displayed() and button.is_enabled():
                        self.logger.info(f"Clicking cookie consent button: {button.text or 'unnamed button'}")
                        button.click()
                        time.sleep(1)  # Brief pause after clicking
                        return True
            except Exception as e:
                self.logger.debug(f"Error with cookie consent selector {selector}: {e}")
        
        return False
    
    def interact_with_search_forms(self):
        """Find and interact with search forms"""
        # Try to find search inputs
        search_selectors = [
            "//input[@type='search']",
            "//input[contains(@name, 'search') or contains(@id, 'search') or contains(@class, 'search')]",
            "//form[contains(@action, 'search')]//input[@type='text']"
        ]
        
        for selector in search_selectors:
            try:
                search_inputs = self.driver.find_elements(By.XPATH, selector)
                for search_input in search_inputs:
                    if search_input.is_displayed() and search_input.is_enabled():
                        # Clear any existing text
                        search_input.clear()
                        
                        # Enter search query
                        search_term = random.choice(self.sample_data['search'])
                        self.logger.info(f"Entering search term '{search_term}' in search input")
                        search_input.send_keys(search_term)
                        
                        # Try to submit the form
                        try:
                            # First try pressing Enter
                            search_input.send_keys(Keys.ENTER)
                            time.sleep(2)  # Wait for results
                            
                            # If that didn't work, look for a submit button
                            form = search_input.find_element(By.XPATH, "./ancestor::form")
                            submit_button = form.find_element(By.XPATH, ".//button[@type='submit'] | .//input[@type='submit']")
                            submit_button.click()
                            
                        except Exception as e:
                            self.logger.debug(f"Error submitting search form: {e}")
                        
                        return True
            except Exception as e:
                self.logger.debug(f"Error with search selector {selector}: {e}")
        
        return False
    
    def interact_with_login_forms(self):
        """Find and interact with login/signup forms"""
        # Try to find login/signup forms
        login_selectors = [
            "//form[contains(@action, 'login') or contains(@action, 'signin') or contains(@id, 'login') or contains(@class, 'login')]",
            "//form[contains(@action, 'register') or contains(@action, 'signup') or contains(@id, 'register') or contains(@class, 'register')]"
        ]
        
        for selector in login_selectors:
            try:
                forms = self.driver.find_elements(By.XPATH, selector)
                for form in forms:
                    if not form.is_displayed():
                        continue
                    
                    # Find input fields in the form
                    inputs = form.find_elements(By.XPATH, ".//input[@type='text' or @type='email' or @type='password']")
                    
                    if len(inputs) >= 1:
                        filled_inputs = 0
                        
                        for input_field in inputs:
                            if not (input_field.is_displayed() and input_field.is_enabled()):
                                continue
                                
                            input_type = input_field.get_attribute('type')
                            input_name = input_field.get_attribute('name') or ''
                            input_id = input_field.get_attribute('id') or ''
                            input_placeholder = input_field.get_attribute('placeholder') or ''
                            
                            # Clear any existing text
                            input_field.clear()
                            
                            # Determine what kind of data to enter
                            if input_type == 'email' or 'email' in input_name.lower() or 'email' in input_id.lower() or 'email' in input_placeholder.lower():
                                value = random.choice(self.sample_data['email'])
                            elif input_type == 'password' or 'password' in input_name.lower() or 'password' in input_id.lower() or 'password' in input_placeholder.lower():
                                value = random.choice(self.sample_data['password'])
                            else:
                                value = random.choice(self.sample_data['text'])
                            
                            self.logger.info(f"Entering '{value}' in {input_type} field")
                            input_field.send_keys(value)
                            filled_inputs += 1
                        
                        if filled_inputs > 0:
                            # Don't actually submit login forms to avoid account lockouts
                            # Just fill in the fields to trigger any JavaScript events
                            self.logger.info(f"Filled {filled_inputs} fields in login/signup form but not submitting")
                            return True
            except Exception as e:
                self.logger.debug(f"Error with login form selector {selector}: {e}")
        
        return False
    
    def interact_with_general_forms(self):
        """Find and interact with general forms"""
        try:
            # Find all forms that are not search or login forms
            forms = self.driver.find_elements(By.XPATH, "//form")
            
            for form in forms:
                if not form.is_displayed():
                    continue
                
                # Skip search and login forms as we've already tried those
                form_id = form.get_attribute('id') or ''
                form_class = form.get_attribute('class') or ''
                form_action = form.get_attribute('action') or ''
                
                if ('search' in form_id.lower() or 'search' in form_class.lower() or 'search' in form_action.lower() or
                    'login' in form_id.lower() or 'login' in form_class.lower() or 'login' in form_action.lower() or
                    'signin' in form_id.lower() or 'signin' in form_class.lower() or 'signin' in form_action.lower()):
                    continue
                
                # Find input fields in the form
                inputs = form.find_elements(By.XPATH, ".//input[@type='text' or @type='email' or @type='tel' or @type='number' or @type='date']")
                textareas = form.find_elements(By.XPATH, ".//textarea")
                selects = form.find_elements(By.XPATH, ".//select")
                
                all_inputs = inputs + textareas
                filled_inputs = 0
                
                # Fill in text inputs and textareas
                for input_field in all_inputs:
                    if not (input_field.is_displayed() and input_field.is_enabled()):
                        continue
                        
                    input_type = input_field.get_attribute('type') or ''
                    input_name = input_field.get_attribute('name') or ''
                    input_id = input_field.get_attribute('id') or ''
                    
                    # Clear any existing text
                    input_field.clear()
                    
                    # Determine what kind of data to enter
                    if input_type == 'email' or 'email' in input_name.lower() or 'email' in input_id.lower():
                        value = random.choice(self.sample_data['email'])
                    elif input_type == 'number' or 'number' in input_name.lower() or 'number' in input_id.lower():
                        value = random.choice(self.sample_data['number'])
                    elif input_type == 'date' or 'date' in input_name.lower() or 'date' in input_id.lower():
                        value = random.choice(self.sample_data['date'])
                    else:
                        value = random.choice(self.sample_data['text'])
                    
                    self.logger.info(f"Entering '{value}' in form field")
                    input_field.send_keys(value)
                    filled_inputs += 1
                
                # Handle select dropdowns
                for select in selects:
                    if not (select.is_displayed() and select.is_enabled()):
                        continue
                    
                    try:
                        # Find all options in the select
                        options = select.find_elements(By.XPATH, ".//option")
                        
                        # Skip the first option (usually a placeholder) if there are multiple options
                        if len(options) > 1:
                            option_to_select = random.choice(options[1:])
                            option_to_select.click()
                            filled_inputs += 1
                    except Exception as e:
                        self.logger.debug(f"Error interacting with select element: {e}")
                
                # If we filled in any inputs, try to find a submit button but don't actually submit
                if filled_inputs > 0:
                    self.logger.info(f"Filled {filled_inputs} fields in general form")
                    return True
            
        except Exception as e:
            self.logger.error(f"Error interacting with general forms: {e}")
        
        return False
    
    def calculate_cookie_age(self, expiry_timestamp, current_time):
        """Calculate the age of a cookie based on its expiration time"""
        age_info = {
            'seconds': None,
            'days': None,
            'readable': 'Session cookie (expires when browser closes)',
            'is_session': True
        }
        
        # If expiry is None or empty, it's a session cookie
        if not expiry_timestamp:
            return age_info
        
        try:
            # Convert to float if it's not already
            expiry_timestamp = float(expiry_timestamp)
            
            # Calculate age in seconds
            age_seconds = expiry_timestamp - current_time
            
            # If expiry is in the past, mark as expired
            if age_seconds <= 0:
                return {
                    'seconds': age_seconds,
                    'days': age_seconds / 86400,  # Convert to days
                    'readable': 'Expired',
                    'is_session': False
                }
            
            # Calculate age in days
            age_days = age_seconds / 86400
            
            # Create human-readable format
            if age_days < 1:
                hours = age_seconds / 3600
                if hours < 1:
                    minutes = age_seconds / 60
                    readable = f"{int(minutes)} minute{'s' if minutes != 1 else ''}"
                else:
                    readable = f"{int(hours)} hour{'s' if hours != 1 else ''}"
            elif age_days < 30:
                readable = f"{int(age_days)} day{'s' if age_days != 1 else ''}"
            elif age_days < 365:
                months = age_days / 30
                readable = f"{int(months)} month{'s' if months != 1 else ''}"
            else:
                years = age_days / 365
                readable = f"{int(years)} year{'s' if years != 1 else ''}"
            
            return {
                'seconds': age_seconds,
                'days': age_days,
                'readable': readable,
                'is_session': False
            }
        except (ValueError, TypeError):
            # If conversion fails, assume it's a session cookie
            return age_info
    
    def click_interactive_elements(self, domain):
        """Click on buttons, links, or other interactive elements"""
        # Get the base domain for comparison
        base_domain = self.extract_base_domain(domain)
        self.logger.info(f"Looking for interactive elements on domain: {base_domain}")
        
        # Selectors for common interactive elements
        interactive_selectors = [
            # Links with href attributes (to check domain)
            "//a[@href and not(contains(@href, 'login') or contains(@href, 'signin'))]",
            # Buttons that aren't submit buttons
            "//button[not(contains(@type, 'submit'))][not(contains(., 'login') or contains(., 'Login') or contains(., 'sign'))]",
            # Divs with button role
            "//div[@role='button']",
            # Elements with button class
            "//*[contains(@class, 'button') and not(contains(@class, 'login') or contains(@class, 'signin'))]"
        ]
        
        # First try to find links that stay within the same domain
        try:
            # Find all links
            links = self.driver.find_elements(By.XPATH, "//a[@href]")
            same_domain_links = []
            
            for link in links:
                if not (link.is_displayed() and link.is_enabled()):
                    continue
                    
                href = link.get_attribute('href')
                if not href:
                    continue
                    
                # Check if the link is to the same domain
                try:
                    link_domain = urlparse(href).netloc
                    link_base_domain = self.extract_base_domain(link_domain)
                    
                    # Only include links to the same domain
                    if link_base_domain == base_domain:
                        same_domain_links.append(link)
                        self.logger.debug(f"Found same-domain link: {href}")
                except Exception as e:
                    self.logger.debug(f"Error parsing link URL: {e}")
            
            # If we found same-domain links, click on one randomly
            if same_domain_links:
                link_to_click = random.choice(same_domain_links)
                link_text = link_to_click.text or link_to_click.get_attribute('href') or 'unnamed link'
                self.logger.info(f"Clicking on same-domain link: {link_text}")
                link_to_click.click()
                time.sleep(2)  # Wait for page to load
                return True
            else:
                self.logger.info(f"No same-domain links found on {domain}")
        except Exception as e:
            self.logger.debug(f"Error finding same-domain links: {e}")
        
        # If no same-domain links were found or clicked, try other interactive elements
        for selector in interactive_selectors:
            try:
                elements = self.driver.find_elements(By.XPATH, selector)
                
                # Filter visible elements
                visible_elements = [e for e in elements if e.is_displayed() and e.is_enabled()]
                
                if visible_elements:
                    # Take a random element to click
                    element_to_click = random.choice(visible_elements)
                    element_text = element_to_click.text or element_to_click.get_attribute('id') or 'unnamed element'
                    
                    self.logger.info(f"Clicking on interactive element: {element_text}")
                    element_to_click.click()
                    time.sleep(2)  # Wait for any page changes
                    return True
            except Exception as e:
                self.logger.debug(f"Error with interactive element selector {selector}: {e}")
        
        return False
        
    def extract_base_domain(self, domain):
        """Extract the base domain (e.g., example.com from www.example.com)"""
        if not domain:
            return ""
            
        # Remove port if present
        if ':' in domain:
            domain = domain.split(':', 1)[0]
            
        parts = domain.split('.')
        
        # Handle special cases like co.uk, com.au
        if len(parts) > 2:
            if parts[-2] in ['co', 'com', 'org', 'net', 'edu', 'gov'] and parts[-1] in ['uk', 'au', 'nz', 'jp']:
                return '.'.join(parts[-3:])
        
        # Return the last two parts for normal domains (example.com)
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        
        return domain
    
    def parse_without_selenium(self, response):
        """Parse using regular Scrapy response (fallback method)"""
        # Extract domain name for file naming
        domain = urlparse(response.url).netloc
        
        # Log status code and check for redirects
        self.logger.info(f"Processing {response.url} with status code {response.status}")
        
        # Check if this was a redirect
        redirect_urls = response.request.meta.get('redirect_urls', [])
        if redirect_urls:
            original_url = redirect_urls[0]
            self.logger.info(f"Followed redirect from {original_url} to {response.url}")
            
            # Update domain if it changed due to redirect
            original_domain = urlparse(original_url).netloc
            if original_domain != domain:
                self.logger.info(f"Domain changed from {original_domain} to {domain} due to redirect")
        
        # Get cookies from response even if status code indicates error
        cookies = response.headers.getlist('Set-Cookie')
        
        # Process and save cookies
        if cookies:
            self.logger.info(f"Found {len(cookies)} cookies for {domain} without Selenium")
            
            cookie_data = []
            for cookie_str in cookies:
                try:
                    # Convert bytes to string
                    cookie_str = cookie_str.decode('utf-8')
                    
                    # Parse cookie string
                    parts = cookie_str.split(';')
                    main_part = parts[0].strip()
                    
                    if '=' in main_part:
                        name, value = main_part.split('=', 1)
                        
                        # Extract other cookie attributes
                        attributes = {}
                        for part in parts[1:]:
                            part = part.strip()
                            if '=' in part:
                                k, v = part.split('=', 1)
                                attributes[k.lower()] = v
                            else:
                                attributes[part.lower()] = True
                        
                        # Parse expires date if available
                        expires_str = attributes.get('expires', '')
                        expiry_timestamp = None
                        if expires_str:
                            try:
                                # Try to parse the expires date string to a timestamp
                                expires_date = datetime.strptime(expires_str, "%a, %d %b %Y %H:%M:%S %Z")
                                expiry_timestamp = expires_date.timestamp()
                            except (ValueError, TypeError):
                                try:
                                    # Try alternative format
                                    expires_date = datetime.strptime(expires_str, "%a, %d-%b-%Y %H:%M:%S %Z")
                                    expiry_timestamp = expires_date.timestamp()
                                except (ValueError, TypeError):
                                    # If parsing fails, leave as None
                                    pass
                        
                        # Calculate cookie age
                        age_info = self.calculate_cookie_age(expiry_timestamp, time.time())
                        
                        cookie_info = {
                            'name': name,
                            'value': value,
                            'domain': attributes.get('domain', domain),
                            'path': attributes.get('path', '/'),
                            'expires': attributes.get('expires', ''),
                            'secure': 'secure' in attributes,
                            'httponly': 'httponly' in attributes,
                            'samesite': attributes.get('samesite', ''),
                            'age': age_info
                        }
                        
                        cookie_data.append(cookie_info)
                    
                except Exception as e:
                    self.logger.error(f"Error parsing cookie: {e}")
            
            # Save cookies to file
            if cookie_data:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{domain.replace('.', '_')}_{timestamp}.json"
                filepath = os.path.join(self.cookies_dir, filename)
                
                with open(filepath, 'w') as f:
                    json.dump({
                        'url': response.url,
                        'timestamp': datetime.now().isoformat(),
                        'cookies': cookie_data,
                        'source': 'scrapy'
                    }, f, indent=4)
                
                self.logger.info(f"Saved cookies to {filepath}")
                return {
                    'domain': domain,
                    'url': response.url,
                    'cookies_count': len(cookie_data),
                    'file_saved': filepath,
                    'source': 'scrapy'
                }
        else:
            self.logger.info(f"No cookies found for {domain} without Selenium")
            return {
                'domain': domain,
                'url': response.url,
                'cookies_count': 0,
                'file_saved': None,
                'source': 'scrapy'
            }
