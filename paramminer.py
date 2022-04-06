'''
An http parameter miner which guesses the parameters of an http request for 
ppossible web cache poisoning attacks.
'''


import re
from threading import Thread
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import sys
import random
import string
from colorama import Fore, Style
from colorama import init

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

init()


evil_headers = []

def header_parser_from_httpmessage(message):
    '''
    Parses the header of an http request.
    '''
    header_dict = {}
    message.replace('\r', '')
    message.replace('\\n','\n')
    for line in message.split('\n'):
        if ':' in line and '<' not in line and '>' not in line:
            key, value = line.split(':', 1)
            header_dict[key] = value.strip()
    print(Fore.BLUE + 'Successfully parsed the http message.' + Style.RESET_ALL)
    print(Fore.CYAN + 'Found '  + str(len(header_dict)) + ' header parameters.' + Style.RESET_ALL)
    return header_dict


def random_cache_buster():
    '''
    Generates a random cache buster.
    '''
    n = random.randint(1, 4)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


def wordlist_param_loader(wordlist):
    '''
    Loads the wordlist of parameters.
    '''
    try:
        with open(wordlist, 'r') as f:
            print(Fore.GREEN + 'Successfully loaded the wordlist.' + Style.RESET_ALL)
            return [line.strip() for line in f.readlines()]
    except FileNotFoundError as e:
        print(Fore.RED + 'Error: ' + str(e) + Style.RESET_ALL)
        sys.exit(1)


def get_headers_from_url(Url):
    '''
    Gets the http message from the Url.
    '''
    try:
        response = requests.get(Url)
        print(Fore.GREEN + 'Successfully retrieved the http message from the url.' + Style.RESET_ALL)
        print(Fore.GREEN + 'Headers Found are: ' + Style.RESET_ALL)
        headers = response.headers
        for key in headers.keys():
            print(Fore.CYAN + key + ': '+ Style.RESET_ALL, end="")
            print(Fore.YELLOW + headers[key] + Style.RESET_ALL)
        return response.headers
    except requests.exceptions.RequestException as e:
        print(Fore.RED + 'Error: ' + str(e) + Style.RESET_ALL)
        sys.exit(1)


def url_list_loader(Urllist):
    '''
    Loads the urls from a Urllist of crawled site.
    '''
    with open(Urllist, 'r') as f:
        return [line.strip() for line in f.readlines()]

def url_exists(Url):
    '''
    Checks if the Url exists.
    '''
    try:
        response = requests.get(Url, verify=False)
        if response.status_code < 400:
            print(Fore.GREEN + 'The url: ' + Style.RESET_ALL,end="")  
            print(Url, end="") 
            print(Fore.GREEN +' exists.' + Style.RESET_ALL)
            return True
        else:
            print(Fore.RED + 'The url: ' + Style.RESET_ALL + Url + Fore.RED + ' either failed to connect or does not exist' + Style.RESET_ALL)
            print(Fore.RED + 'The status code is: ' + Style.RESET_ALL + str(response.status_code))
            print(Fore.RED + 'Body: ' + Style.RESET_ALL + str(response.text) + Style.RESET_ALL)
            return False
    except requests.exceptions.RequestException as e:
        print(Fore.RED + 'The url: ' + Style.RESET_ALL + Url + Fore.RED + ' does not exist' + Style.RESET_ALL)
        print(Fore.RED + 'Error: ' + str(e) + Style.RESET_ALL)
        return False



def basic_poisoning_using_x_forwarded_host(url, wordlist):
    cachebuster = random_cache_buster()
    cachebusterparam = random.randint(1,2000)
    regex = re.compile("(?<=://)[^/\n]*")

    forwarded_host_input = regex.search(url).group()
    
    url_new = url + '?' + cachebuster + '=' + str(cachebusterparam)
    primary = requests.get(url_new, verify=False)

    if "x-forwarded-host" in primary.headers.keys():
        default_forwarded_host = primary.headers["x-forwarded-host"]
        if default_forwarded_host == forwarded_host_input:
            forwarded_host_input = cachebuster + forwarded_host_input

    msg = requests.get(url_new, verify=False, 
                    headers={'X-forwarded-host': forwarded_host_input}, allow_redirects=False)

    if msg.status_code < 300:
        #find changed values due to forwarding
        if forwarded_host_input in msg.text or msg.text != primary.text or forwarded_host_input in msg.headers.values():
            print(Fore.YELLOW + "[ALERT] X-Forwarded-Host header on url: " + url_new + " maybe vulnerable to cache poisoning !!" 
                    + Style.RESET_ALL)
        else:
            print(Fore.GREEN + "[INFO] X-Forwarded-Host header on url: " + url_new + " is not vulnerable to cache poisoning." 
                    + Style.RESET_ALL)

    if msg.status_code < 400:
        # queue new headers
        for word in wordlist:
            cachebuster = random_cache_buster()
            cachebusterparam = str(random.randint(1,2000))
            url_new = url + '?' + cachebuster + '=' + str(cachebusterparam)
            
            if ':' in word:
                word, param = word.split(':')
            else:
                param = cachebuster + cachebusterparam    
            print(Fore.CYAN + "[*] Using header: " + word + Style.RESET_ALL)

            new_msg = requests.get(url_new, verify=False,
                            headers={'X-forwarded-host': forwarded_host_input, 
                                        word: param}, 
                            allow_redirects=False)

            print(Fore.LIGHTCYAN_EX + "[INFO] Status code: " + Style.RESET_ALL + Fore.LIGHTBLUE_EX + str(new_msg.status_code) + Style.RESET_ALL)
            
            if new_msg.status_code < 400:
                if forwarded_host_input in new_msg.text or new_msg.text != msg.text or forwarded_host_input in "".join(new_msg.headers.values()):
                    print(Fore.RED +"[ALERT] '"+ word + "' header on url: " + url_new + " maybe vulnerable to cache poisoning !!" 
                            + Style.RESET_ALL)
                    for key in new_msg.headers.keys():
                        if forwarded_host_input in new_msg.headers[key]:
                            print(Fore.RED + "[ALERT] X-forwarded-host param value found in '"+ key + "' header on url: " + url_new
                                    + Style.RESET_ALL)
                            print(Fore.RED + "[ALERT] "+key+ " : " + Style.RESET_ALL + Fore.LIGHTBLUE_EX + forwarded_host_input + Style.RESET_ALL)
                    evil_headers.append(word)
                else:
                    print(Fore.GREEN +"[INFO] '"+ word+ "' header on url: " + url_new + " is not vulnerable to cache poisoning." 
                            + Style.RESET_ALL)



# This is basic poisoning using X-Forwarded-Host header
# This is not a good way to do it, but it is a good example of how to use the X-Forwarded-Host header
# can be used for cache poisoning attacks.
def basic_poisoning_with_x_forwarded_scheme(url):
    cachebuster = random_cache_buster()
    cachebusterparam = random.randint(1,2000)
    forwarded_scheme_input = "nohttps"

    url_new = url + '?' + cachebuster + '=' + str(cachebusterparam)

    primary = requests.get(url, verify=False)
    print(Fore.LIGHTCYAN_EX + "[INFO] Status code: " + Style.RESET_ALL + Fore.LIGHTBLUE_EX + str(primary.status_code) + Style.RESET_ALL)
    
    msg = requests.get(url_new, verify=False,
                    headers={'X-forwarded-Scheme': forwarded_scheme_input}, allow_redirects=False)
    print(Fore.LIGHTCYAN_EX + "[INFO] Status code after 'X-Forward-Scheme' header addition: " + Style.RESET_ALL + Fore.LIGHTBLUE_EX + 
            str(msg.status_code) + Style.RESET_ALL)

    if msg.status_code != primary.status_code:
        print(Fore.YELLOW + "[INFO] X-Forwarded-Scheme header on url: " + url_new + " maybe vulnerable to cache poisoning !!" 
                + Style.RESET_ALL)
        
        #try further with X-forwarded-host
        forwarded_host_input = "example.com"
        print(Fore.LIGHTCYAN_EX + "[INFO] Using X-Forwarded-Host header to confirm: " + forwarded_host_input + Style.RESET_ALL)
        msg_new = requests.get(url_new, verify=False,
                        headers={'X-forwarded-scheme': forwarded_scheme_input,
                                    'X-forwarded-host': forwarded_host_input},
                        allow_redirects=False)

        if msg_new.headers.keys() != msg.headers.keys():
            print(Fore.RED + "[ALERT] X-Forwarded-Host value: " + Style.RESET_ALL + msg.headers['X-forwarded-host'])
            print(Fore.RED + "[ALERT] X-Forwarded-Scheme header on url: " + url_new + " is vulnerable to cache poisoning !!" 
                    + Style.RESET_ALL)

        elif "location" in msg_new.headers.keys():
            print(Fore.RED + "[ALERT] X-Forwarded-Scheme header on url: " + url_new + " is vulnerable to cache poisoning !!" 
                    + Style.RESET_ALL)
            print(Fore.RED + "[ALERT] Location header (result of using 'X-Forwarded-Host' header): " + Style.RESET_ALL + msg_new.headers['location'])
            




def guess_params(Url, Wordlist, numthreads):
    '''
    Guesses the unkeyed headers in the HttMessage from the wordlist provided.  
    '''
    #Maybe this is not required but anyways
    #basic_poisoning_with_x_forwarded_scheme(Url)
    
    #realgame starts here
    Thread_List = []
    k = 0
    block = int(len(Wordlist)/numthreads)
    for i in range(numthreads):
        if i == numthreads-1:
            worker = Thread(target=basic_poisoning_using_x_forwarded_host, args=(Url, Wordlist[k:]))
        else:
            worker = Thread(target=basic_poisoning_using_x_forwarded_host, args=(Url, Wordlist[k:k+block]))
        Thread_List.append(worker)
        k += block

    for worker in Thread_List:
        worker.start()
    for worker in Thread_List:
        worker.join()

    print(Fore.LIGHTBLUE_EX + "[INFO] Poisoning with X-Forwarded-Host header completed." + Style.RESET_ALL)
    print(Fore.RED + "[ALERT] Vulnerable headers found are: " + Style.RESET_ALL)
    for i in evil_headers:
        print(Fore.RED + "[*****] " + i + Style.RESET_ALL)
