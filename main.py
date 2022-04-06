from paramminer import *
from threading import Thread

url = "https://ac8d1f221fe90d4ec0513250006f0094.web-security-academy.net/"

    
guess_params(url, wordlist_param_loader("headerwordlist.txt"),25)
