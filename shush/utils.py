import math
import string
from enum import Enum
from colorama import Fore

HEX_ALPHABET = string.hexdigits
BASE64_ALPHABET = string.ascii_letters + string.digits + "+/="


def banner():
    print('''
8""""8                         
8      e   e e   e eeeee e   e 
8eeeee 8   8 8   8 8   " 8   8 
    88 8eee8 8e  8 8eeee 8eee8 
e   88 88  8 88  8    88 88  8 
8eee88 88  8 88ee8 8ee88 88  8 

           Created by Security Dragon               
''')


class LOGLEVEL(Enum):
    INFO = 0,
    WARNING = 1,
    ERROR = 2,
    SUCCESS = 3


def log(level: LOGLEVEL, message: str):
    if level == LOGLEVEL.WARNING:
        prefix = Fore.YELLOW + "[~]"
    elif level == LOGLEVEL.ERROR:
        prefix = Fore.RED + "[x]"
    elif level == LOGLEVEL.SUCCESS:
        prefix = Fore.GREEN + "[+]"
    else:
        prefix = "[ ]"
    print(prefix + Fore.RESET + " " + message)


def info(message: str):
    log(LOGLEVEL.INFO, message)


def warning(message: str):
    log(LOGLEVEL.WARNING, message)


def error(message: str):
    log(LOGLEVEL.ERROR, message)


def success(message: str):
    log(LOGLEVEL.SUCCESS, message)


def mask_slack_token(token):
    """
    Preserve the token prefix (xoxp is personal token, xoxb is a bot, etc.).
    Mask all other characters except for the final 8 chars in the Slack token.
    This will help people debug their token permissions without logging full Slack
    tokens to the console / logs.
    """
    toks = token.split('-')
    return "{}-{}-{}".format(
        toks[0],
        '-'.join('*' * len(tok) for tok in toks[1:len(toks) - 1]),
        ('*' * (len(toks[len(toks) - 1]) - 8)) + toks[len(toks) - 1][-8:])


def dump_config(args: dict):
    info("Dumping running configuration:")
    max_keylen = max(map(len, args.keys()))
    for key in sorted(args.keys()):
        val = args[key]
        if key == "token":
            val = mask_slack_token(val)
        info("\t" + key.ljust(max_keylen) + "\t" + str(val))


def calc_entropy_shannon(str="", alphabet=None):
    # http://blog.dkbza.org/2007/05/scanning-data-for-entropy-anomalies.html
    if alphabet is None:
        alphabet = []
    entropy = 0
    for c in alphabet:
        p_c = float(str.count(c)) / len(str)
        if p_c > 0:
            entropy += (-p_c * math.log(p_c, 2))
    return entropy