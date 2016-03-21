#!/usr/bin/python
from __future__ import print_function
import python_sha3
import aes
import os
import sys
import json
import getpass
import binascii
import pbkdf2 as PBKDF2
from utils import decode_hex, encode_hex
import traceback
from joblib import Parallel, delayed
import itertools

from optparse import OptionParser

# Arguments

exodus = '36PrZ1KHYMpqSyAQXSG8VwbUiq2EogxLo2'
minimum = 1000000
maximum = 150000000000

# Option parsing

parser = OptionParser()
parser.add_option('-p', '--password',
                  default=None, dest='pw',
                  help="A single password to try against the wallet.")
parser.add_option('-f', '--passwords-file',
                  default=None, dest='pwfile',
                  help="A file containing a newline-delimited list of passwords to try. (default: %default)")
parser.add_option('-s', '--password-spec-file',
                  default=None, dest='pwsfile',
                  help="A file containing a password specification")
parser.add_option('-w', '--wallet',
                  default='wallet.json', dest='wallet',
                  help="The wallet against which to try the passwords. (default: %default)")

(options, args) = parser.parse_args()

# Function wrappers


def sha3(x):
    return python_sha3.sha3_256(x).digest()


def pbkdf2(x):
    return PBKDF2._pbkdf2(x, x, 2000)[:16]

# Prefer openssl because it's more well-tested and reviewed; otherwise,
# use pybitcointools' internal ecdsa implementation
try:
    import openssl
except:
    openssl = None


def secure_privtopub(priv):
    if len(priv) == 64:
        return secure_privtopub(priv.decode('hex')).encode('hex')
    if openssl:
        k = openssl.CKey()
        k.generate(priv)
        return k.get_pubkey()
    else:
        return privtopub(priv)


def tryopen(f):
    try:
        assert f
        t = open(f).read()
        try:
            return json.loads(t)
        except:
            raise Exception("Corrupted file: "+f)
    except:
        return None


def eth_privtoaddr(priv):
    pub = encode_pubkey(secure_privtopub(priv), 'bin_electrum')
    return encode_hex(sha3(pub)[12:])


class DecryptionException(Exception):
    pass

def getseed(encseed, pw, ethaddr):
    try:
        seed = aes.decryptData(pw, binascii.unhexlify(encseed))
    except Exception, e:
        raise DecryptionException("AES Decryption error. Bad password?")
    try:
        ethpriv = sha3(seed)
        eth_privtoaddr(ethpriv)
        assert eth_privtoaddr(ethpriv) == ethaddr
    except Exception, e:
        # print ("eth_priv = %s" % eth_privtoaddr(ethpriv))
        # print ("ethadd = %s" % ethaddr)
        # traceback.print_exc()
        raise DecryptionException("Decryption failed. Bad password?")
    return seed


def list_passwords():
    if not options.pwfile:
        return []
    with open(options.pwfile) as f:
        return f.read().splitlines()


def ask_for_password():
    return getpass.getpass()


class PasswordFoundException(Exception):
    pass

def generate_all(el, tr):
    if el:
        for j in xrange(len(el[0])):
            for w in generate_all(el[1:], tr + el[0][j]):
                yield w
    else:
        yield tr

def attempt(w, pw):
    try:
        print (pw)
        raise PasswordFoundException(
            """\n\nYour seed is:\n%s\nYour password is:\n%s""" % (getseed(w['encseed'], pbkdf2(pw), w['ethaddr']), pw))

    except DecryptionException as e:
        # print(e)
        return ""

def __main__():
    w = tryopen(options.wallet)
    if not w:
        print("Wallet file not found! (-h for help)")
        exit(1)

    pwds = []

    if not(options.pw or options.pwfile or options.pwsfile):
        print("No passwords specified! (-h for help)")

    if options.pw:
        pwds.append(options.pw)

    if options.pwfile:
        try:
            pwds.extend(list_passwords())
        except:
            print("Password file not found! (-h for help)")
            exit(1)

    if options.pwsfile:
        grammar = eval(file(options.pwsfile, 'r').read())
        pwds = itertools.chain(pwds, generate_all(grammar,''))


    try:
        Parallel(n_jobs=-1)(delayed(attempt)(w, pw) for pw in pwds)
    except Exception, e:
        traceback.print_exc()
        while True:
            sys.stdout.write('\a')
            sys.stdout.flush()

if __name__ == "__main__":
    __main__()
