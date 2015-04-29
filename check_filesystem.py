#!/usr/bin/env python
#
# file:     check_filesystem.py
# author:   Jay Maree (pm@me)
#
#  Scan the filesystem for the Mumblehard Backdoor.
#  It will only scan files matching the given file patterns.
#
#  Known SHA-1 hashes are compared to determine if it's really Mumblehard.
#
#  Example usage: ./check_filesystem.py /dirname
#
import re
import os
import sys
import fnmatch
import optparse
import hashlib
try:
    from hashlib import sha1
except ImportError:
    from sha1 import sha1

# from https://github.com/jaymaree/detectmumblehard/blob/master/file_hashes.txt
MUMBLEHARD_SHA1_HASHES = [
    "65a2dc362556b55cf2dbe3a10a2b337541eea4eb", "331ca10a5d1c5a5f3045511f7b66340488909339",
    "2f2e5776fb7405996feb1953b8f6dbca209c816a", "95aed86918568b122712bdbbebdd77661e0e6068",
    "c83042491efade4a4a46f437bee5212033c168ee", "e62c7c253f18ec7777fdd57e4ae500ad740183fb",
    "9540072cbc9c4b34d9c784aed60a071ece5264bc",
]

FNMATCH_PATTERNS = ["*.zip", "*.*", "*.elf", "*.lf", "*.sh"]
REGEX_VERSION = re.compile(".*'ver'[^=]*=\s*([^;]*);.*", re.MULTILINE)

KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

def bold(text):
    return KBOLD + text + KNORM

def cyan(text):
    return KCYAN + text + KNORM

def green(text):
    return KGREEN + text + KNORM

def red(text):
    return KRED + text + KNORM

def yellow(text):
    return KYELLOW + text + KNORM

def nocolor(text):
    return text


def is_crypto_php_shell(data):
    """ Quick check to determine if contents of file is CRYPTOPHP """
    return 'openssl_seal' in data and 'serverKey' in data

def cryptophp_version(buf):
    for line in buf.splitlines():
        match = REGEX_VERSION.match(line)
        if match:
            return match.group(1).strip('"').strip("'")
    return None

def scan_file(path):
    """ Scan a file for CryptoPHP.
    Returns (path, msg) if file is CryptoPHP, otherwise None
    """
    data = ''
    f = open(path, "rb")
    data = f.read()
    f.close()

    # Not CryptoPHP, skip
    if not is_crypto_php_shell(data.decode("utf-8", "replace")):
        return None

    # Determine version
    version = cryptophp_version(data.decode("utf-8", "replace"))

    # return result
    msg = bold(yellow('POSSIBLE MUMBLEHARD!'))
    sha1_hash = sha1(data).hexdigest()
    if sha1_hash in MUMBLEHARD_SHA1_HASHES:
        msg = bold(red('MUMBLEHARD DETECTED!'))

    if version:
        msg += ' (version: %s)' % bold(version)

    return (bold(path), msg)

def scan_directory(directory, patterns):
    """ Recursively scan the `directory` for CryptoPHP.
    It will only scan files that match `patterns`.
    yields (path, msg) for scan results
    """
    for root, dirs, files in os.walk(directory):
        for fname in files:
            path = os.path.join(root, fname)
            if not os.path.isfile(path):
                continue

            # Only process files matching `patterns`
            to_process = False
            for pattern in patterns:
                # case insensitive match
                if fnmatch.fnmatch(fname.lower(), pattern):
                    to_process = True
                    break
            if not to_process:
                continue

            # Check contents of file
            result = scan_file(path)
            if result:
                yield result

def main():
    parser = optparse.OptionParser(usage="usage: %prog [options] directory|file [directory2|file2] [..]")
    parser.add_option("-n", "--no-color", dest="nocolor", action="store_true",
            default=False,
            help="no color output [default: %default]")
    parser.add_option("-p", "--patterns", dest="patterns", action="store",
            default=",".join(FNMATCH_PATTERNS),
            help="scan only files matching the patterns (comma seperated) [default: %default]")

    (options, args) = parser.parse_args()

    if options.nocolor:
        global bold, cyan, green, red, yellow
        bold = cyan = green = red = yellow = nocolor

    options.patterns = options.patterns.split(",")
    print("File matching patterns: %r" % options.patterns)

    # default to root if user did not specify a directory as argument
    if not args:
        args = ["/"]

    found = []
    for directory in args:
        if not os.path.exists(directory):
            print('File or directory does not exist: %s, skipping' % directory)
            continue
        if os.path.isfile(directory):
            print('Scanning file: %s' % directory)
            result = scan_file(directory)
            if result:
                print(" %s: %s" % result)
                found.append(result)
            continue
        print('Recursively scanning directory: %s' % directory)
        for result in scan_directory(directory, options.patterns):
            print(" %s: %s" % result)
            found.append(result)

    if found:
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
