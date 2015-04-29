#!/bin/bash
#
# file:     check_filesystem.sh
# author:   Jay Maree (pm@me)
#
#  Scan the filesystem for the Mumblehard Backdoor.
#  It will only scan files matching the given SHA1 hashes.
#
#  Known SHA-1 hashes are compared to determine if it's really Mumblehard.
#
#  Example usage: ./check_filesystem.sh /dirname
#
# find $1 -type f | xargs -I {} openssl sha1 {} | grep '9540072cbc9c4b34d9c784aed60a071ece5264bc|second|third'

# from https://github.com/jaymaree/detectmumblehard/blob/master/hashes.txt
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root :("
    echo "Please try running this command again as root user"
    exit 1
fi

function printMessage() {
    echo -e "\e[1;37m# $1\033[0m"
}

printMessage "Starting the hunt..."

# the backdoor is mostly planted in the tmp folders. ex: /tmp

find $1 -type f | xargs -I {} openssl sha1 {} | grep -iHFf hashes.txt > output_mumblehard.txt

printMessage "Saved the scan to output_mumblehard.txt..."
printMessage "Stay safe!"
