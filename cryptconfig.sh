#!/bin/sh
set -eu

cmdname=`basename "$0"`
encrypted_configs=configs.tar.gz.gpg
decrypted_configs=configs
encryption_recipient="conspirator@PSYOPS"

usage() {
    cat <<ENDUSAGE
Usage: $cmdname [-h] <encrypt|decrypt>
Encryption operations for the $encrypted_configs file

The file is always encrypted to $encryption_recipient

ARGUMENTS
    -h | --help: Print help and exit
    encrypt: tar, gzip, and encrypt $decrypted_configs => $encrypted_configs
    decrypt: decrypt, gunzip, and untar $encrypted_configs => $decrypted_configs
ENDUSAGE
}

if test $# -ne 1; then
    usage
    exit 1
elif test "$1" = "encrypt"; then
    rm "$encrypted_configs"
    tar -c "$decrypted_configs" |
        gzip |
        gpg --recipient "$encryption_recipient" --encrypt --output "$encrypted_configs"
elif test "$1" = "decrypt"; then
    rm -rf "$decrypted_configs"
    gpg --decrypt "$encrypted_configs" |
        gunzip |
        tar x
else
    usage
    exit 1
fi
