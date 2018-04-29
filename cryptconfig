#!/bin/sh
set -eu

cmdname=`basename "$0"`
encrypted_configs=configs.tar.gz.gpg
decrypted_configs=configs
testcrypt_dir=testcrypt
testcrypt_configs="$testcrypt_dir/$decrypted_configs"
encryption_recipient="conspirator@PSYOPS"

usage() {
    cat <<ENDUSAGE
Usage: $cmdname [-h] <encrypt|decrypt|test>
Encryption operations for the $encrypted_configs file

The file is always encrypted to $encryption_recipient

ARGUMENTS
    -h | --help:    Print help and exit
    encrypt:        Encrypt $decrypted_configs/ => $encrypted_configs
    decrypt:        Decrypt $encrypted_configs => $decrypted_configs/
    test:           Test whether the contents of $encrypted_configs
                    matches that of $decrypted_configs/
ENDUSAGE
}

if test $# -ne 1; then
    usage
    exit 1
fi

case "$1" in
    "help" | "-h" | "--help")
        usage
        exit
        ;;
    "encrypt")
        rm "$encrypted_configs"
        tar -c "$decrypted_configs" |
            gzip |
            gpg --recipient "$encryption_recipient" --encrypt --output "$encrypted_configs"
        exit
        ;;
    "decrypt")
        rm -rf "$decrypted_configs"
        gpg --decrypt "$encrypted_configs" |
            gunzip |
            tar -x
        exit
        ;;
    "test")
        mkdir "$testcrypt_dir"
        gpg --decrypt "$encrypted_configs" |
            gunzip |
            tar -x -C "$testcrypt_dir"
        differ=0
        if diff -r "$decrypted_configs" "$testcrypt_configs" > /dev/null; then
            differ=
            echo "The contents of $decrypted_configs and $testcrypt_configs match"
        else
            differ=yes
            echo "The contents of $decrypted_configs and $testcrypt_configs differ"
        fi
        rm -rf "$testcrypt_dir"
        if test "$differ"; then
            exit 1
        fi
        exit
        ;;
    *)
        usage
        exit 1
        ;;
esac
