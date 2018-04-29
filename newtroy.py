#!/usr/bin/env python

## WARNING: This is written for Python 2.7 because that is what Algo uses, rolleyes

import argparse
import errno
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap


SCRIPTPATH = os.path.realpath(__file__)
SCRIPTDIR = os.path.dirname(SCRIPTPATH)
logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
LOGGER = logging.getLogger(__name__)


## Generic helper functions/classes


class MismatchedConfigsError(Exception):
    """An error indicating that an encrypted configs archive differs from a decrypted configs directory
    """
    pass


def bettermkdir(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


def debugexchandler(exc_type, exc_value, exc_traceback):
    """Debug Exception Handler

    If sys.excepthook is set to this function, automatically enter the debugger when encountering
    an uncaught exception
    """
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
    else:
        import pdb
        import traceback
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(exc_type, exc_value, exc_traceback)
        print()
        # ...then start the debugger in post-mortem mode.
        pdb.pm()


def pipe(arg_kwarg_list):
    """Construct a shell pipeline

    Invokes the first command in the arglist, retrieves its STDOUT, passes that to the STDIN of the
    next command in the arglist, and so on.

    arg_kwarg_list:     A list of (command, kwargs) tuples
                        command:    A list to pass to subprocess.Popen
                        kwargs:     Any keyword arguments to subprocess.Popen
    result:             The STDOUT of the final command
    """
    first = True
    stdin = b""
    for argtuple in arg_kwarg_list:
        if len(argtuple) != 2:
            raise Exception(
                "Expected tuple of 2 elements but found tuple of {}".format(len(argtuple)))
        command, kwargs = argtuple
        kwargs['stdout'] = subprocess.PIPE
        kwargs['stderr'] = subprocess.PIPE

        if not first:
            kwargs['stdin'] = subprocess.PIPE
        first = False

        process = subprocess.Popen(command, **kwargs)
        stdout, _ = process.communicate(input=stdin)

        if process.returncode != 0:
            raise subprocess.CalledProcessError(process.returncode, command)

        stdin = stdout

    return stdout


def resolvepath(path):
    return os.path.realpath(os.path.normpath(os.path.expanduser(path)))


## Implementation functions


def activate_venv(venvpath):
    """Activate a virtual environment

    Note that this will remain activated for subprocesses
    """
    if sys.prefix != venvpath:
        if hasattr(sys, 'real_prefix'):
            LOGGER.warning(" ".join([
                "Will activate venv at {}, ".format(venvpath),
                "but there was an already activated venv at {}; ".format(sys.real_prefix),
                "if you have problems, consider deactivating that environment in your shell"]))

        # Based on instructions found in the activate_this.py on my system

        activate_this = "{}/bin/activate_this.py".format(venvpath)
        newglobals = dict(__file__=activate_this)

        try:
            execfile(activate_this, newglobals)
        except NameError:
            # python3 does not have execfile()
            # See also https://stackoverflow.com/questions/436198/what-is-an-alternative-to-execfile-in-python-3#437857
            with open(activate_this) as f:
                exec(compile(f.read(), activate_this, 'exec'), newglobals)


# TODO: handle absolute paths
def encrypt_configs(encrypted, decrypted, recipient, overwrite=False):
    """Encrypt the configs directory
    """
    decrypted_parent, decrypted_dir = os.path.split(decrypted)
    if os.path.exists(encrypted):
        if not overwrite:
            raise Exception("Encrypted file '{}' exists".format(encrypted))
        else:
            os.unlink(encrypted)
    pipe([
        (['tar', '-c', decrypted_dir], {'cwd': decrypted_parent}),
        (['gzip'], {}),
        (['gpg', '--recipient', recipient, '--encrypt', '--output', encrypted], {})
    ])


def decrypt_configs(encrypted, decrypted, overwrite=False):
    """Decrypt the configs tarball

    encrypted           The path to the encrypted config archive
    decrypted           The full path to the extracted folder inside the archive
                        (Requires exactly one folder in the encrypted archive)
                        This almost ends with '/configs'
    overwrite           If true, allow extraction even if decrypted_dirname contains files
    """
    decrypted_parent, decrypted_dirname = os.path.split(decrypted)
    bettermkdir(decrypted_parent)
    if not test_empty_config(decrypted) and not overwrite:
        raise Exception("Decrypted directory '{}' is not empty".format(decrypted))
    pipe([
        (['gpg', '--decrypt', encrypted], {}),
        (['gunzip'], {}),
        (['tar', '-x'], {'cwd': decrypted_parent})
    ])
    if not os.path.exists(decrypted):
        raise Exception(" ".join([
            "Intended to decrypt {} to parent directory {}, ".format(encrypted, decrypted_parent),
            "but did not find the {} directory we expected afterwards; ".format(decrypted),
            "that directory contains: {}".format(os.listdir(decrypted_parent))
        ]))
    return decrypted


# TODO: handle absolute paths
def test_empty_config(configdir):
    """Test whether the config dir is empty (but ignore hidden files)
    """
    if os.path.exists(configdir):
        for child in os.listdir(configdir):
            if child.startswith("."):
                return False
    return True


# TODO: handle absolute paths
def test_equal_configs(encrypted, decrypted):
    tempdir = tempfile.mkdtemp()
    try:
        temp_decrypted = '{}/{}'.format(tempdir, os.path.basename(decrypted))
        decrypt_configs(encrypted, temp_decrypted)
        # pipe([
        #     (['gpg', '--decrypt', encrypted], {}),
        #     (['gunzip'], {}),
        #     (['tar', '-x'], {'cwd': tempdir})
        # ])
        result = subprocess.call(['diff', '-r', decrypted, temp_decrypted])
        return result == 0
    finally:
        # shutil.rmtree(tempdir)
        pass


def predeploy_prep_configs(encrypted, decrypted):
    if not os.path.exists(encrypted):
        LOGGER.info("The encrypted configs file is not present, nothing to do")
    elif test_empty_config(decrypted):
        LOGGER.info(
            "The decrypted configs directory has no non-hidden files "
            "(and the encrypted tarball exists), decrypting...")
        decrypt_configs(encrypted, decrypted)
    elif test_equal_configs(encrypted, decrypted):
        LOGGER.info(
            "The decrypted configs directory and the encrypted tarball match in content, "
            "nothing to do")
    else:
        msg = "The decrypted configs directory and the encrypted tarball do not match!"
        LOGGER.error(msg)
        raise MismatchedConfigsError(msg)


# TODO: handle absolute path better?
def deploy(environment):
    """Deploy Algo
    """

    # Arguments for all environments
    varsfiles = []
    tags = [
        'ec2',              # Required for AWS
        'vpn',              # Required for Algo
        'cloud',            # Required for non-local deployments (I think)
        'security',         # Make additional security enhancements
        'encrypted',        # Encrypt the AWS EBS volume
        'ssh_tunneling',    # Enable SSH tunneling, and save known_hosts
    ]

    # Arguments for specific environments
    if environment == "production":
        tags += [
            'dns_route53',      # Enable Route53 DNS
        ]
    elif environment == "testing":
        varsfiles += [
            'config.vault.cfg',         # Included to work w/ upstream algo (see newtroy readme)
                                        # Must be first so others can override
            'config.test.vault.cfg',    # An ansible vault containing test env secrets
            'config.test.cfg',          # An ansible config file containing test env variables
        ]
    else:
        raise Exception("Invalid environment name")
    
    command = ['ansible-playbook', 'deploy.yml', '-t', ','.join(tags)]
    for varsfile in varsfiles:
        command += ['-e', '@{}'.format(varsfile)]
    LOGGER.info("Deploying Algo with command: {}".format(' '.join(command)))
    subprocess.check_call(command, cwd=SCRIPTDIR)


def main(*args, **kwargs):  # pylint: disable=W0613

    epilog = textwrap.dedent("""
        PRODUCTION:
            Production is deployed to AWS
            It uses config.cfg and config.vault.cfg for its variables

            It is only intended to work on the newtroy fork

            Note that a typical Algo deployment passes in multiple variables with '-e'
            on the command line, but since this is a fork containing just my
            configuration, I have set those values in config.cfg and config.vault.cfg
            (See README.NEWTROY.md for more information)

        TESTING:
            Testing is deployed to AWS
            It uses config.cfg/config.vault.cfg, but overrides some value from those
            files with value from config.test.cfg/config.test.vault.cfg

            It is intended to work on the newtroy fork, OR on upstream algo
        """)

    parser = argparse.ArgumentParser(
            description="Deploy an Algo VPN with NEWTROY additions",
            epilog=epilog,
            add_help=True,
            formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument(
        '--debug', '-d', action='store_true', help='Enable debugging')
    parser.add_argument(
        '--configs-path', default=resolvepath('configs'),
        help='The path to the Algo configs directory')
    parser.add_argument(
        '--encrypted-configs', default=resolvepath('configs.tar.gz.gpg'),
        help='The path to the encrypted configs tarball')
    parser.add_argument(
        '--encryption-recipient', default="conspirator@PSYOPS",
        help='The recipient for GPG encryption. You probably do not want to change this.')
    parser.add_argument(
        '--venv-path', default=resolvepath('env.PSYOPS'),
        help=(
            'The location of the virtual environment. '
            'Used regardless of whether it is activated in your shell. '
            'If it does not exist, it will be created.'))
    
    subparsers = parser.add_subparsers(dest='action')

    subparsers.add_parser('production', help='Deploy production')

    subparsers.add_parser('testing', help='Deploy testing')

    sub_encrypt = subparsers.add_parser('encrypt', help='Compress the configs directory to an encrypted file')
    sub_encrypt.add_argument(
        "--force", action='store_true', default=False,
        help='Overwrite an existing encrypted configs archive')

    sub_decrypt = subparsers.add_parser('decrypt', help='Decompress the encrypted configs file')
    sub_decrypt.add_argument(
        "--force", action='store_true', default=False,
        help='Overwrite an existing nonempty configs directory')

    parsed = parser.parse_args()

    if parsed.debug:
        LOGGER.setLevel(logging.DEBUG)
        sys.excepthook = debugexchandler

    activate_venv(parsed.venv_path)

    try:
        if parsed.action == 'production':
            predeploy_prep_configs(parsed.encrypted_configs, parsed.configs_path)
            deploy("production")
            encrypt_configs(
                parsed.encrypted_configs,
                parsed.configs_path,
                parsed.encryption_recipient,
                overwrite=True)
        elif parsed.action == 'testing':
            predeploy_prep_configs(parsed.encrypted_configs, parsed.configs_path)
            deploy("testing")
            encrypt_configs(
                parsed.encrypted_configs,
                parsed.configs_path,
                parsed.encryption_recipient,
                overwrite=True)
        elif parsed.action == 'encrypt':
            encrypt_configs(
                parsed.encrypted_configs,
                parsed.configs_path,
                parsed.encryption_recipient,
                overwrite=parsed.force)
        elif parsed.action == 'decrypt':
            result = decrypt_configs(
                parsed.encrypted_configs,
                parsed.configs_path,
                overwrite=parsed.force)
            print("Extracted the encrypted configs archive to {}".format(result))
        else:
            print("Unknown action '{}'".format(parsed.action))
            parser.print_usage()
            return 1
    except MismatchedConfigsError:
        msg = textwrap.dedent("""
            !!ERROR!!

            Configs directory:          {configs}
            Encrypted configs archive:  {encconf}

            The contents of the configs directory do not match the contents of the encrypted
            configs archive.
            You have probably modified the configs dir outside of this script

            To decrypt the encrypted archive, run:
                {scriptpath} --configs-path TEMP-decrypted-configs decrypt
            and examine the contents of the newly created directory.

            To ignore the current configs dir, remove its contents:
                rm -rf {configs}
            
            To save the existing configs dir to the encrypted configs archive, run:
                {scriptpath} encrypt --force

            """.format(
                configs=parsed.configs_path,
                encconf=parsed.encrypted_configs,
                scriptpath=SCRIPTPATH))
        print(msg)


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
