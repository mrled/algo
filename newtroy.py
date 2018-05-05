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
    def __init__(self, message, configdiff):
        super(MismatchedConfigsError, self).__init__(message)
        self.configdiff = configdiff


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
        stdout, stderr = process.communicate(input=stdin)
        if stderr is not None:
            LOGGER.debug("STDERR from '{}': {}".format(" ".join(command), stderr.decode()))

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
            real_prefix = sys.real_prefix  # pylint: disable=E1101
            LOGGER.warning(" ".join([
                "Will activate venv at {}, ".format(venvpath),
                "but there was an already activated venv at {}; ".format(real_prefix),
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
    decrypted_parent, _ = os.path.split(decrypted)
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


def test_empty_config(configdir):
    """Test whether the config dir is empty (but ignore hidden files)
    """
    if os.path.exists(configdir):
        for child in os.listdir(configdir):
            if child.startswith("."):
                return False
    return True


def get_config_diff(
        encrypted,
        decrypted,
        encrypted_path_replace=None,
        decrypted_path_replace=None):
    """Test whether configs are equal

    If the configs match, return False; if not, return the result of the diff command.

    encrypted               The path to the encrypted config archive
    decrypted               The path to the decrypted config directory
    encrypted_path_replace  The text to display in lieu of the actual temp directory
                            where the encrypted config archive was extracted
                            Defaults to /path/to/encrypted.gpg##/
    decrypted_path_replace  The text to display in lieu of the actual decrypted configs path
                            Defaults to the actual path
    """
    decrypted_parent = os.path.basename(decrypted)
    if encrypted_path_replace is None:
        encrypted_path_replace = "{}##/".format(encrypted)
    if decrypted_path_replace is None:
        decrypted_path_replace = decrypted_parent

    tempdir = tempfile.mkdtemp()
    try:
        LOGGER.debug("Using tempdir in get_config_diff() at {}".format(tempdir))
        temp_decrypted = '{}/{}'.format(tempdir, decrypted_parent)
        decrypt_configs(encrypted, temp_decrypted)
        command = ['diff', '-r', decrypted, temp_decrypted]
        diffproc = subprocess.Popen(command, stdout=subprocess.PIPE)
        diffout, differr = diffproc.communicate()
        if differr is not None:
            LOGGER.debug("STDERR from '{}': {}".format(" ".join(command), differr.encode()))

        diffout = diffout.decode()
        diffout = diffout.replace(temp_decrypted, encrypted_path_replace)
        diffout = diffout.replace(decrypted, decrypted_path_replace)

        if diffproc.returncode != 0:
            return diffout
        return False
    finally:
        shutil.rmtree(tempdir)


def config_git_diff(encrypted, configspath):
    """Show a 'git diff' on the encrypted config file

    encrypted       The path to the encrypted configs archive
                    Must not have been moved with e.g. 'git mv' without being committed
    configspath     The path to the decrypted configs dir
                    Used solely for its basename, to know what should extract
    """

    encrypted_git_subpath = encrypted.replace(SCRIPTDIR, '')
    while encrypted_git_subpath.startswith('/'):
        encrypted_git_subpath = encrypted_git_subpath[1:]

    # Get the contents of the committed encrypted configs file
    command = ['git', 'show', 'HEAD:{}'.format(encrypted_git_subpath)]
    gitproc = subprocess.Popen(command, stdout=subprocess.PIPE, cwd=SCRIPTDIR)
    gitout, giterr = gitproc.communicate()
    if giterr is not None:
        LOGGER.debug("STDERR from '{}': {}".format(" ".join(command), giterr.encode()))
    if gitproc.returncode != 0:
        raise Exception("Git exited with code {}".format(gitproc.returncode))

    committed_config_tempdir = tempfile.mkdtemp()
    try:
        committed_config_encrypted_path = os.path.join(committed_config_tempdir, 'tmp.gpg')
        LOGGER.debug(
            "Using tempdir in config_git_diff() at {}".format(committed_config_encrypted_path))
        with open(committed_config_encrypted_path, 'wb') as encf:
            encf.write(gitout)

        committed_config_decrypted_tempdir = tempfile.mkdtemp()
        try:
            temp_decrypted = '{}/{}'.format(committed_config_decrypted_tempdir, os.path.basename(configspath))
            decrypt_configs(committed_config_encrypted_path, temp_decrypted)
            configdiff = get_config_diff(
                encrypted, temp_decrypted,
                encrypted_path_replace="   SAVED TO DISK",
                decrypted_path_replace="COMMITTED TO GIT")
        finally:
            shutil.rmtree(committed_config_decrypted_tempdir)

    finally:
        shutil.rmtree(committed_config_tempdir)
    return configdiff


def predeploy_prep_configs(encrypted, decrypted):
    """Ensure the configs directory is in the correct state

    Test that the contents of the 'encrypted' archive match the contents of the existing
    'decrypted' directory.
    If they do not, raise a MismatchedConfigsError.
    """

    if not os.path.exists(encrypted):
        LOGGER.info("The encrypted configs file is not present, nothing to do")
    elif test_empty_config(decrypted):
        LOGGER.info(
            "The decrypted configs directory has no non-hidden files "
            "(and the encrypted tarball exists), decrypting...")
        decrypt_configs(encrypted, decrypted)

    else:
        configdiff = get_config_diff(encrypted, decrypted)
        if configdiff is False:
            LOGGER.info(
                "The decrypted configs directory and the encrypted tarball match in content, "
                "nothing to do")
        else:
            msg = "The decrypted configs directory and the encrypted tarball do not match!"
            LOGGER.error(msg)
            raise MismatchedConfigsError(msg, configdiff)


def postdeploy_prep_configs(encrypted, decrypted, recipient):
    """Recreate the configs archive after deployment

    Should only result in a new encrypted archive if the _contents_ of the archive differ.
    That is, some metadata like timestamps may differ and should not result in a new archive;
    only when the contents differ should the new archive be created.
    """
    if not os.path.exists(encrypted):
        LOGGER.info(' '.join([
            "No encrypted archive at {},".format(encrypted),
            "will save a new one from {}".format(decrypted)]))
        encrypt_configs(encrypted, decrypted, recipient)
    elif get_config_diff(encrypted, decrypted) is not False:
        LOGGER.info(' '.join([
            "Found difference between configuration at {}".format(decrypted),
            "and encrypted archive at {}; recreating config...".format(encrypted)]))
        encrypt_configs(encrypted, decrypted, recipient, overwrite=True)
    else:
        LOGGER.info(' '.join([
            "No difference between configuration at {}".format(decrypted),
            "and encrypted archive at {}; will not recreate encrypted archive".format(encrypted)]))


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
            'dns_vpnclients_route53',   # Enable Route53 DNS for internal VPN client addreses
            'dns_vpnserver_route53',    # Enable Route53 DNS for connecting to the server
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
        '--configs-path', '-c',
        default=resolvepath('configs'), type=resolvepath,
        help='The path to the Algo configs directory')
    parser.add_argument(
        '--encrypted-configs', '-e',
        default=resolvepath('configs.tar.gz.gpg'), type=resolvepath,
        help='The path to the encrypted configs tarball')
    parser.add_argument(
        '--encryption-recipient', '-r',
        default="conspirator@PSYOPS",
        help='The recipient for GPG encryption. You probably do not want to change this.')
    parser.add_argument(
        '--venv-path', '-v',
        default=resolvepath('env.PSYOPS'), type=resolvepath,
        help=(
            'The location of the virtual environment. '
            'Used regardless of whether it is activated in your shell. '
            'If it does not exist, it will be created.'))

    subparsers = parser.add_subparsers(dest='action')

    sub_deploy = subparsers.add_parser('deploy', help="Deploy Algo")
    sub_deploy.add_argument(
        'environment',
        choices=['production', 'testing'],
        help='The name of the environment to deploy')

    sub_config = subparsers.add_parser('config', help='Work with the encrypted configuration')
    sub_config.add_argument(
        'configaction',
        choices=['encrypt', 'decrypt', 'gitdiff'],
        help=(
            'ENCRYPT: Encrypt the decrypted config directory; '
            'DECRYPT: Decrypt the encrypted config archive; '
            'GITDIFF: Diff the encrypted config contents on disk vs committed to git'))
    sub_config.add_argument(
        "--force", '-f',
        action='store_true', default=False,
        help='Overwrite the output if it exists')

    parsed = parser.parse_args()

    if parsed.debug:
        LOGGER.setLevel(logging.DEBUG)
        sys.excepthook = debugexchandler

    activate_venv(parsed.venv_path)

    try:
        if parsed.action == 'deploy':
            predeploy_prep_configs(parsed.encrypted_configs, parsed.configs_path)
            deploy(parsed.environment)
            postdeploy_prep_configs(
                parsed.encrypted_configs,
                parsed.configs_path,
                parsed.encryption_recipient)
        elif parsed.action == 'config':
            if parsed.configaction == 'encrypt':
                encrypt_configs(
                    parsed.encrypted_configs,
                    parsed.configs_path,
                    parsed.encryption_recipient,
                    overwrite=parsed.force)
            elif parsed.configaction == 'decrypt':
                result = decrypt_configs(
                    parsed.encrypted_configs,
                    parsed.configs_path,
                    overwrite=parsed.force)
                print("Extracted the encrypted configs archive to {}".format(result))
            elif parsed.configaction == 'gitdiff':
                result = config_git_diff(parsed.encrypted_configs, parsed.configs_path)
                print(result)
            else:
                print("Unknown configaction '{}'".format(parsed.configaction))
                parser.print_usage()
                return 1
        else:
            print("Unknown action '{}'".format(parsed.action))
            parser.print_usage()
            return 1

    # We get a BrokenPipeError if we pipe to e.g. less and then quit less
    # BrokenPipeError inherits from one of these errors, depending on Python version
    except (IOError, OSError) as exc:
        if exc.errno != errno.EPIPE:
            raise

    except MismatchedConfigsError as exc:
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
        msg += "Output of the `diff` command:\n\n{}".format(exc.configdiff)
        print(msg)


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
