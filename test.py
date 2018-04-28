#!/usr/bin/env python2

import argparse
import pdb
import sys

from asn1crypto.x509 import Name as X509Name
from asn1crypto.core import load as asn1load
from ansible.parsing.yaml.objects import AnsibleUnicode


strace = pdb.set_trace


def idb_excepthook(type, value, tb):
    """Call an interactive debugger in post-mortem mode

    If you do "sys.excepthook = idb_excepthook", then an interactive debugger
    will be spawned at an unhandled exception
    """
    if hasattr(sys, 'ps1') or not sys.stderr.isatty():
        # we are in interactive mode or we don't have a tty-like
        # device, so we call the default hook
        sys.__excepthook__(type, value, tb)
    else:
        import traceback
        # we are NOT in interactive mode, print the exception...
        traceback.print_exception(type, value, tb)
        print
        # ...then start the debugger in post-mortem mode.
        pdb.pm()


def ensure_unicode(string):
    """ Ensure that an input string is a (python2) unicode object
    """
    if isinstance(string, AnsibleUnicode):
        return string.decode()
    elif isinstance(string, str):
        return unicode(string, 'utf-8')
    else:
        return string


def bytestring2hex(bytestring):
    """ Convert a (python2) byte/string object to a hex string

    The resulting hex string is in the format of bytes separated by colons
    """
    return ':'.join('{:02x}'.format(ord(character)) for character in bytestring)


def hex2bytestring(hexstring):
    """ Convert a hex string to to a (python2) byte/string object

    The input hex string should be in the format of bytes separated by colons
    """
    return ''.join('{}'.format(chr(int(hexbyte, 16))) for hexbyte in hexstring.split(':'))


def x509_common_name_hex(string):
    """ Create a DER-encoded common name for the input string

    Return the hex-encoded value
    """
    common_name = X509Name.build({u'common_name': ensure_unicode(string)})
    return bytestring2hex(common_name.dump())


class IdentityMetadata(object):

    def __init__(self, friendly, commonname, clientgen):
        self.friendly = friendly
        self.commonname = commonname
        self.clientgen = clientgen

    @property
    def decoded(self):
        return X509Name.load(hex2bytestring(self.clientgen))

    @property
    def clientgen_ascii(self):
        return hex2bytestring(self.clientgen)

    @property
    def calculated(self):
        return x509_common_name_hex(self.commonname)


identities = [
    IdentityMetadata(
        "Magrassee",
        'magrassee.internal.micahrl.com',
        "30:29:31:27:30:25:06:03:55:04:03:0c:1e:6d:61:67:72:61:73:73:65:65:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d"
    ),
    # IdentityMetadata(
    #     "Magrassee Two",
    #     'magrassee.internal.micahrl.com',
    #     "30:22:31:20:30:1e:06:03:55:04:03:0c:17:6d:61:67:72:61:73:73:65:65:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34"
    # ),
    IdentityMetadata(
        "AndrAIa",
        'andraia.internal.micahrl.com',
        "61:6e:64:72:61:69:61:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d"
    ),
    IdentityMetadata(
        "Example host",
        'windowsclient.example.com',
        "30:24:31:22:30:20:06:03:55:04:03:0c:19:77:69:6e:64:6f:77:73:63:6c:69:65:6e:74:2e:65:78:61:6d:70:6c:65:2e:63:6f:6d"
    ),

]


def showids():
    for identity in identities:
        print("{} (CommonName: {})".format(identity.friendly, identity.commonname))
        print("- Client-generated ID:           {}".format(identity.clientgen))
        print("- ASCII-decoded client-gen ID:   {}".format(identity.clientgen_ascii))
        print("- Calculated ID:                 {}".format(identity.calculated))
        print("- Decoded client-gen ID:")
        try:
            identity.decoded.debug()
        except ValueError:
            print("  UNAVAILBLE - NOT AN X.509 NAME")


# Main handling
# The main() function is not special - it's invoked explicitly at the end
def main(*args, **kwargs):
    parser = argparse.ArgumentParser(
        description="A template for writing a new Python3 command line tool")
    parser.add_argument(
        "-d", action='store_true', dest='debug',
        help="Include debugging output")
    # parser.add_argument(
    #     "directobject",
    #     default="mom", nargs='?',
    #     help="The object the command is working on")
    parsed = parser.parse_args()
    if parsed.debug:
        sys.excepthook = idb_excepthook

    showids()


# Unless we are running this script directly on the commandline, the main()
# function will NOT execute
if __name__ == '__main__':
    sys.exit(main(*sys.argv))
