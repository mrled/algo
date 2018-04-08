#!/usr/bin/env python

from asn1crypto.x509 import Name as X509Name
from ansible.parsing.yaml.objects import AnsibleUnicode


def ensure_unicode(string):
    """ Ensure that an input string is a (python2) unicode object
    """
    if isinstance(string, AnsibleUnicode):
        return string.decode()
    elif isinstance(string, str):
        return unicode(string, 'utf-8')
    else:
        return string


def string2hex(string):
    """ Convert a (python2) string object to a hex string

    The resulting hex string is in the format of bytes separated by colons
    """
    return ':'.join('{:02x}'.format(ord(character)) for character in string)


def x509_common_name_hex(string):
    """ Create a DER-encoded common name for the input string

    Return the hex-encoded value
    """
    common_name = X509Name.build({u'common_name': ensure_unicode(string)})
    return string2hex(common_name.dump())


class FilterModule(object):
    def filters(self):
        return {
            'x509_common_name_hex': x509_common_name_hex
        }


# Useful during debugging
if __name__ == '__main__':
    instring = "whatever.example.com"
    result = x509_common_name_hex(instring)
    print("\n".join([
        "Input value:   {}".format(instring),
        "Input type:    {}".format(type(instring)),
        "Result value:  {}".format(result),
        "Result type:   {}".format(type(result))
    ]))
