#!/usr/bin/env python

# A UUID filter that works with namespaces

import argparse
import sys
import uuid


class FilterModule(object):
    """Name-based UUID filter
    """

    @staticmethod
    def nbuuid(name, namespace):
        """Generate a name-based UUID

        Per RFC4122, a name-based UUID is generated from a 'name' (any input) and a 'namespace'
        (itself a UUID which uniquely represents the namespace).

        Given the same name and namespace, will always return the same value.

        name        Any input
        namespace   A UUID representing the namespace
                    Must be either a valid uuid.UUID object
                    or a string that can be passed to the uuid.UUID constructor
        """
        if not isinstance(namespace, uuid.UUID):
            namespace = uuid.UUID(namespace)
        return uuid.uuid5(namespace, str(name))

    @staticmethod
    def url_nbuuid(name):
        """Generate a name-based UUID in the URL namespace
        """
        return uuid.uuid5(uuid.NAMESPACE_URL, name)

    @staticmethod
    def dns_nbuuid(name):
        """Generate a name-based UUID in the DNS namespace
        """
        return uuid.uuid5(uuid.NAMESPACE_DNS, name)

    @staticmethod
    def test_nbuuid(name, namespace=None):

        if namespace == None:
            namespace = uuid.uuid4()
            print("Example namespace (randomly generated): {}".format(namespace))
        else:
            print("Attempting to use passed-in namespace: {}".format(namespace))

        namebased_uuid = FilterModule.nbuuid(name, namespace)
        print("UUID for input '{}' in namespace '{}': {}".format(name, namespace, namebased_uuid))

    def filters(self):
        return {
            'newtroy_nbuuid': self.nbuuid,
            'newtroy_url_nbuuid': self.url_nbuuid,
            'newtroy_dns_nbuuid': self.dns_nbuuid,
        }


def main(*args, **kwargs):
    """Show a simple example result of using the nbuuid() static method

    Intended only for demo/testing purposes.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'name', help="Input for a new name-based UUID")
    parser.add_argument(
        'namespace', nargs='?', default=None, type=uuid.UUID,
        help=(
            "An optional namespace (which itself must be a UUID) for a name-based UUID. "
            "If omitted, a randomly generated namespace will be used. "
            "Note that this program will return the same output UUID "
            "for the same input name and namespace UUIDs"))
    parsed = parser.parse_args()

    if not parsed.namespace:
        namespace = uuid.uuid4()
        print("Example namespace (randomly generated): {}".format(namespace))
    else:
        namespace = parsed.namespace
        print("Attempting to use passed-in namespace: {}".format(namespace))

    namebased_uuid = FilterModule.nbuuid(parsed.name, namespace)
    print("UUID for input '{}' in namespace '{}': {}".format(
        parsed.name, namespace, namebased_uuid))


if __name__ == '__main__':
    main(*sys.argv[1:])
