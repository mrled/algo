#!/usr/bin/env python

# A UUID filter that works with namespaces

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

        name        Any input
        namespace   A UUID representing the namespace
                    Must be either a valid uuid.UUID object
                    or a string that can be passed to the uuid.UUID constructor
        """
        if not isinstance(namespace, uuid.UUID):
            namespace = uuid.UUID(namespace)
        return uuid.uuid5(namespace, str(name))

    @staticmethod
    def test_nbuuid(name, namespace=None):
        """Show a simple example result of using the nbuuid() static method

        Intended only for demo/testing purposes.
        """
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
        }


if __name__ == '__main__':
    FilterModule.test_nbuuid(*sys.argv[1:])