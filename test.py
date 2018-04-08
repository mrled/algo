#!/usr/bin/env python2

import asn1crypto
import asn1crypto.core
import asn1crypto.x509


identity = "30:29:31:27:30:25:06:03:55:04:03:0c:1e:6d:61:67:72:61:73:73:65:65:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d"
# idbytes = bytes.fromhex(identity.replace(":", ""))
# parsed = asn1crypto.x509.Name.load(idbytes)

magrassee_cn = asn1crypto.x509.Name().build({u'common_name': unicode('magrassee.internal.micahrl.com', 'utf-8')})
magrassee_id = ':'.join('{:02x}'.format(ord(byte)) for byte in magrassee_cn.dump())

print(identity)
print(magrassee_id)
print("Strings match: {}".format(identity == magrassee_id))
