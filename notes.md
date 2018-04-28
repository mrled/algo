# Notes

## Handy commands

    cat /var/log/syslog | grep dnsmasq | grep -v 'using local addresses only' | less

    tail -f /var/log/syslog | grep dnsmasq | grep -v 'using local addresses only' > /root/dnsmasq.log &

    clear; ipsec start --nofork

## Compiling strongswan on debian

    sudo apt-get install -y libsoup2.4 libsoup2.4-dev libsoup2.4-doc dh-autoreconf libgmp-dev libgmp10 libgmp10-doc libssl-dev libssl-doc gperf bison libbison-dev bison-doc flex flex-doc libfl-dev
    ./autogen.sh
    ./configure --enable-dhcp --enable-gcm --enable-openssl
    make && sudo make install && sudo ipsec stop && sudo cp -pfr /etc/ipsec.conf /etc/ipsec.d /etc/ipsec.secrets /etc/strongswan.conf /etc/strongswan.d /usr/local/etc/ && sudo /usr/local/sbin/ipsec start --nofork


Links:

- https://lists.strongswan.org/pipermail/users/2017-July/011224.html

## Notes from adding debugging messages to the dhcp module

I got this result:

    16[NET] ====================== MRLDBG ======================
    16[NET] DHCP request:
    16[NET]         id (SipHash-2-4 result): '3971320764',
    16[NET]         chunk.ptr (client identity): '0¶1↕0►♠♥U♦♥♀      magrassee'
    16[NET]         chunk.ptr in hex: 30:14:31:12:30:10:06:03:55:04:03:0C:09:6D:61:67:72:61:73:73:65:65

When I did this:

    diff --git a/src/libcharon/plugins/dhcp/dhcp_socket.c b/src/libcharon/plugins/dhcp/dhcp_socket.c
    index b8c1b40..ad1e014 100644
    --- a/src/libcharon/plugins/dhcp/dhcp_socket.c
    +++ b/src/libcharon/plugins/dhcp/dhcp_socket.c
    @@ -35,6 +35,9 @@
    #include <daemon.h>
    #include <processing/jobs/callback_job.h>

    +#include <inttypes.h>
    +#include <utils/debug.h>
    +
    #define DHCP_SERVER_PORT 67
    #define DHCP_CLIENT_PORT 68
    #define DHCP_TRIES 5
    @@ -233,6 +236,23 @@ static int prepare_dhcp(private_dhcp_socket_t *this,
            {
                    id = transaction->get_id(transaction);
            }
    +
    +       char mrlmsg[1024];
    +       int bufctr;
    +       sprintf(
    +               mrlmsg,
    +               "====================== MRLDBG ======================\n"
    +               "DHCP request:\n"
    +               "\tid (SipHash-2-4 result): '%"PRIu32"',\n"
    +               "\tchunk.ptr (client identity): '%s'\n"
    +               "\tchunk.ptr in hex: ",
    +               id, chunk.ptr);
    +       for (bufctr = 0; bufctr < chunk.len; ++bufctr) {
    +               sprintf(mrlmsg + strlen(mrlmsg), "%02X", chunk.ptr[bufctr]);
    +               if (bufctr + 1 < chunk.len) sprintf(mrlmsg + strlen(mrlmsg), "%s", ":");
    +       }

I was getting this from `dhcpdump`:

    TIME: 2018-04-06 03:13:48.610
        IP: 10.19.48.1 (0:0:0:0:0:0) > 10.19.48.1 (0:0:0:0:0:0)
        OP: 1 (BOOTPREQUEST)
    HTYPE: 1 (Ethernet)
    HLEN: 6
    HOPS: 0
    XID: 93f298b5
    SECS: 0
    FLAGS: 0
    CIADDR: 0.0.0.0
    YIADDR: 0.0.0.0
    SIADDR: 0.0.0.0
    GIADDR: 10.19.48.1
    CHADDR: 7a:a7:50:5e:b7:61:00:00:00:00:00:00:00:00:00:00
    SNAME: .
    FNAME: .
    OPTION:  53 (  1) DHCP message type         1 (DHCPDISCOVER)
    OPTION:  61 ( 43) Client-identifier         30:29:31:27:30:25:06:03:55:04:03:0c:1e:6d:61:67:72:61:73:73:65:65:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d1
    OPTION:  55 (  2) Parameter Request List      6 (DNS server)
                                                44 (NetBIOS name server)

    ---------------------------------------------------------------------------

    TIME: 2018-04-06 03:13:48.610

OH MY GOD

 -  that client identifier option is sorta decodable in ascii to:
    `0)1'0%Umagrassee.internal.micahrl.com`

 -  You can divide it into two chunks:
    `30:29:31:27:30:25:06:03:55:04:03:0c:1e`
    and
    `6d:61:67:72:61:73:73:65:65:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d`

 -  The first chunk is garbage in ASCII, but the second chunk is just
    `magrassee.internal.micahrl.com`

 -  BUT THE FIRST CHUNK IS ASN.1 ENCODED.
    Actually it's a hex representation of DER encoding.

## Halfway working on Windows

As of the commit that adds this file, my Windows client can connect.

HOWEVER, it's not clear whether it is assigned an IP address correctly. (I tested before fixing a bug.)

On iOS, however, I get this in the log and it immediately disconnects me:

`    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[MGR] checkout IKE_SA by message
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[MGR] IKE_SA (unnamed)[11] successfully checked out
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[NET] received packet: from 136.62.77.151[1024] to 172.16.255.219[4500] (468 bytes)
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[ENC] parsed IKE_AUTH request 1 [ EF(2/2) ]
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[ENC] received fragment #2 of 2, reassembling fragmented IKE message
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[ENC] unknown attribute type (25)
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[ENC] parsed IKE_AUTH request 1 [ IDi N(INIT_CONTACT) N(MOBIKE_SUP) IDr CERTREQ AUTH CERT CPRQ(ADDR DHCP DNS MASK ADDR6 DHCP6 DNS6 (25)) N(ESP_TFC_PAD_N) N(NON_FIRST_FRAG) SA TSi TSr ]
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] received cert request for "CN=52.55.21.63"
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] received end entity cert "CN=glitch.internal.micahrl.com"
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[CFG] looking for peer configs matching 172.16.255.219[52.55.21.63]...136.62.77.151[glitch]
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[CFG]   candidate "ikev2-pubkey", match: 20/1/28 (me/other/ike)
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[CFG] selected peer config 'ikev2-pubkey'
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] no trusted ECDSA public key found for 'glitch'
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP4_ADDRESS attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP4_DHCP attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP4_DNS attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP4_NETMASK attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP6_ADDRESS attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP6_DHCP attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing INTERNAL_IP6_DNS attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] processing (25) attribute
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] received ESP_TFC_PADDING_NOT_SUPPORTED, not using ESPv3 TFC padding
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] peer supports MOBIKE
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[ENC] generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[NET] sending packet: from 172.16.255.219[4500] to 136.62.77.151[1024] (65 bytes)
    Apr  8 05:08:14 ip-172-16-255-219 charon: 10[NET] sending packet: from 172.16.255.219[4500] to 136.62.77.151[1024]
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[MGR] checkin and destroy IKE_SA ikev2-pubkey[11]
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[IKE] IKE_SA ikev2-pubkey[11] state change: CONNECTING => DESTROYING
    Apr  8 05:08:14 ip-172-16-255-219 charon: 13[MGR] check-in and destroy of IKE_SA successful`

## Next steps

- Re-test a Windows client after fixing the bug, to see if its IP address gets assigned correctly
- Figure out what can be done about iOS
- Test macOS
- Test a strongswan client
- Test whether we really need to set the VPN domain as part of the CN of the certs

Note that I'm not 100% sure I'm configuring strongswan coorectly. I was told I need to set `rightid=%{{ vpn_domain }}`, however, when I did that the Windows client couldn't connect. Leaving the `rightid` unset (same as upstream Algo) appeared to let Windows connect, so idk.


## Successful Windows connection

NOTE that the IP address is NOT set successfully

    Apr  8 20:16:19 ip-172-16-254-113 charon: 13[KNL] using 10.19.48.1 as address to reach 10.19.48.1/32
    Apr  8 20:16:19 ip-172-16-254-113 charon: 13[CFG] sending DHCP REQUEST for 10.19.48.106 to 127.0.0.1
    Apr  8 20:16:23 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[500] to 172.16.254.113[500]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[MGR] checkout IKE_SA by message
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[MGR] created IKE_SA (unnamed)[4]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[NET] received packet: from 136.62.77.151[500] to 172.16.254.113[500] (344 bytes)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[ENC] parsed IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) V V V V ]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] looking for an ike config for 172.16.254.113...136.62.77.151
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG]   candidate: %any...%any, prio 28
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] found matching ike config: %any...%any with prio 28
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] received MS NT5 ISAKMPOAKLEY v9 vendor ID
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] received MS-Negotiation Discovery Capable vendor ID
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] received Vid-Initial-Contact vendor ID
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[ENC] received unknown vendor ID: 01:52:8b:bb:c0:06:96:12:18:49:ab:9a:1c:5b:2a:51:00:00:00:02
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] 136.62.77.151 is initiating an IKE_SA
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] IKE_SA (unnamed)[4] state change: CREATED => CONNECTING
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] selecting proposal:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG]   no acceptable ENCRYPTION_ALGORITHM found
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] selecting proposal:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG]   no acceptable PSEUDO_RANDOM_FUNCTION found
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] selecting proposal:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG]   proposal matches
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] received proposals: IKE:AES_CBC_128/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_256
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] configured proposals: IKE:AES_GCM_16_128/PRF_HMAC_SHA2_512/ECP_256, IKE:AES_CBC_128/HMAC_SHA2_512_256/PRF_HMAC_SHA2_512/ECP_256, IKE:AES_CBC_128/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_256
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[CFG] selected proposal: IKE:AES_CBC_128/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_256
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] local host is behind NAT, sending keep alives
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] remote host is behind NAT
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[IKE] sending cert request for "CN=52.70.45.223"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[ENC] generating IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) CERTREQ N(MULT_AUTH) ]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[NET] sending packet: from 172.16.254.113[500] to 136.62.77.151[500] (273 bytes)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[500] to 136.62.77.151[500]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[MGR] checkin IKE_SA (unnamed)[4]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 06[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:23 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[4500] to 172.16.254.113[4500]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[MGR] checkout IKE_SA by message
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[MGR] IKE_SA (unnamed)[4] successfully checked out
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[NET] received packet: from 136.62.77.151[4500] to 172.16.254.113[4500] (1720 bytes)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[ENC] parsed IKE_AUTH request 1 [ IDi CERT CERTREQ AUTH N(MOBIKE_SUP) CPRQ(ADDR DNS NBNS SRV ADDR6 DNS6 SRV6) SA TSi TSr ]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 0e:ac:82:60:40:56:27:97:e5:25:13:fc:2a:e1:0a:53:95:59:e4:a4
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid dd:bc:bd:86:9c:3f:07:ed:40:e3:1b:08:ef:ce:c4:d1:88:cd:3b:15
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 4a:5c:75:22:aa:46:bf:a4:08:9d:39:97:4e:bd:b4:a3:60:f7:a0:1d
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 5c:b8:69:fe:8d:ef:c1:ed:66:27:ee:b2:12:0f:72:1b:b8:0a:0e:04
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 6a:47:a2:67:c9:2e:2f:19:68:8b:9b:86:61:66:95:ed:c1:2c:13:00
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for "CN=52.70.45.223"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 01:f0:33:4c:1a:a1:d9:ee:5b:7b:a9:de:43:bc:02:7d:57:09:33:fb
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid b5:cc:82:0c:a3:a1:71:12:35:6e:0e:37:bf:f1:09:f1:c8:6b:e0:df
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 88:a9:5a:ef:c0:84:fc:13:74:41:6b:b1:63:32:c2:cf:92:59:bb:3b
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 34:4f:30:2d:25:69:31:91:ea:f7:73:5c:ab:f5:86:8d:37:82:40:ec
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 3e:df:29:0c:c1:f5:cc:73:2c:eb:3d:24:e1:7e:52:da:bd:27:e2:f0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid ab:76:88:f4:e5:e1:38:c9:e9:50:17:cd:cd:b3:18:17:b3:3e:8c:f5
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid da:ed:64:74:14:9c:14:3c:ab:dd:99:a9:bd:5b:28:4d:8b:3c:c9:d8
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 5e:8c:53:18:22:60:1d:56:71:d6:6a:a0:cc:64:a0:60:07:43:d5:a8
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid c0:7a:98:68:8d:89:fb:ab:05:64:0c:11:7d:aa:7d:65:b8:ca:cc:4e
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid a8:e3:02:96:70:a6:8b:57:eb:ec:ef:cc:29:4e:91:74:9a:d4:92:38
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid f7:93:19:ef:df:c1:f5:20:fb:ac:85:55:2c:f2:d2:8f:5a:b9:ca:0b
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 30:a4:e6:4f:de:76:8a:fc:ed:5a:90:84:28:30:46:79:2c:29:15:70
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 48:e6:68:f9:2b:d2:b2:95:d7:47:d8:23:20:10:4f:33:98:90:9f:d4
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 69:c4:27:db:59:69:68:18:47:e2:52:17:0a:e0:e5:7f:ab:9d:ef:0f
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid ba:42:b0:81:88:53:88:1d:86:63:bd:4c:c0:5e:08:fe:ea:6e:bb:77
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 87:db:d4:5f:b0:92:8d:4e:1d:f8:15:67:e7:f2:ab:af:d6:2b:67:75
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 6e:58:4e:33:75:bd:57:f6:d5:42:1b:16:01:c2:d8:c0:f5:3a:9f:6e
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 4a:81:0c:de:f0:c0:90:0f:19:06:42:31:35:a2:a2:8d:d3:44:fd:08
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid d5:2e:13:c1:ab:e3:49:da:e8:b4:95:94:ef:7c:38:43:60:64:66:bd
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 6c:ca:bd:7d:b4:7e:94:a5:75:99:01:b6:a7:df:d4:5d:1c:09:1c:cc
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 42:32:b6:16:fa:04:fd:fe:5d:4b:7a:c3:fd:f7:4c:40:1d:5a:43:af
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid a5:06:8a:78:cf:84:bd:74:32:dd:58:f9:65:eb:3a:55:e7:c7:80:dc
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid e2:7f:7b:d8:77:d5:df:9e:0a:3f:9e:b4:cb:0e:2e:a9:ef:db:69:77
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 83:31:7e:62:85:42:53:d6:d7:78:31:90:ec:91:90:56:e9:91:b9:e3
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 3e:22:d4:2c:1f:02:44:b8:04:10:65:61:7c:c7:6b:ae:da:87:29:9c
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid b1:81:08:1a:19:a4:c0:94:1f:fa:e8:95:28:c1:24:c9:9b:34:ac:c7
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 21:0f:2c:89:f7:c4:cd:5d:1b:82:5e:38:d6:c6:59:3b:a6:93:75:ae
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid bb:c2:3e:29:0b:b3:28:77:1d:ad:3e:a2:4d:bd:f4:23:bd:06:b0:3d
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid ee:e5:9f:1e:2a:a5:44:c3:cb:25:43:a6:9a:5b:d4:6a:25:bc:bb:8e
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 17:4a:b8:2b:5f:fb:05:67:75:27:ad:49:5a:4a:5d:c4:22:cc:ea:4e
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 68:33:0e:61:35:85:21:59:29:83:a3:c8:d2:d2:e1:40:6e:7a:b3:c1
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 9c:a9:8d:00:af:74:0d:dd:81:80:d2:13:45:a5:8b:8f:2e:94:38:d6
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received cert request for unknown ca with keyid 4f:9c:7d:21:79:9c:ad:0e:d8:b9:0c:57:9f:1a:02:99:e7:90:f3:87
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received 38 cert requests for an unknown ca
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] received end entity cert "CN=magrassee.internal.micahrl.com"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] looking for peer configs matching 172.16.254.113[%any]...136.62.77.151[CN=magrassee.internal.micahrl.com]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   candidate "ikev2-pubkey", match: 1/1/28 (me/other/ike)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] selected peer config 'ikev2-pubkey'
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   using certificate "CN=magrassee.internal.micahrl.com"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   certificate "CN=magrassee.internal.micahrl.com" key: 256 bit ECDSA
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   using trusted ca certificate "CN=52.70.45.223"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] checking certificate status of "CN=magrassee.internal.micahrl.com"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] ocsp check skipped, no ocsp found
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] certificate status is not available
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   certificate "CN=52.70.45.223" key: 256 bit ECDSA
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   reached self-signed root ca with a path length of 0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] authentication of 'CN=magrassee.internal.micahrl.com' with ECDSA-256 signature successful
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP4_ADDRESS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP4_DNS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP4_NBNS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP4_SERVER attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP6_ADDRESS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP6_DNS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] processing INTERNAL_IP6_SERVER attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] peer supports MOBIKE
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] authentication of '52.70.45.223' (myself) with ECDSA-256 signature successful
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] IKE_SA ikev2-pubkey[4] established between 172.16.254.113[52.70.45.223]...136.62.77.151[CN=magrassee.internal.micahrl.com]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] IKE_SA ikev2-pubkey[4] state change: CONNECTING => ESTABLISHED
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] sending end entity cert "CN=52.70.45.223"
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] peer requested virtual IP %any
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] using 10.19.48.1 as address to reach 10.19.48.1/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] sending DHCP DISCOVER to 10.19.48.1
    Apr  8 20:16:23 ip-172-16-254-113 dnsmasq-dhcp[7530]: DHCPDISCOVER(lo) 7a:a7:50:5e:b7:61
    Apr  8 20:16:23 ip-172-16-254-113 dnsmasq-dhcp[7530]: DHCPOFFER(lo) 10.19.48.106 7a:a7:50:5e:b7:61
    Apr  8 20:16:23 ip-172-16-254-113 charon: 04[CFG] received DHCP OFFER 10.19.48.106 from 10.19.48.1
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] using 10.19.48.1 as address to reach 10.19.48.1/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] sending DHCP REQUEST for 10.19.48.106 to 10.19.48.1
    Apr  8 20:16:23 ip-172-16-254-113 dnsmasq-dhcp[7530]: DHCPREQUEST(lo) 10.19.48.106 7a:a7:50:5e:b7:61
    Apr  8 20:16:23 ip-172-16-254-113 dnsmasq-dhcp[7530]: DHCPACK(lo) 10.19.48.106 7a:a7:50:5e:b7:61
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG] DHCP REQUEST timed out
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[IKE] no virtual IP found for %any requested by 'CN=magrassee.internal.micahrl.com'
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[IKE] peer requested virtual IP %any6
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[IKE] no virtual IP found for %any6 requested by 'CN=magrassee.internal.micahrl.com'
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[IKE] no virtual IP found, sending INTERNAL_ADDRESS_FAILURE
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG] looking for a child config for 0.0.0.0/0 ::/0 === 0.0.0.0/0 ::/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG] proposing traffic selectors for us:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG]  0.0.0.0/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG]  ::/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG] proposing traffic selectors for other:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG]  dynamic
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG]   candidate "ikev2-pubkey" with prio 15+10
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[CFG] found matching child config "ikev2-pubkey" with prio 25
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[IKE] configuration payload negotiation failed, no CHILD_SA built
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[IKE] failed to establish CHILD_SA, keeping IKE_SA
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[ENC] generating IKE_AUTH response 1 [ IDr CERT AUTH N(MOBIKE_SUP) N(ADD_6_ADDR) N(INT_ADDR_FAIL) ]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (696 bytes)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 13[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:23 ip-172-16-254-113 charon: 03[CFG] received DHCP ACK for 10.19.48.106
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] assigning virtual IP 10.19.48.106 to peer 'CN=magrassee.internal.micahrl.com'
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] peer requested virtual IP %any6
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] no virtual IP found for %any6 requested by 'CN=magrassee.internal.micahrl.com'
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] building INTERNAL_IP4_DNS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] building INTERNAL_IP4_DNS attribute
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] looking for a child config for 0.0.0.0/0 ::/0 === 0.0.0.0/0 ::/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] proposing traffic selectors for us:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  0.0.0.0/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  ::/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] proposing traffic selectors for other:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  10.19.48.106/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   candidate "ikev2-pubkey" with prio 15+2
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] found matching child config "ikev2-pubkey" with prio 17
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] selecting proposal:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]   proposal matches
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] received proposals: ESP:AES_GCM_16_128/NO_EXT_SEQ
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] configured proposals: ESP:AES_GCM_16_128/ECP_256/NO_EXT_SEQ, ESP:AES_CBC_128/HMAC_SHA2_512_256/PRF_HMAC_SHA2_512/ECP_256/NO_EXT_SEQ
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] selected proposal: ESP:AES_GCM_16_128/NO_EXT_SEQ
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] got SPI caabb182
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] selecting traffic selectors for us:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  config: 0.0.0.0/0, received: 0.0.0.0/0 => match: 0.0.0.0/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  config: 0.0.0.0/0, received: ::/0 => no match
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  config: ::/0, received: 0.0.0.0/0 => no match
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  config: ::/0, received: ::/0 => match: ::/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG] selecting traffic selectors for other:
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  config: 10.19.48.106/32, received: 0.0.0.0/0 => match: 10.19.48.106/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[CFG]  config: 10.19.48.106/32, received: ::/0 => no match
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] adding SAD entry with SPI caabb182 and reqid {1}  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL]   using encryption algorithm AES_GCM_16 with key size 160
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL]   using replay window of 32 packets
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] adding SAD entry with SPI 4ffa6a26 and reqid {1}  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL]   using encryption algorithm AES_GCM_16 with key size 160
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL]   using replay window of 32 packets
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] adding policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] adding policy 10.19.48.106/32 === 0.0.0.0/0 in  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] adding policy 10.19.48.106/32 === 0.0.0.0/0 fwd  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] getting a local address in traffic selector 0.0.0.0/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] using host %any
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] using 172.16.254.1 as nexthop to reach 136.62.77.151/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] 172.16.254.113 is on interface eth0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] installing route: 10.19.48.106/32 via 172.16.254.1 src %any dev eth0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] getting iface index for eth0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000) already exists, increasing refcount
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] updating policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] policy 10.19.48.106/32 === 0.0.0.0/0 in  (mark 0/0x00000000) already exists, increasing refcount
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] updating policy 10.19.48.106/32 === 0.0.0.0/0 in  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] policy 10.19.48.106/32 === 0.0.0.0/0 fwd  (mark 0/0x00000000) already exists, increasing refcount
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] updating policy 10.19.48.106/32 === 0.0.0.0/0 fwd  (mark 0/0x00000000)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] getting a local address in traffic selector 0.0.0.0/0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] using host %any
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] using 172.16.254.1 as nexthop to reach 136.62.77.151/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[KNL] 172.16.254.113 is on interface eth0
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[IKE] CHILD_SA ikev2-pubkey{1} established with SPIs caabb182_i 4ffa6a26_o and TS 0.0.0.0/0 ::/0 === 10.19.48.106/32
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[ENC] generating IKE_AUTH response 1 [ IDr CERT AUTH CPRP(ADDR DNS DNS) SA TSi TSr N(MOBIKE_SUP) N(ADD_6_ADDR) ]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (856 bytes)
    Apr  8 20:16:23 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[MGR] checkin IKE_SA ikev2-pubkey[4]
    Apr  8 20:16:23 ip-172-16-254-113 charon: 05[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:29 ip-172-16-254-113 charon: 01[MGR] checkout IKE_SA
    Apr  8 20:16:29 ip-172-16-254-113 charon: 01[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:16:29 ip-172-16-254-113 charon: 01[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:29 ip-172-16-254-113 charon: 01[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:39 ip-172-16-254-113 charon: 12[MGR] checkout IKE_SA
    Apr  8 20:16:39 ip-172-16-254-113 charon: 12[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:16:39 ip-172-16-254-113 charon: 12[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:39 ip-172-16-254-113 charon: 12[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:43 ip-172-16-254-113 charon: 11[MGR] checkout IKE_SA
    Apr  8 20:16:43 ip-172-16-254-113 charon: 11[MGR] IKE_SA ikev2-pubkey[4] successfully checked out
    Apr  8 20:16:43 ip-172-16-254-113 charon: 11[KNL] querying policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000)
    Apr  8 20:16:43 ip-172-16-254-113 charon: 11[MGR] checkin IKE_SA ikev2-pubkey[4]
    Apr  8 20:16:43 ip-172-16-254-113 charon: 11[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:44 ip-172-16-254-113 charon: 14[MGR] checkout IKE_SA
    Apr  8 20:16:44 ip-172-16-254-113 charon: 14[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:16:44 ip-172-16-254-113 charon: 14[IKE] sending keep alive to 136.62.77.151[4500]
    Apr  8 20:16:44 ip-172-16-254-113 charon: 14[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:44 ip-172-16-254-113 charon: 14[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:44 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[MGR] checkout IKE_SA
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[IKE] sending DPD request
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[IKE] queueing IKE_DPD task
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[IKE] activating new tasks
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[IKE]   activating IKE_DPD task
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[ENC] generating INFORMATIONAL request 0 [ ]
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:44 ip-172-16-254-113 charon: 15[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:44 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:48 ip-172-16-254-113 charon: 16[MGR] checkout IKE_SA
    Apr  8 20:16:48 ip-172-16-254-113 charon: 16[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:16:48 ip-172-16-254-113 charon: 16[IKE] retransmit 1 of request with message ID 0
    Apr  8 20:16:48 ip-172-16-254-113 charon: 16[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:16:48 ip-172-16-254-113 charon: 16[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:48 ip-172-16-254-113 charon: 16[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:48 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:53 ip-172-16-254-113 charon: 06[MGR] checkout IKE_SA
    Apr  8 20:16:53 ip-172-16-254-113 charon: 06[MGR] IKE_SA ikev2-pubkey[4] successfully checked out
    Apr  8 20:16:53 ip-172-16-254-113 charon: 06[MGR] checkin IKE_SA ikev2-pubkey[4]
    Apr  8 20:16:53 ip-172-16-254-113 charon: 06[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:56 ip-172-16-254-113 charon: 04[MGR] checkout IKE_SA
    Apr  8 20:16:56 ip-172-16-254-113 charon: 04[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:16:56 ip-172-16-254-113 charon: 04[IKE] retransmit 2 of request with message ID 0
    Apr  8 20:16:56 ip-172-16-254-113 charon: 04[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:16:56 ip-172-16-254-113 charon: 04[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:16:56 ip-172-16-254-113 charon: 04[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:56 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[4500] to 172.16.254.113[4500]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[MGR] checkout IKE_SA by message
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[MGR] IKE_SA ikev2-pubkey[4] successfully checked out
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[NET] received packet: from 136.62.77.151[4500] to 172.16.254.113[4500] (88 bytes)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[ENC] parsed INFORMATIONAL request 2 [ D ]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[IKE] received DELETE for ESP CHILD_SA with SPI 4ffa6a26
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] querying SAD entry with SPI caabb182  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] querying SAD entry with SPI 4ffa6a26  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[IKE] closing CHILD_SA ikev2-pubkey{1} with SPIs caabb182_i (71810 bytes) 4ffa6a26_o (275175 bytes) and TS 0.0.0.0/0 ::/0 === 10.19.48.106/32
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[IKE] sending DELETE for ESP CHILD_SA with SPI caabb182
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[IKE] CHILD_SA closed
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] policy still used by another CHILD_SA, not removed
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] updating policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting policy 10.19.48.106/32 === 0.0.0.0/0 in  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] policy still used by another CHILD_SA, not removed
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] updating policy 10.19.48.106/32 === 0.0.0.0/0 in  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting policy 10.19.48.106/32 === 0.0.0.0/0 fwd  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] policy still used by another CHILD_SA, not removed
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] updating policy 10.19.48.106/32 === 0.0.0.0/0 fwd  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] getting a local address in traffic selector 0.0.0.0/0
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] using host %any
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] using 172.16.254.1 as nexthop to reach 136.62.77.151/32
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] 172.16.254.113 is on interface eth0
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting policy 0.0.0.0/0 === 10.19.48.106/32 out  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting policy 10.19.48.106/32 === 0.0.0.0/0 in  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting policy 10.19.48.106/32 === 0.0.0.0/0 fwd  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] getting iface index for eth0
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting SAD entry with SPI caabb182  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleted SAD entry with SPI caabb182 (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleting SAD entry with SPI 4ffa6a26  (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[KNL] deleted SAD entry with SPI 4ffa6a26 (mark 0/0x00000000)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[ENC] generating INFORMATIONAL response 2 [ D ]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[MGR] checkin IKE_SA ikev2-pubkey[4]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 13[MGR] check-in of IKE_SA successful.
    Apr  8 20:16:57 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[4500] to 172.16.254.113[4500]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[MGR] checkout IKE_SA by message
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[MGR] IKE_SA ikev2-pubkey[4] successfully checked out
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[NET] received packet: from 136.62.77.151[4500] to 172.16.254.113[4500] (88 bytes)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[ENC] parsed INFORMATIONAL request 3 [ D ]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[IKE] received DELETE for IKE_SA ikev2-pubkey[4]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[IKE] deleting IKE_SA ikev2-pubkey[4] between 172.16.254.113[52.70.45.223]...136.62.77.151[CN=magrassee.internal.micahrl.com]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[IKE] IKE_SA ikev2-pubkey[4] state change: ESTABLISHED => DELETING
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[IKE] IKE_SA deleted
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[ENC] generating INFORMATIONAL response 3 [ ]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[MGR] checkin and destroy IKE_SA ikev2-pubkey[4]
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[IKE] IKE_SA ikev2-pubkey[4] state change: DELETING => DESTROYING
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[KNL] using 10.19.48.1 as address to reach 10.19.48.1/32
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[CFG] sending DHCP RELEASE for 10.19.48.106 to 10.19.48.1
    Apr  8 20:16:57 ip-172-16-254-113 charon: 02[MGR] check-in and destroy of IKE_SA successful
    Apr  8 20:16:57 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:16:57 ip-172-16-254-113 dnsmasq-dhcp[7530]: DHCPRELEASE(lo) 10.19.48.106 7a:a7:50:5e:b7:61
    Apr  8 20:16:58 ip-172-16-254-113 charon: 05[MGR] checkout IKE_SA
    Apr  8 20:17:01 ip-172-16-254-113 CRON[11989]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)
    Apr  8 20:17:03 ip-172-16-254-113 charon: 01[MGR] checkout IKE_SA
    Apr  8 20:17:04 ip-172-16-254-113 charon: 12[MGR] checkout IKE_SA
    Apr  8 20:17:04 ip-172-16-254-113 charon: 12[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:17:04 ip-172-16-254-113 charon: 12[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:17:04 ip-172-16-254-113 charon: 12[MGR] check-in of IKE_SA successful.
    Apr  8 20:17:09 ip-172-16-254-113 charon: 11[MGR] checkout IKE_SA
    Apr  8 20:17:09 ip-172-16-254-113 charon: 11[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:17:09 ip-172-16-254-113 charon: 11[IKE] retransmit 3 of request with message ID 0
    Apr  8 20:17:09 ip-172-16-254-113 charon: 11[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:17:09 ip-172-16-254-113 charon: 11[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:17:09 ip-172-16-254-113 charon: 11[MGR] check-in of IKE_SA successful.
    Apr  8 20:17:09 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]

## Unsuccessfull macOS connection

    Apr  8 20:18:12 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[1] to 172.16.254.113[500]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[MGR] checkout IKE_SA by message
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[MGR] created IKE_SA (unnamed)[5]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[NET] received packet: from 136.62.77.151[1] to 172.16.254.113[500] (240 bytes)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[ENC] parsed IKE_SA_INIT request 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) N(FRAG_SUP) ]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG] looking for an ike config for 172.16.254.113...136.62.77.151
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG]   candidate: %any...%any, prio 28
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG] found matching ike config: %any...%any with prio 28
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[IKE] 136.62.77.151 is initiating an IKE_SA
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[IKE] IKE_SA (unnamed)[5] state change: CREATED => CONNECTING
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG] selecting proposal:
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG]   proposal matches
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG] received proposals: IKE:AES_GCM_16_128/PRF_HMAC_SHA2_512/ECP_256
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG] configured proposals: IKE:AES_GCM_16_128/PRF_HMAC_SHA2_512/ECP_256, IKE:AES_CBC_128/HMAC_SHA2_512_256/PRF_HMAC_SHA2_512/ECP_256, IKE:AES_CBC_128/HMAC_SHA2_384_192/PRF_HMAC_SHA2_384/ECP_256
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[CFG] selected proposal: IKE:AES_GCM_16_128/PRF_HMAC_SHA2_512/ECP_256
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[IKE] local host is behind NAT, sending keep alives
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[IKE] remote host is behind NAT
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[IKE] sending cert request for "CN=52.70.45.223"
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[ENC] generating IKE_SA_INIT response 0 [ SA KE No N(NATD_S_IP) N(NATD_D_IP) CERTREQ N(FRAG_SUP) N(MULT_AUTH) ]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[NET] sending packet: from 172.16.254.113[500] to 136.62.77.151[1] (273 bytes)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[500] to 136.62.77.151[1]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[MGR] checkin IKE_SA (unnamed)[5]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 02[MGR] check-in of IKE_SA successful.
    Apr  8 20:18:12 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[1024] to 172.16.254.113[4500]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:18:12 ip-172-16-254-113 charon: 09[NET] received packet: from 136.62.77.151[1024] to 172.16.254.113[4500]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 09[NET] waiting for data on sockets
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] checkout IKE_SA by message
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] IKE_SA (unnamed)[5] successfully checked out
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[NET] received packet: from 136.62.77.151[1024] to 172.16.254.113[4500] (540 bytes)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] parsed IKE_AUTH request 1 [ EF(1/2) ]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] received fragment #1 of 2, waiting for complete IKE message
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] checkin IKE_SA (unnamed)[5]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] check-in of IKE_SA successful.
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] checkout IKE_SA by message
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] IKE_SA (unnamed)[5] successfully checked out
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[NET] received packet: from 136.62.77.151[1024] to 172.16.254.113[4500] (468 bytes)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] parsed IKE_AUTH request 1 [ EF(2/2) ]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] received fragment #2 of 2, reassembling fragmented IKE message
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] unknown attribute type (25)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] parsed IKE_AUTH request 1 [ IDi N(INIT_CONTACT) N(MOBIKE_SUP) IDr CERTREQ AUTH CERT CPRQ(ADDR DHCP DNS MASK ADDR6 DHCP6 DNS6 (25)) N(ESP_TFC_PAD_N) N(NON_FIRST_FRAG) SA TSi TSr ]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] received cert request for "CN=52.70.45.223"
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] received end entity cert "CN=andraia.internal.micahrl.com"
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[CFG] looking for peer configs matching 172.16.254.113[52.70.45.223]...136.62.77.151[andraia]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[CFG]   candidate "ikev2-pubkey", match: 20/1/28 (me/other/ike)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[CFG] selected peer config 'ikev2-pubkey'
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] no trusted ECDSA public key found for 'andraia'
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP4_ADDRESS attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP4_DHCP attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP4_DNS attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP4_NETMASK attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP6_ADDRESS attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP6_DHCP attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing INTERNAL_IP6_DNS attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] processing (25) attribute
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] received ESP_TFC_PADDING_NOT_SUPPORTED, not using ESPv3 TFC padding
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] peer supports MOBIKE
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[ENC] generating IKE_AUTH response 1 [ N(AUTH_FAILED) ]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[1024] (65 bytes)
    Apr  8 20:18:12 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[1024]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] checkin and destroy IKE_SA ikev2-pubkey[5]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[IKE] IKE_SA ikev2-pubkey[5] state change: CONNECTING => DESTROYING
    Apr  8 20:18:12 ip-172-16-254-113 charon: 01[MGR] check-in and destroy of IKE_SA successful
    Apr  8 20:18:12 ip-172-16-254-113 charon: 12[MGR] checkout IKE_SA
    Apr  8 20:18:12 ip-172-16-254-113 charon: 12[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:18:12 ip-172-16-254-113 charon: 12[IKE] sending keep alive to 136.62.77.151[4500]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 12[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:18:12 ip-172-16-254-113 charon: 12[MGR] check-in of IKE_SA successful.
    Apr  8 20:18:12 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]
    Apr  8 20:18:14 ip-172-16-254-113 charon: 11[MGR] checkout IKE_SA
    Apr  8 20:18:14 ip-172-16-254-113 charon: 11[MGR] IKE_SA ikev2-pubkey[3] successfully checked out
    Apr  8 20:18:14 ip-172-16-254-113 charon: 11[IKE] retransmit 5 of request with message ID 0
    Apr  8 20:18:14 ip-172-16-254-113 charon: 11[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500] (88 bytes)
    Apr  8 20:18:14 ip-172-16-254-113 charon: 11[MGR] checkin IKE_SA ikev2-pubkey[3]
    Apr  8 20:18:14 ip-172-16-254-113 charon: 11[MGR] check-in of IKE_SA successful.
    Apr  8 20:18:14 ip-172-16-254-113 charon: 10[NET] sending packet: from 172.16.254.113[4500] to 136.62.77.151[4500]

## Solved macOS connection problem

I had to change the LocalIdentifier in the mobileconfig to include the VPN domain as well, then it connected.

However, just like Windows, it was not getting the right IP address

## dhcp-host entries in dnsmasq.conf

    dhcp-host=id:30:20:31:1e:30:1c:06:03:55:04:03:0c:15:61:6e:64:72:61:69:61:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34,10.19.48.51,andraia.internal.micahrl.com
    dhcp-host=id:30:1f:31:1d:30:1b:06:03:55:04:03:0c:14:67:6c:69:74:63:68:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34,10.19.48.52,glitch.internal.micahrl.com
    dhcp-host=id:30:26:31:24:30:22:06:03:55:04:03:0c:1b:63:65:72:74:69:63:61:6c:61:70:74:6f:70:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34,10.19.48.53,certicalaptop.internal.micahrl.com
    dhcp-host=id:30:22:31:20:30:1e:06:03:55:04:03:0c:17:61:72:63:68:69:74:65:63:74:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34,10.19.48.54,architect.internal.micahrl.com
    dhcp-host=id:30:21:31:1f:30:1d:06:03:55:04:03:0c:16:6e:75:76:69:73:69:6f:6e:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34,10.19.48.55,nuvision.internal.micahrl.com
    dhcp-host=id:30:22:31:20:30:1e:06:03:55:04:03:0c:17:6d:61:67:72:61:73:73:65:65:2e:31:30:2e:31:39:2e:34:38:2e:30:2f:32:34,10.19.48.56,magrassee.internal.micahrl.com

              id:30:29:31:27:30:25:06:03:55:04:03:0c:1e:6d:61:67:72:61:73:73:65:65:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d

## dhcpdump when Andraia connects

    TIME: 2018-04-08 20:25:28.281
        IP: 10.19.48.1 (0:0:0:0:0:0) > 10.19.48.1 (0:0:0:0:0:0)
        OP: 1 (BOOTPREQUEST)
    HTYPE: 1 (Ethernet)
    HLEN: 6
    HOPS: 0
    XID: 199ef74f
    SECS: 0
    FLAGS: 0
    CIADDR: 0.0.0.0
    YIADDR: 0.0.0.0
    SIADDR: 0.0.0.0
    GIADDR: 10.19.48.1
    CHADDR: 7a:a7:d2:b3:25:66:00:00:00:00:00:00:00:00:00:00
    SNAME: .
    FNAME: .
    OPTION:  53 (  1) DHCP message type         1 (DHCPDISCOVER)
    OPTION:  12 ( 28) Host name                 andraia.internal.micahrl.com
    OPTION:  61 ( 28) Client-identifier         61:6e:64:72:61:69:61:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d
    OPTION:  55 (  2) Parameter Request List      6 (DNS server)
                            44 (NetBIOS name server)
                            
    ---------------------------------------------------------------------------

    TIME: 2018-04-08 20:25:28.281
        IP: 10.19.48.1 (0:0:0:0:0:0) > 10.19.48.1 (0:0:0:0:0:0)
        OP: 2 (BOOTPREPLY)
    HTYPE: 1 (Ethernet)
    HLEN: 6
    HOPS: 0
    XID: 199ef74f
    SECS: 0
    FLAGS: 0
    CIADDR: 0.0.0.0
    YIADDR: 10.19.48.94
    SIADDR: 10.19.48.1
    GIADDR: 10.19.48.1
    CHADDR: 7a:a7:d2:b3:25:66:00:00:00:00:00:00:00:00:00:00
    SNAME: .
    FNAME: .
    OPTION:  53 (  1) DHCP message type         2 (DHCPOFFER)
    OPTION:  54 (  4) Server identifier         10.19.48.1
    OPTION:  51 (  4) IP address leasetime      43200 (12h)
    OPTION:  58 (  4) T1                        21600 (6h)
    OPTION:  59 (  4) T2                        37800 (10h30m)
    OPTION:   1 (  4) Subnet mask               255.0.0.0
    OPTION:  28 (  4) Broadcast address         10.19.48.1
    OPTION:   6 (  4) DNS server                10.19.48.1
    ---------------------------------------------------------------------------

    TIME: 2018-04-08 20:25:28.281
        IP: 10.19.48.1 (0:0:0:0:0:0) > 10.19.48.1 (0:0:0:0:0:0)
        OP: 1 (BOOTPREQUEST)
    HTYPE: 1 (Ethernet)
    HLEN: 6
    HOPS: 0
    XID: 199ef74f
    SECS: 0
    FLAGS: 0
    CIADDR: 0.0.0.0
    YIADDR: 0.0.0.0
    SIADDR: 0.0.0.0
    GIADDR: 10.19.48.1
    CHADDR: 7a:a7:d2:b3:25:66:00:00:00:00:00:00:00:00:00:00
    SNAME: .
    FNAME: .
    OPTION:  53 (  1) DHCP message type         3 (DHCPREQUEST)
    OPTION:  12 ( 28) Host name                 andraia.internal.micahrl.com
    OPTION:  61 ( 28) Client-identifier         61:6e:64:72:61:69:61:2e:69:6e:74:65:72:6e:61:6c:2e:6d:69:63:61:68:72:6c:2e:63:6f:6d
    OPTION:  50 (  4) Request IP address        10.19.48.94
    OPTION:  54 (  4) Server identifier         10.19.48.1
    OPTION:  55 (  2) Parameter Request List      6 (DNS server)
                            44 (NetBIOS name server)
                            
    ---------------------------------------------------------------------------

    TIME: 2018-04-08 20:25:28.281
        IP: 10.19.48.1 (0:0:0:0:0:0) > 10.19.48.1 (0:0:0:0:0:0)
        OP: 2 (BOOTPREPLY)
    HTYPE: 1 (Ethernet)
    HLEN: 6
    HOPS: 0
    XID: 199ef74f
    SECS: 0
    FLAGS: 0
    CIADDR: 0.0.0.0
    YIADDR: 10.19.48.94
    SIADDR: 10.19.48.1
    GIADDR: 10.19.48.1
    CHADDR: 7a:a7:d2:b3:25:66:00:00:00:00:00:00:00:00:00:00
    SNAME: .
    FNAME: .
    OPTION:  53 (  1) DHCP message type         5 (DHCPACK)
    OPTION:  54 (  4) Server identifier         10.19.48.1
    OPTION:  51 (  4) IP address leasetime      43200 (12h)
    OPTION:  58 (  4) T1                        21600 (6h)
    OPTION:  59 (  4) T2                        37800 (10h30m)
    OPTION:   1 (  4) Subnet mask               255.0.0.0
    OPTION:  28 (  4) Broadcast address         10.19.48.1
    OPTION:   6 (  4) DNS server                10.19.48.1
    ---------------------------------------------------------------------------

