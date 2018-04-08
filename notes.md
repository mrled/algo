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
