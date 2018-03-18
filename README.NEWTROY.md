# NEWTROY - mrled's VPN server

This is a fork of the algo project, specific to me.

## Use with PSYOPS

Make sure to use python2 and set it up as described in `README.md`

To use from PSYOPS, you have to use python2 and set it up more or less the way the README says to set up macOS:

(Note: use a `env.PSYOPS` directory, instead of just `env`, in case I need to use it from the Docker host as well.)

    python2 -m ensurepip --user
    python2 -m pip install --user --upgrade virtualenv
    python2 -m virtualenv env.PSYOPS && source env.PSYOPS/bin/activate && python -m pip install -U pip && python -m pip install -r requirements.txt

Later, as long as the `env.PSYOPS` directory still exists, you can just do

    source env.PSYOPS/bin/activate

## Differences from upstream

As I make my own modifications, some bits that I don't use may rot a little.
For instance, I'm using AWS, and when I added `dns_route53`, I didn't also add `dns_gcp` or `dns_azure` along with it.
I also am not going to maintain the `algo` script, so you should deploy from Ansible (see below).
That said, I don't want to outright _remove_ that functionality, because it will make merging from upstream harder.
So, it may rot. I'm ok with that.
I will document changes and my user here, and anyone who wants to use this as a jumping-off point will have to mind the sharp edges.

### Misc stuff

- My values are committed in `config.cfg`
- Encrypted `configs.tar.gz.gpg` (see below)
- Logging is added to `ansible.cfg`

### Resolving client hosts with dnsmasq

Added support for dnsmasq to resolve client hosts when `dns_adblocking` is enabled and `vpn_domain` is specified.

There are two components here:

1. Modify `ipsec.conf` to create a separate connection for each user
2. Add an `/etc/hosts.ipsecclients` file that dnsmasq uses as a hosts file to map IP addresses to hostnames

The first component necessitated a breaking change from upstream,
where new connections that use the same certificate as an existing connection _disconnect_ the existing connection.
This was necessary because IP addresses are now mapped to users,
so there isn't a good way to allow a user to maintain multiple connections -
how would the DNS server know what IP address to use?
I don't think this is a big deal,
because I create a separate Algo user
(resulting in a separate certificate and private key)
for each device,
figuring I can revoke a device if it gets compromised
without having to redistribute keys to all other devices.

Also, it seems that Strongswan clients send their id as `/CN=USER`,
but other clients like macOS and iOS send simply `USER`.
Therefore, I made a modification to the `ipsec_$user.conf` files,
which can be used by a Strongswan client,
to send the ID as simply `USER`.

### Resolving client hosts with Route53

Added support to update Route53 if `vpn_domain` and `vpn_hosted_zone_id` is specified.

This is much better than my previous solution (with dnsmasq, above) because it will let me use Let's Encrypt with an ACME client that supports DNS attestation.
(Aside: I need to use DNS attestation for non-public hosts, because I cannot use HTTP attestation because, well, they're non public.)

There are two components to this as well

1. The same as the first component in the dnsmasq solution
2. I added a new `dns_route53` role, controlled by a new `dns_route53` tag, that invokes the Ansible Route53 module

For now, I didn't get very clever with the second component.
It just creates the records if one of the same name doesn't exist, or updates them if it does exist.
If the zone already has a record with the same IP address but a different name, it will not get removed.

**Rough edges**

1.  Old records are not removed, possibly leading to confusion.
    Solution: just fix this by hand

## Deploying from Ansible

As I said above, I am not maintaining the `algo` script, so deployments should be done from Ansible.

**Deploy from Ansible. Don't use the `algo` script.**

This is how I deploy:

    AWS_ACCESS_KEY=whatever
    AWS_SECRET_KEY=whatever
    CA_PASS=whatever
    CLIENT_PASS=whatever
    ansible-playbook deploy.yml -t ec2,vpn,cloud,security,encrypted,ssh_tunneling,dns_route53 -e "aws_access_key=$AWS_ACCESS_KEY aws_secret_key=$AWS_SECRET_KEY easyrsa_CA_password=$CA_PASS p12_export_password=$CLIENT_PASS"

Tags:

1. `ec2`: required for AWS
2. `vpn`: required
3. `cloud`
4. `security`
5. `encrypted`: some AWS specific thing, I think it's encrypting the EBS disk but honestly what is the threat model here
6. `ssh_tunneling`: enable SSH tunneling, which saves a `known_hosts` file inside the `configs/` directory
7. `dns_route53`: enable route53 DNS

Environment settings:

1. `aws_access_key`
2. `aws_secret_key`
3. `easyrsa_CA_password`: if you have added a user to `config.cfg` and are redeploying, you MUST pass this with the value that Algo generated or else you'll get an error like `unable to load CA private key`. If it's your first time deploying, you can leave this blank causing Algo to generate a password for you and display it at the end.
4. `p12_export_password`: this is just a nice thing to pass in so my fucking client PKCS12 certificate passwords don't change every fucking time I redeploy

Experimental settings

1.  Environment: `max_mss=1316`: (EXPERIMENTAL) this is set for GCP deployments in upstream Algo by default, and can apparently resolve some MTU issues.

    See also:
     -   https://github.com/trailofbits/algo/pull/185 (which claims EC2 is not affected)
     -   https://github.com/trailofbits/algo/issues/686 (which claims EC2 might be affected after all)

    Update: Based on
    [this](https://trailofbits.github.io/algo/troubleshooting.html#various-websites-appear-to-be-offline-through-the-vpn),
    my guess is now that modifying MTU was not related to my problem.


## Redeployment notes

It appear to keep the same (Elastic) IP address, but terminates the old EC2 VM and provisions a new one.

When deploying to a machine that has already been deployed to, it will re-encrypt the CA key and all client keys. However, it will not re-key the CA; the old client profiles are still valid.

For this reason, there's not much point in saving the CA or client key passphrases. If you forget them, you can just regenerate them by redeploying and reconfigure the clients.

## Troubleshooting

SSH using the administrative user (not one of your VPN client users, which have SSH tunneling but no shell access) like so:

    algoserver=1.2.3.4
    ssh -o "UserKnownHostsFile=configs/$algoserver/known_hosts" -i configs/algo.pem -l ubuntu "$algoserver"

## Working with the encrypted configs

The `configs` directory is tar'd, gzip'd, gpg'd, and committed to the repository.

To decrypt and extract:

    ./cryptconfig.sh decrypt

To compress and encrypt:

    ./cryptconfig.sh encrypt

## Misc

1. Not enabling "VPN On Demand" for macOS/iOS clients for now. If enabled, it will connect to VPN automatically unless on trusted wifi, which means if my VPN server goes down I can't use wifi. (Can enable for cellular too, with the same effect over that network.)

## TO DO

Stuff I want for me:

 -  Use Ansible Vault to store secrets so I don't have to pass them as variables?
 -  Some way to use Ansible Vault to store the whole configs/ directory ?

Stuff I want for me that could go upstream:

 -  Document exactly the necessary permissions Algo needs to deploy to AWS
    (and generate an IAM account with those creds)