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
For instance, I'm using AWS, and when I added `dns_vpnclients_route53` and `dns_vpnserver_route53`,
I didn't also add `dns_gcp` or `dns_azure` along with it.
I also am not going to maintain the `algo` script, so you should deploy from Ansible (see below).
That said, I don't want to outright _remove_ that functionality, because it will make merging from upstream harder.
So, it may rot. I'm ok with that.
I will document changes and my user here, and anyone who wants to use this as a jumping-off point will have to mind the sharp edges.

### Misc stuff

 -  My values are committed in `config.cfg`

 -  Encrypted `configs.tar.gz.gpg` (see below)

 -  Logging is added to `ansible.cfg`

 -  Using the `newtroy.py` script,
    the `configs/` dir is automatically encrypted and saved to `configs.tar.gz.gpg` on successful deployment,
    and that encrypted archive is automatically decrypted and extracted to `configs/` before deployment.

### Resolving client hosts with dnsmasq

Added support for dnsmasq to resolve client hosts when `dns_adblocking` is enabled and `newtroy_vpn_internal_domain` is specified.

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

Added support to update Route53 if `newtroy_vpn_internal_domain` and `newtroy_vpn_internal_hosted_zone_id` is specified.

This is much better than my previous solution (with dnsmasq, above) because it will let me use Let's Encrypt with an ACME client that supports DNS attestation.
(Aside: I need to use DNS attestation for non-public hosts, because I cannot use HTTP attestation because, well, they're non public.)

There are two components to this as well

1.  The same as the first component in the dnsmasq solution
2.  I added a new `dns_vpnclients_route53` role,
    controlled by a new `dns_vpnclients_route53` tag,
    that sets DNS names in Route53 to the internal (RFC1918) VPN IP addresses

### Use of Ansible vault

I use Ansible vault for sensitive values,
allowing me to commit them in an encrypted form to the repository.
I use GPG to unlock the vault.

For the setup:

1. Generate a vault passphrase, and save it to a GPG-encrypted file

        openssl rand -hex 64 | gpg --encrypt --output .vault-passphrase.gpg --recipient 'conspirator@PSYOPS'

2. Add the `.vault-pass-script` file as it exists in this repo, and make sure it is executable

3. Modify the `ansible.cfg` file to include a `vault_password_file` line as is done in this repo

4. Run `ansible-vault create config.vault.cfg` to create the vault the first time

5. Run `ansible-vault edit config.vault.cfg` to edit it later

See also: https://benincosa.com/?p=3235

## Deploying

As I said above, I am not maintaining the `algo` script.

However, I have created a new `newtroy.py` script,
which uses Ansible to deploy with all of my defaults.

See `newtroy.py --help` for details on how to use it.

Once more, for emphasis: **Don't use the `algo` script.**

### Deploying production

This is very easy, just do

    ./newtroy.py deploy production

Note that this will automatically decrypt the configs archive in `configs.tar.gz.gpg`
and extract it to `configs/` first,
then it will run the deployment,
and then it will compress and encrypt the resulting `configs/` directory,
and save the resulting archive back to `configs.tar.gz.gpg`.

See below for more information about working with the encrypted configs archive,
including how to view a diff of changes.

The script makes some effort only to save changes to content -
while `tar` does track metadata like last updated time,
the script will not automatically re-encrypt the configs if the file _content_ has not changed.
(But again, see below for more information,
including instructions on how to tell it to encrypt the configs explicitly,
which will always save the tar file even if only metadata has changed.)

### Deploying a testing environment

I sometimes use DigitalOcean for testing.
For testing deployments, we do not update Route53.
To deploy to testing, you can run `./newtroy.py deploy testing`.

I have also designed this to work with the master branch of upstream Algo directly.
To use it, check out the upstream master branch and then copy the files from the newtroy branch:

    git checkout upstream/master
    git checkout origin/newtroy -- \
        ansible.cfg \
        config.cfg \
        config.vault.cfg \
        config.test.cfg \
        config.test.vault.cfg \
        .vault-pass-script \
        .vault-passphrase.gpg \
        newtroy.py

## Working with encrypted configs

We save an encrypted archive of contents of the `configs/` directory to git.

1.  Encrypt the `configs` dir to `configs.tar.gz.gpg`:
    `./newtroy.py config encrypt`
2.  Decrypt the `configs.tar.gz` archive to `configs/`:
    `./newtroy config decrypt`
3.  View the difference between the contents of the `configs/` dir _as it exists on disk_
    and the contents of the `configs.tar.gz.gpg` archive _as it was committed to git_
    (that is, not the version as it may exist on disk which might have uncommitted changes):
    `./newtroy config gitdiff | less`

### Experimental settings

I have run some experiments with additional settings,
and record their results here.
These settings are NOT saved in `config.cfg`/`newtroy`.

1.  Environment: `-e max_mss=1316`: (EXPERIMENTAL) this is set for GCP deployments in upstream Algo by default, and can apparently resolve some MTU issues.

    See also:
     -   https://github.com/trailofbits/algo/pull/185 (which claims EC2 is not affected)
     -   https://github.com/trailofbits/algo/issues/686 (which claims EC2 might be affected after all)

    Update: Based on
    [this](https://trailofbits.github.io/algo/troubleshooting.html#various-websites-appear-to-be-offline-through-the-vpn),
    my guess is now that modifying MTU was not related to my problem.

## Misc

1. Not enabling "VPN On Demand" for macOS/iOS clients for now. If enabled, it will connect to VPN automatically unless on trusted wifi, which means if my VPN server goes down I can't use wifi. (Can enable for cellular too, with the same effect over that network.)

## TO DO

Stuff I want for me:

 -  Some way to use Ansible Vault to store the whole configs/ directory ?

Stuff I have that I could consider PRing:

 -  Allow the `CA_password` to be passed in from the vault
    (see `playbooks/facts/main.yml`).

 -  Rename the misspelled `ipec` file(s)

Stuff I want for me that could go upstream:

 -  Document exactly the necessary permissions Algo needs to deploy to AWS
    (and generate an IAM account with those creds)

 -  Generate SSH host key client-side.
    Not possible to securely upload it,
    but could reduce attack surface by requiring that a MITM actively intercept the first SSH connection
    and then maintain that active intercept for all subsequent connections

 -  Support a domain name for the VPN endpoint.
    Lots of people ask for this mostly for aesthetic reasons.
    However, I want it so that I can tear down my infrastructure and redeploy with the same server cert.
    (See next item.)

 -  Support deploying generated PKI to brand new VMs.
    Currently, if you tear down your Algo server,
    you have to delete `configs/*`, redeploy, regenerate keys, and redistribute them to your clients.
    Would be very useful if I could keep my configuration (the PKI)
    even as I tear down my infrastructure (the VMs).