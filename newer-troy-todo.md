A list of to do items

## Changed files

    # mb=$(git merge-base upstream/master origin/newtroy)
    # git diff --name-only ${mb}..newtroy

Generates this list, which I've migrated:

- .gitignore
- .travis.yml
- .vault-pass-script
- .vault-passphrase.gpg
- README.NEWTROY.md
- ansible.cfg
- config.cfg => config.newtroy.cfg
- config.test.cfg
- config.test.vault.cfg
- config.vault.cfg
- configs.tar.gz.gpg
- deploy.yml => various new playbooks
- filter_plugins/newtroy_nbuuid.py
- newtroy.py
- playbooks/facts/main.yml => dispersed around
- playbooks/win_script_rebuild.yml
- requirements.txt
- roles/dns_adblocking/tasks/main.yml => skipping this whole role b/c it's done by dns_vpn_*_route53 roles now
- roles/dns_adblocking/templates/dnsmasq.conf.j2
- roles/dns_adblocking/templates/etc.hosts.ipsecclients.j2
- roles/dns_adblocking/templates/usr.sbin.dnsmasq.j2
- roles/client/tasks/main.yml
- roles/dns_vpn_internal_network_route53/defaults/main.yml
- roles/dns_vpn_internal_network_route53/tasks/main.yml
- roles/dns_vpn_internal_network_route53/templates/stack.yml.j2
- roles/dns_vpn_server_route53/defaults/main.yml
- roles/dns_vpn_server_route53/tasks/main.yml
- roles/ssh_tunneling/tasks/main.yml -- skipping this whole role, will implement ssh-keyscan elsewhere
- roles/ssh_tunneling/templates/ssh_config.j2
- roles/vpn/tasks/client_configs.yml
- roles/vpn/tasks/distribute_keys.yml
- roles/vpn/tasks/openssl.yml
- roles/vpn/templates/client_ipsec.conf.j2
- roles/vpn/templates/client_ipsec.secrets.j2
- roles/vpn/templates/client_windows.ps1.j2
- roles/vpn/templates/ipsec.conf.j2
- roles/vpn/templates/ipsec.secrets.j2
- roles/vpn/templates/mobileconfig.j2
- roles/vpn/templates/openssl.cnf.j2
- roles/vpn/templates/sswan.j2

## Other notes

- modify wireguard role to connect to hostname, not IP address
- originally thought I wouldn't need to change configs/{{ IP_subject_alt_name }} but actually I do b/c I don't want that to change when I redeploy - rip that out and replace it with something that uses a hostname or something
- actually, more generally, ensure that IP_subject_alt_name is used only for that purpose, and isn't scattered everywhere

UPDATE: ACTUALLY I THINK I DON'T NEED THIS IF I SET `endpoint`!

## Other other notes

- update readme
- test with endpoint
- use vars instead of tags for my custom roles in cloud.yml, mimmicking new algo pattern
- ssh-keyscan the remote server in a new role, so we don't have to worry about ssh_tunneling
- ensure test configure still works - i think it might not
