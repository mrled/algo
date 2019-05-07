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

## Other other notes

- use vars instead of tags for my custom roles in cloud.yml, mimmicking new algo pattern
- test wireguard
