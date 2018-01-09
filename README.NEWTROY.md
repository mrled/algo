# NEWTROY - mrled's VPN server

More or less following official documentation. Some notes:

1. I'm using system Python (since it has to be Python2, ugh), so all `python` commands are `/usr/bin/python`

2. Not enabling "VPN On Demand" for macOS/iOS clients for now. If enabled, it will connect to VPN automatically unless on trusted wifi, which means if my VPN server goes down I can't use wifi. (Can enable for cellular too, with the same effect over that network.)

3. Deploying from Ansible vs deploying from the `algo` script

    The first time around, I deployed from Ansible, without using the `algo` script from this repo:

        AWS_ACCESS_KEY=whatever
        AWS_SECRET_KEY=whatever
        ansible-playbook deploy.yml -t ec2,vpn,cloud,security,encrypted -e "aws_access_key=$AWS_ACCESS_KEY aws_secret_key=$AWS_SECRET_KEY aws_server_name=newtroy region=us-east-2 Win10_Enabled=Y Store_CAKEY=Y"

    The second time, I redeployed using the `algo` script:

        ./algo

    Both seemed to work fine. It appears to have kept the same IP address, but terminated the old EC2 VM and provisioned a new one.

4. Redeploying

    When deploying to a machine that has already been deployed to, it will re-encrypt the CA key and all client keys. However, it will not re-key the CA; the old client profiles are still valid.

    For this reason, there's not much point in saving the CA or client key passphrases. If you forget them, you can just regenerate them by redeploying and reconfigure the clients.

5.  Encrypted configs

    The `configs` directory is tar'd, gzip'd, gpg'd, and committed to the repository.

    To decrypt and extract:

        rm -rf configs; gpg --decrypt configs.tar.gz.gpg | gunzip | tar x

    To compress and encrypt:

        tar -c configs | gzip | gpg --recipient conspirator@PSYOPS --encrypt --output configs.tar.gz.gpg
