# NEWTROY - mrled's VPN server

More or less following official documentation, but noting differences here.

1. I'm using system Python (since it has to be Python2, ugh), so all `python` commands are `/usr/bin/python`

2. Not enabling "VPN On Demand" for macOS/iOS clients for now. If enabled, it will connect to VPN automatically unless on trusted wifi, which means if my VPN server goes down I can't use wifi. (Can enable for cellular too, with the same effect over that network.)

3. I deployed from Ansible, without using the `algo` script from this repo, but I don't know that I gained anything from doing that

        AWS_ACCESS_KEY=whatever
        AWS_SECRET_KEY=whatever
        ansible-playbook deploy.yml -t ec2,vpn,cloud,security,encrypted -e "aws_access_key=$AWS_ACCESS_KEY aws_secret_key=$AWS_SECRET_KEY aws_server_name=newtroy region=us-east-2 Win10_Enabled=Y Store_CAKEY=Y"
