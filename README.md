# torspray
A console utility to bring up new Tor nodes easily


### Usage

1) check out repository: `git clone https://github.com/gergelykalman/torspray.git`
2) cd to the repository's root: `cd torspray`
3) install paramiko: `pip install paramiko`
4) run torspray for the first time: `python torspray`
5) generate ssh keys for torspray: `ssh-keygen -f ./.torspray/torspray_key -t rsa -b 4096 -N ""`

In the future key generation will be done by torspray
