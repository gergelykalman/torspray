# torspray
A console utility to bring up new Tor nodes easily

### Current progress
Works:
- key generation
- node management commands
- file copy
- command execution on one or all nodes
- automatic configuration of tor on the node

Works in progress:
- meaningful statistics
- ability to compile torspray to a standalone executable
- password login support


### Why?
This tool is meant to empower less tech-savvy users to be able to quickly and effortlessly
bring up tor nodes to help out the network in times of crisis.


### What do I need?
- You will need a virtual machine (VM) with Debian 11 at a hosting provider. I use Hetzner.
- On installation, specify the ssh key that torspray generates. Passwords support doesn't yet work unfortunately.
  - if you don't remember, run `python torspray.py showpubkey`
- Once the server is provisioned you can add it to torspray to manage


### Bugs
The software is in very early stages if you encounter problems, open a github issue
or DM me on twitter @gergely_kalman


### Installation

```bash
$ mkdir torspray
$ cd torspray
$ python3 -m venv venv
$ . ./venv/bin/activate
$ pip install paramiko
$ git clone https://github.com/gergelykalman/torspray.git
$ cd torspray
$ python torspray.py
```

### Usage example

initialization:
```bash
$ python torspray.py init pleaseuseaproperemailhere@example.com
[+] Initializing torspray directory: /home/synapse/projects/development/torspray/code/.torspray
[+] Generating SSH keys
Basic configuration written, SSH key generated:
##################################################
#        Use this key when creating the VM:      #
##################################################
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrMjEtbW/rkbf50kkpejiftyc5SLARU/GFaYusWGBqeRdxhlhipgov5bJQ3BTlZP/3GJZZQg7rqGwv4cR3WNQuqSwjgYIGqT1NNjmyNiJxhDkr1RVIhpDnaQ+odsA4hoIFcMq5Y/Ll/ODn8b4jRJ/DuzZ06tPFmKnmHGWh/E/LfcASUpx00Wbzej2Gb5T/PCs1uq/CO7JxlNzzLT+sz4W3vsEZ1w6HSXPrxnNvrQFFsxBj1CsoI9gH3Ncsroc7f6/LXHGTWIXqns0c8cSbWFPw1yIwBPCa51X2hJHRj9XtOS+wvt/2XtWikp5qd8Zq5aa5m4sqG8/iJYcZOG0TyMXhCqjnrRjflj/ryD7ToUmrzx4LKM0fqnIqloR+TX1mWDTmiHj7yNycXxKPUF0wl0id8uMdtnjJW3A4knr2F/cvu1qrqVJeRCb3SZcYfpIazUwsmOeTYGx8JMqHAalt6nucpjXzlppHIHAqp/1eAskTLSOTdWEBLwDScGgS8ERjfRuE0ICLe1oh92iXQPuQyM+CHyN9sF2evzhPTwAmlEmfjxYtTmd9rFxYzq2VTHWuDAuf/IrDmKr9OoD9Imrr9J0wInlj7QOWExryGeRuBqxAvvEoC83iwWq8ogaO86vGHK6ETDQ7hHVX914zlLq3G6cN/yiRBlpCJCUwqvLZdS48Pw== torspray-8b9932c2@home
```

Adding nodes, VMs might take time to come up, so have to retry:
```
$ python torspray.py add testnode 65.108.217.166
[+] Adding server 65.108.217.166, password: None
[-] Failed to reach server, try again later

$ python torspray.py add testnode 65.108.217.166
[+] Adding server 65.108.217.166, password: None
We have:
	username root
	hostname debian-2gb-hel1-1
```

Listing nodes:
```
$ python torspray.py list
[+] Servers in the DB:
	testnode: {'address': '65.108.217.166', 'hostname': 'testnode'}
```

Installing tor bridge on node (log was cut short):
```
$ python torspray.py spray testnode
[+] Spray verifying versions
$ dpkg --print-architecture
amd64
	version: Debian GNU/Linux
	codename: bullseye
	arch: amd64
[+] Spray enabling updates
...
$ systemctl restart tor.service
```

Testing execute on node 'testnode'
```
$ python torspray.py node-exec testnode 'hostname'
[+] Execing: hostname
testnode:
debian-2gb-hel1-1
```

Showing pubkey because I forgot:
```
$ python torspray.py showpubkey
##################################################
#        Use this key when creating the VM:      #
##################################################
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrMjEtbW/rkbf50kkpejiftyc5SLARU/GFaYusWGBqeRdxhlhipgov5bJQ3BTlZP/3GJZZQg7rqGwv4cR3WNQuqSwjgYIGqT1NNjmyNiJxhDkr1RVIhpDnaQ+odsA4hoIFcMq5Y/Ll/ODn8b4jRJ/DuzZ06tPFmKnmHGWh/E/LfcASUpx00Wbzej2Gb5T/PCs1uq/CO7JxlNzzLT+sz4W3vsEZ1w6HSXPrxnNvrQFFsxBj1CsoI9gH3Ncsroc7f6/LXHGTWIXqns0c8cSbWFPw1yIwBPCa51X2hJHRj9XtOS+wvt/2XtWikp5qd8Zq5aa5m4sqG8/iJYcZOG0TyMXhCqjnrRjflj/ryD7ToUmrzx4LKM0fqnIqloR+TX1mWDTmiHj7yNycXxKPUF0wl0id8uMdtnjJW3A4knr2F/cvu1qrqVJeRCb3SZcYfpIazUwsmOeTYGx8JMqHAalt6nucpjXzlppHIHAqp/1eAskTLSOTdWEBLwDScGgS8ERjfRuE0ICLe1oh92iXQPuQyM+CHyN9sF2evzhPTwAmlEmfjxYtTmd9rFxYzq2VTHWuDAuf/IrDmKr9OoD9Imrr9J0wInlj7QOWExryGeRuBqxAvvEoC83iwWq8ogaO86vGHK6ETDQ7hHVX914zlLq3G6cN/yiRBlpCJCUwqvLZdS48Pw== torspray-8b9932c2@home
```

Adding and spraying 2nd node:
```
$ python torspray.py add testnode2 65.108.150.86
[+] Adding server 65.108.150.86, password: None
We have:
	username root
	hostname debian-2gb-hel1-2

$ python torspray.py spray testnode2
[+] Spray verifying versions
...

```

Executing 'hostname' on all nodes we know about:
```
$ python torspray.py cluster-exec 'hostname'
[+] Execing: hostname
testnode:
debian-2gb-hel1-1
testnode2:
debian-2gb-hel1-2
```
