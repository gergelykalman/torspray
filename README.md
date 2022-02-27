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
  - if you don't remember, run `torspray showpubkey`
- Once the server is provisioned you can add it to torspray to manage


### Bugs
The software is in very early stages if you encounter problems, open a github issue
or DM me on twitter @gergely_kalman


### Installation

```bash
$ pip install torspray
```

### Usage example

initialization:
```bash
$ torspray init pleaseuseaproperemailhere@example.com
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
$ torspray add testnode 65.108.217.166
[+] Adding server 65.108.217.166, password: None
[-] Failed to reach server, try again later

$ torspray add testnode 65.108.217.166
[+] Adding server 65.108.217.166, password: None
We have:
	username root
	hostname debian-2gb-hel1-1
```

Listing nodes:
```
$ torspray list
[+] Servers in the DB:
	testnode: {'address': '65.108.217.166', 'hostname': 'testnode'}
```

Installing tor bridge on node (log was cut short):
```
$ torspray spray testnode
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
$ torspray node-exec testnode 'hostname'
[+] Execing: hostname
testnode:
debian-2gb-hel1-1
```

Showing pubkey because I forgot:
```
$ torspray showpubkey
##################################################
#        Use this key when creating the VM:      #
##################################################
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDrMjEtbW/rkbf50kkpejiftyc5SLARU/GFaYusWGBqeRdxhlhipgov5bJQ3BTlZP/3GJZZQg7rqGwv4cR3WNQuqSwjgYIGqT1NNjmyNiJxhDkr1RVIhpDnaQ+odsA4hoIFcMq5Y/Ll/ODn8b4jRJ/DuzZ06tPFmKnmHGWh/E/LfcASUpx00Wbzej2Gb5T/PCs1uq/CO7JxlNzzLT+sz4W3vsEZ1w6HSXPrxnNvrQFFsxBj1CsoI9gH3Ncsroc7f6/LXHGTWIXqns0c8cSbWFPw1yIwBPCa51X2hJHRj9XtOS+wvt/2XtWikp5qd8Zq5aa5m4sqG8/iJYcZOG0TyMXhCqjnrRjflj/ryD7ToUmrzx4LKM0fqnIqloR+TX1mWDTmiHj7yNycXxKPUF0wl0id8uMdtnjJW3A4knr2F/cvu1qrqVJeRCb3SZcYfpIazUwsmOeTYGx8JMqHAalt6nucpjXzlppHIHAqp/1eAskTLSOTdWEBLwDScGgS8ERjfRuE0ICLe1oh92iXQPuQyM+CHyN9sF2evzhPTwAmlEmfjxYtTmd9rFxYzq2VTHWuDAuf/IrDmKr9OoD9Imrr9J0wInlj7QOWExryGeRuBqxAvvEoC83iwWq8ogaO86vGHK6ETDQ7hHVX914zlLq3G6cN/yiRBlpCJCUwqvLZdS48Pw== torspray-8b9932c2@home
```

Adding and spraying 2nd node:
```
$ torspray add testnode2 65.108.150.86
[+] Adding server 65.108.150.86, password: None
We have:
	username root
	hostname debian-2gb-hel1-2

$ torspray spray testnode2
[+] Spray verifying versions
...

```

Executing 'hostname' on all nodes we know about:
```
$ torspray cluster-exec 'hostname'
[+] Execing: hostname
testnode:
debian-2gb-hel1-1
testnode2:
debian-2gb-hel1-2
```
