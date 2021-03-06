# torspray
A console utility to bring up new Tor nodes easily

If you feel like supporthing the project, you can [buy me a coffee](https://www.buymeacoffee.com/gergelykalman).

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
  - if you don't remember, run `torspray pubkey`
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
$ torspray run testnode 'hostname'
[+] Execing: hostname
testnode:
debian-2gb-hel1-1
```

Showing pubkey because I forgot:
```
$ torspray pubkey
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
$ torspray run-all 'hostname'
[+] Execing: hostname
testnode:
debian-2gb-hel1-1
testnode2:
debian-2gb-hel1-2
```

Running netstatus across all machines:
```bash
$ torspray netstatus --interval 1
[+] Status every 1s:
torbridge0 RX:      73.83 kbit/s TX:      51.51 kbit/s - total: RX:      55.10 GB TX:      56.79 GB
torbridge1 RX:      29.88 kbit/s TX:      13.26 kbit/s - total: RX:      36.69 GB TX:      37.93 GB
torbridge2 RX:      54.67 kbit/s TX:      20.14 kbit/s - total: RX:     173.84 GB TX:     175.76 GB
torbridge3 RX:     706.39 kbit/s TX:     619.88 kbit/s - total: RX:      80.57 GB TX:      78.51 GB
torbridge4 RX:     352.24 kbit/s TX:     299.38 kbit/s - total: RX:      73.66 GB TX:      72.94 GB
torbridge5 RX:       5.24 kbit/s TX:      10.65 kbit/s - total: RX:     144.82 GB TX:     147.31 GB
torbridge6 RX:       5.24 kbit/s TX:      10.55 kbit/s - total: RX:       5.97 GB TX:       5.86 GB
torbridge7 RX:     136.70 kbit/s TX:      43.91 kbit/s - total: RX:      84.33 GB TX:      87.20 GB
torbridge8 RX:       5.24 kbit/s TX:      10.65 kbit/s - total: RX:       3.87 GB TX:       4.09 GB
torbridge9 RX:       7.20 kbit/s TX:      24.81 kbit/s - total: RX:      10.38 GB TX:      10.69 GB

date: 2022-03-02 00:37:48.537278, delta: 1.17, sleep time: 0.00     TOTAL: RX:     669.23 GB TX:     677.09 GB
==================================================
...
```

Executing a pty actual shell on a node:
```bash
$ torspray shell testnode
$ top
...
top - 14:33:41 up 4 days, 15:06,  1 user,  load average: 0.03, 0.01, 0.00
Tasks:  83 total,   1 running,  82 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.0 us,  0.0 sy,  0.0 ni,100.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
MiB Mem :   1934.6 total,    934.8 free,    249.3 used,    750.5 buff/cache
MiB Swap:      0.0 total,      0.0 free,      0.0 used.   1542.8 avail Mem

    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
      1 root      20   0  164352  10896   7792 S   0.0   0.6   0:16.08 systemd
      2 root      20   0       0      0      0 S   0.0   0.0   0:00.09 kthreadd
      3 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_gp
      4 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 rcu_par_gp
      6 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker/0:0H-events_highpri
      9 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 mm_percpu_wq
     10 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tasks_rude_
     11 root      20   0       0      0      0 S   0.0   0.0   0:00.00 rcu_tasks_trace
     12 root      20   0       0      0      0 S   0.0   0.0   0:22.70 ksoftirqd/0
     13 root      20   0       0      0      0 I   0.0   0.0   0:09.81 rcu_sched
     14 root      rt   0       0      0      0 S   0.0   0.0   0:01.73 migration/0
     15 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/0
     16 root      20   0       0      0      0 S   0.0   0.0   0:00.00 cpuhp/1
     17 root      rt   0       0      0      0 S   0.0   0.0   0:01.78 migration/1
     18 root      20   0       0      0      0 S   0.0   0.0   0:07.93 ksoftirqd/1
     20 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 kworker/1:0H-events_highpri
     23 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kdevtmpfs
     24 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 netns
     25 root      20   0       0      0      0 S   0.0   0.0   0:00.00 kauditd
     26 root      20   0       0      0      0 S   0.0   0.0   0:00.09 khungtaskd
     27 root      20   0       0      0      0 S   0.0   0.0   0:00.00 oom_reaper
     28 root       0 -20       0      0      0 I   0.0   0.0   0:00.00 writeback
     29 root      20   0       0      0      0 S   0.0   0.0   0:10.32 kcompactd0
     30 root      25   5       0      0      0 S   0.0   0.0   0:00.00 ksm
...
```
