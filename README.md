# torspray
A console utility to bring up new Tor nodes easily

### Current progress
Works:
- key generation
- node management commands
- file copy
- command execution on one or all nodes

Works in progress:
- automatic configuration of tor on the node
- meaningful statistics
- ability to compile torspray to a standalone executable


### Why?
This tool is meant to empower less tech-savvy users to be able to quickly and effortlessly
bring up tor nodes to help out the network in times of crisis.


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

### Basic usage

```bash
usage: torspray.py [-h]
                   {add,list,remove,status,netstatus,showpubkey,internal-genkey,copyfile,cluster-exec,node-exec}
                   ...

positional arguments:
  {add,list,remove,status,netstatus,showpubkey,internal-genkey,copyfile,cluster-exec,node-exec}
    add                 add node to torspray
    list                list nodes
    remove              remove node from torspray
    status              list node status
    netstatus           list node network status
    showpubkey          show public key signature for VM creation
    internal-genkey     regenerate and OVERWRITE ssh keys
    copyfile            copy file to/from node
    cluster-exec        execute commands on one node
    node-exec           execute commands on all nodes

optional arguments:
  -h, --help            show this help message and exit
```
