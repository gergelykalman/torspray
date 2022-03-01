import os
import re
import pprint
import time
from datetime import datetime as dt, timedelta as td

import concurrent.futures

from concurrent.futures import ThreadPoolExecutor

import argparse

from torspray.modules.config import CONFIG
from torspray.modules.db import DB
from torspray.modules.ssh_keys import generate_key, remove_hostkeys
from torspray.modules.node import Node, NodeAuthException, NodeTimeoutException
from torspray.sprays.debian_11_torbridge.spray import Debian11Bridge


class TorSpray:
    def __init__(self):
        # set os stuff
        self.__CWD = os.getcwd()

        # parse arguments
        self.__parser = None
        self.__args = self.__parse_args()

        # config paths
        self.__CONF_DIR = self.__args.confdir
        self.__CONFIGNAME = os.path.join(self.__CONF_DIR, "torspray.json")
        self.__HOSTKEYS = os.path.join(self.__CONF_DIR, "hostkeys")
        self.__PRIVPATH = os.path.join(self.__CONF_DIR, "torspray_key")
        self.__PUBPATH = os.path.join(self.__CONF_DIR, "torspray_key.pub")

        # vars
        self.__db = DB(self.__CONFIGNAME, self.__HOSTKEYS)
        self.__first_run = self.__db.is_first_run()

    def __node_exec(self, cmd, nodes):
        def run(node, cmd):
            out, err = node.run(cmd)
            return out, err

        with ThreadPoolExecutor(max_workers=CONFIG.MAX_WORKERS) as executor:
            futures = {}
            for node in nodes:
                tmp = executor.submit(run, node, cmd)
                futures[tmp] = node

            for future in concurrent.futures.as_completed(futures):
                server = futures[future]
                try:
                    data = future.result()
                except Exception as exc:
                    print("EXCEPTION on {}: {}".format(server, exc))
                else:
                    out, err = data
                    yield server, out, err

    def need_init(f, *args, **kwargs):  # *args, **kwargs makes pycharm shut up
        def magic(self, *args, **kwargs):
            if self.__first_run:
                print("Torspray has not been initialized, run torspray init YOUR_EMAIL_ADDR")
                exit(1)
            return f(self, *args, **kwargs)
        return magic

    @need_init
    def add_server(self, hostname, address, password=None, overwrite=False):
        print("[+] Adding server {}, password: {}".format(address, password))

        tmp = self.__list_servers(hostname)
        if not overwrite and len(tmp) > 0:
            print("{} is already in servers!".format(hostname))
            return

        if overwrite:
            remove_hostkeys(address, self.__HOSTKEYS)

        node = Node(hostname, address, self.__HOSTKEYS, self.__PRIVPATH)

        try:
            node.connect(ignore_missing=True)
        except NodeAuthException:
            print("[-] Could not authenticate to the server, either the key is bad or the password")
            exit(1)
        except NodeTimeoutException:
            print("[-] Failed to reach server, try again later")
            exit(1)

        out, err = node.run("whoami")
        ret_username = out.strip()

        out, err = node.run("hostname")
        ret_hostname = out.strip()
        print("We have:")
        print("\tusername", ret_username)
        print("\thostname", ret_hostname)

        self.__db.add_server(hostname, address, overwrite)

        node.disconnect()

    def __get_server(self, nodename):
        data = self.__db.get_server(nodename)
        if data is None:
            print("Server not in DB")
            exit(1)

        node = Node(nodename, data["address"], self.__HOSTKEYS, self.__PRIVPATH)
        return node

    def __list_servers(self, filter=None):
        nodes = self.__db.list_servers(filter=filter)
        servers = []
        for nodename, data in nodes.items():
            node = Node(nodename, data["address"], self.__HOSTKEYS, self.__PRIVPATH)
            servers.append(node)
        return servers

    @need_init
    def list_servers(self):
        servers = self.__db.list_servers()
        if len(servers) == 0:
            print("No servers in DB")
        else:
            print("[+] Servers in the DB:")
            for name, data in servers.items():
                print("\t{}: {}".format(name, data))

    @need_init
    def remove_server(self, nodename):
        print("[+] Removing {}".format(nodename))

        node = self.__get_server(nodename)
        remove_hostkeys(node.addr, self.__HOSTKEYS)
        self.__db.remove_server(nodename)

    @need_init
    def node_exec(self, node, cmd):
        print("[+] Execing: {}".format(cmd))
        servers = self.__list_servers(filter=node)
        if len(servers) == 0:
            print("Error: node not found: {}".format(node))
            exit(1)

        for result in self.__node_exec(cmd, servers):
            server, out, err = result
            print("{}:".format(server))
            print(out)

    @need_init
    def cluster_exec(self, cmd):
        print("[+] Execing: {}".format(cmd))
        servers = self.__list_servers()
        for result in self.__node_exec(cmd, servers):
            server, out, err = result
            print("{}:".format(server))
            print(out)

    @need_init
    def status(self):
        print("[+] Status:")
        servers = self.__list_servers()
        for node, out, err in self.__node_exec("whoami", servers):
            print("{}:".format(node))
            print(out, err)

    @need_init
    def netstatus(self):
        print("[+] Status:")
        previous = dt.now()
        bw = {}
        servers = self.__list_servers()
        while True:
            for result in self.__node_exec("ifconfig eth0", servers):
                server, out, err = result
                for line in out.split("\n"):
                    # TODO: this is very brittle
                    match = re.search(r" +(?P<direction>[RT]X) packets (?P<packets>\d+) *bytes (?P<bytes>\d+)", line)
                    if match is not None:
                        matchdict = match.groupdict()
                        if bw.get(server) is None:
                            bw[server] = {}
                        bw[server][match["direction"]] = {
                                "packets": matchdict["packets"],
                                "bytes": matchdict["bytes"],
                            }
            pprint.pprint(bw)
            now = dt.now()
            delta = (now-previous).total_seconds()
            time.sleep(max(0, 1-int(delta)))
            previous = now

    def __showpubkey(self):
        print("##################################################")
        print("#        Use this key when creating the VM:      #")
        print("##################################################")
        with open(self.__PUBPATH) as f:
            print(f.read())

    @need_init
    def showpubkey(self):
        self.__showpubkey()

    def init(self, email):
        # TODO: validate email properly
        if not self.__first_run:
            print("[-] Torspray init already ran, if you want to re-run init, delete the .torspray directory")
            exit(1)

        if "@" not in email:
            print("Contact info has to be an email!")
            exit(1)

        self.__db.init_config(email)

        self.__generate_key()
        print("Basic configuration written, SSH key generated:")
        self.__showpubkey()

    def __generate_key(self):
        print("[+] Generating SSH keys")
        failed_filename = generate_key(self.__PRIVPATH, self.__PUBPATH)
        if failed_filename is not None:
            raise FileExistsError(failed_filename)

    @need_init
    def copyfile(self, nodename, direction, src, dst):
        node = self.__get_server(nodename)
        node.copyfile(direction, src, dst)

    @need_init
    def spray(self, hostname):
        contactinfo = self.__db.getcontactinfo()
        node = self.__get_server(hostname)
        s = Debian11Bridge(contactinfo, node, CONFIG.PORTRANGE)
        s.spray()

    def __parse_args(self):
        # if --confdir is set use it
        # if not and CONFDIR is set in env, use it
        # if not fall back to $(pwd)/.torspray
        confdir_default = os.environ.get(
            "CONFDIR",
            os.path.join(self.__CWD, ".torspray")
        )

        self.__parser = argparse.ArgumentParser()
        subparsers = self.__parser.add_subparsers()
        self.__parser.set_defaults(func=self.__parser.print_help)
        self.__parser.add_argument('--confdir', type=str, required=False,
                                   default=confdir_default,
                                   help='Set torspray config directory')

        parser_init = subparsers.add_parser('init', help='sets contact email for tor')
        parser_init.add_argument('email', type=str, help='email address')
        parser_init.set_defaults(func='init')

        parser_add = subparsers.add_parser('add', help='add node to torspray')
        parser_add.add_argument('hostname', type=str, help='hostname')
        parser_add.add_argument('address', type=str, help='address')
        parser_add.add_argument('--password', type=str, required=False, help='password')
        parser_add.add_argument('--overwrite', action='store_true', required=False, help='overwrite')
        parser_add.set_defaults(func='add')

        parser_list = subparsers.add_parser('list', help='list nodes')
        parser_list.set_defaults(func='list')

        parser_add = subparsers.add_parser('remove', help='remove node from torspray')
        parser_add.add_argument('hostname', type=str, help='hostname')
        parser_add.set_defaults(func='remove')

        parser_status = subparsers.add_parser('status', help='list node status')
        parser_status.set_defaults(func='status')

        parser_netstatus = subparsers.add_parser('netstatus', help='list node network status')
        parser_netstatus.set_defaults(func='netstatus')

        parser_showpubkey = subparsers.add_parser('showpubkey', help='show public key signature for VM creation')
        parser_showpubkey.set_defaults(func='showpubkey')

        parser_copyfile = subparsers.add_parser('copyfile', help='copy file to/from node')
        parser_copyfile.add_argument('server', type=str)
        parser_copyfile.add_argument('direction', choices=["put", "get"], type=str)
        parser_copyfile.add_argument('src', type=str)
        parser_copyfile.add_argument('dst', type=str)
        parser_copyfile.set_defaults(func='copyfile')

        parser_cluster_exec = subparsers.add_parser('cluster-exec', help='execute commands on one node')
        parser_cluster_exec.add_argument('cmd', type=str)
        parser_cluster_exec.set_defaults(func='cluster-exec')

        parser_node_exec = subparsers.add_parser('node-exec', help='execute commands on all nodes')
        parser_node_exec.add_argument('hostname', type=str)
        parser_node_exec.add_argument('cmd', type=str)
        parser_node_exec.set_defaults(func='node-exec')

        parser_spray = subparsers.add_parser('spray', help='initialize the node as a tor bridge')
        parser_spray.add_argument('hostname', type=str)
        parser_spray.set_defaults(func='spray')

        args = self.__parser.parse_args()
        return args

    def main(self):
        func = self.__args.func
        if func == "init":
            self.init(self.__args.email)
        elif func == "add":
            self.add_server(self.__args.hostname, self.__args.address, self.__args.password, self.__args.overwrite)
        elif func == "list":
            self.list_servers()
        elif func == "remove":
            self.remove_server(self.__args.hostname)
        elif func == "status":
            self.status()
        elif func == "netstatus":
            self.netstatus()
        elif func == "showpubkey":
            self.showpubkey()
        elif func == "copyfile":
            self.copyfile(self.__args.server, self.__args.direction, self.__args.src, self.__args.dst)
        elif func == "node-exec":
            self.node_exec(self.__args.hostname, self.__args.cmd)
        elif func == "cluster-exec":
            self.cluster_exec(self.__args.cmd)
        elif func == "spray":
            self.spray(self.__args.hostname)
        else:
            self.__parser.print_help()


def main():
    ts = TorSpray()
    ts.main()


if __name__ == "__main__":
    main()
