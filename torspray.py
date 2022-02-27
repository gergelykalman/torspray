import random
import os
import io
import shutil
import json
import re
import pprint
import time
from datetime import datetime as dt, timedelta as td

import concurrent.futures

from concurrent.futures import ThreadPoolExecutor

import paramiko
import argparse

BASE_DIR = os.path.join(os.path.dirname(__file__), ".torspray")
CONFIGNAME = os.path.join(BASE_DIR, "torspray.json")
HOSTKEYS = os.path.join(BASE_DIR, "hostkeys")
PRIVKEY = os.path.join(BASE_DIR, "torspray_key")
PUBKEY = os.path.join(BASE_DIR, "torspray_key.pub")
USER = "root"
TIMEOUT = 30
MAX_WORKERS = 10


class TorSpray:
    def __init__(self):
        self.__config = self.__readconfig()
        self.__pkey = self.__load_private_key()

    def __load_private_key(self):
        pkey = None
        while True:
            try:
                pkey = paramiko.RSAKey.from_private_key_file(PRIVKEY)
            except FileNotFoundError:
                print("ERROR: SSH key files not found in {}".format(PRIVKEY))
                resp = input("Would you like me to genreate a new keypair? (y/N): ")
                if resp in ("y", "Y"):
                    self.__genkey()
                    print("Done")
                else:
                    print("Aborted")
                    exit(1)
            else:
                break
        return pkey

    def __connect_ssh(self, server, username, ignore_missing=False):
        client = paramiko.SSHClient()
        client.load_host_keys(HOSTKEYS)

        # should we add missing keys?
        if ignore_missing:
            policy = paramiko.AutoAddPolicy()
            client.set_missing_host_key_policy(policy)

        client.connect(server, username=username, pkey=self.__pkey, timeout=TIMEOUT)
        return client

    def __readconfig(self):
        while True:
            try:
                config = self.__db_read()
            except FileNotFoundError:
                print("[+] Torspray is not yet configured...")
                self.__init_config()
                self.__genkey()
                print("Basic configuration written, SSH key generated:")
                self.__showpubkey()
                exit(1)
            else:
                break

        return config

    def __init_config(self):
        print("[+] Initializing torspray directory: {}".format(BASE_DIR))

        try:
            os.makedirs(BASE_DIR, 0o750)
        except FileExistsError:
            pass

        with open(CONFIGNAME, "w") as f:
            config = {
                "servers": {}
            }
            json.dump(config, f, sort_keys=True, indent=4)

        with open(HOSTKEYS, "w") as f:
            pass

    def __db_read(self):
        with open(CONFIGNAME, "r") as f:
            config = json.load(f)
        return config

    def __db_write(self, config):
        with open(CONFIGNAME, "w") as f:
            json.dump(config, f, sort_keys=True, indent=4)

    def __get_connection(self, server, user, ignore_missing=False):
        client = self.__connect_ssh(server, user, ignore_missing)
        return client

    def __close_connection(self, connection):
        connection.close()

    def __run_command(self, client, command):
        _stdin, stdout, stderr = client.exec_command(command)

        # TODO: merge stdout and stderr!
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()

        # WARNING: anything that comes out here can be MALICIOUS!
        return out, err

    def __get_server_data(self, target):
        found = None
        servers = self.__list_servers()
        for nodename, data in servers.items():
            if nodename != target:
                pass
            found = data

        if found is None:
            print("ERROR: node {} was not found in db!".format(target))
            exit(1)

        return found

    def copyfile(self, nodename, direction, src, dst):
        addr = self.__get_server_data(nodename)["address"]

        client = self.__connect_ssh(addr, "root")

        if direction not in ("get", "put"):
            raise ValueError("Invalid value for direction (not 'get' or 'put')")

        sftp = client.open_sftp()
        if direction == "get":
            sftp.get(src, dst)
        else:
            sftp.put(src, dst)
        sftp.close()

    def __add_server(self, hostname, address, overwrite):
        db = self.__db_read()
        if not overwrite and hostname in db["servers"]:
            print("{} is already in servers!".format(hostname))
            return

        db["servers"][hostname] = {
            "hostname": hostname,
            "address": address,
        }

        self.__db_write(db)

    def add_server(self, hostname, address, password=None, overwrite=False):
        print("[+] Adding server {}, password: {}".format(address, password))

        client = self.__get_connection(address, USER, ignore_missing=True)

        out, err = self.__run_command(client, "whoami")
        ret_username = out.strip()

        out, err = self.__run_command(client, "hostname")
        ret_hostname = out.strip()
        print("We have:")
        print("\tusername", ret_username)
        print("\thostname", ret_hostname)

        self.__add_server(hostname, address, overwrite)

        self.__close_connection(client)

    def __list_servers(self, filter=None):
        servers = {}
        config = self.__db_read()
        for name, data in config["servers"].items():
            if filter is None or name == filter:
                servers[name] = data
        return servers

    def list_servers(self):
        servers = self.__list_servers()
        if len(servers) == 0:
            print("No servers in DB")
        else:
            print("[+] Servers in the DB:")
            for name, data in servers.items():
                print("\t{}: {}".format(name, data))

    def remove_server(self, nodename):
        print("[+] Removing {}".format(nodename))
        config = self.__db_read()
        if config["servers"].get(nodename) is not None:
            del config["servers"][nodename]
            self.__db_write(config)
            print("Server removed")

    def __node_exec(self, cmd, servers):
        def run(server, cmd):
            conn = self.__get_connection(server, USER)
            out, err = self.__run_command(conn, cmd)
            return out, err

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            for node, data in servers.items():
                tmp = executor.submit(run, data["address"], cmd)
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

    def node_exec(self, node, cmd):
        print("[+] Execing: {}".format(cmd))
        servers = self.__list_servers(filter=node)
        for result in self.__node_exec(cmd, servers):
            server, out, err = result
            print("{}:".format(server))
            print(out)

    def cluster_exec(self, cmd):
        print("[+] Execing: {}".format(cmd))
        servers = self.__list_servers()
        for result in self.__node_exec(cmd, servers):
            server, out, err = result
            print("{}:".format(server))
            print(out)

    def status(self):
        print("[+] Status:")
        servers = self.__list_servers()
        for result in self.__node_exec("whoami", servers):
            print(result)

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
                    match = re.search(" +(?P<direction>[RT]X) packets (?P<packets>\d+) *bytes (?P<bytes>\d+)", line)
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
            time.sleep(max(0, 1-delta))
            previous = now

    def __genkey(self, overwrite=False):
        print("[+] Generating SSH keys")
        if not overwrite:
            for name, filename in (
                            ("private", PRIVKEY),
                            ("public", PUBKEY)):
                if os.path.exists(filename):
                    print("ERROR: {} key {} exists, aborting!".format(name, filename))
                    exit(1)

        # private part
        privkey = paramiko.RSAKey.generate(4096)
        privkey.write_private_key_file(PRIVKEY)

        # public part
        with open(os.path.expanduser(PUBKEY), "w") as f:
            f.write("{} {} {}".format(
                privkey.get_name(),
                privkey.get_base64(),
                "torspray-{:x}@home".format(random.randint(2**31, 2**32)),
            ))

    def internal_genkey(self):
        self.__genkey(overwrite=True)

    def __showpubkey(self):
        print("##################################################")
        print("#        Use this key when creating the VM:      #")
        print("##################################################")
        with open(PUBKEY) as f:
            print(f.read())

    def showpubkey(self):
        self.__showpubkey()

    def spray(self):
        # TODO
        pass

    def parse_args(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        parser.set_defaults(func=parser.print_help)

        parser_add = subparsers.add_parser('add', help='add node to torspray')
        parser_add.add_argument('hostname', type=str, help='hostname')
        parser_add.add_argument('address', type=str, help='address')
        parser_add.add_argument('--password', type=str, required=False, help='password')
        parser_add.add_argument('--overwrite', type=bool, required=False, help='overwrite')
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

        parser_genkey = subparsers.add_parser('internal-genkey', help='regenerate and OVERWRITE ssh keys')
        parser_genkey.set_defaults(func='internal-genkey')

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

        # do parse
        args = parser.parse_args()
        # print("DBG", args)

        if args.func == "add":
            self.add_server(args.hostname, args.address, args.password, args.overwrite)
        elif args.func == "list":
            self.list_servers()
        elif args.func == "remove":
            self.remove_server(args.hostname)
        elif args.func == "status":
            self.status()
        elif args.func == "netstatus":
            self.netstatus()
        elif args.func == "internal-genkey":
            # internal function
            self.internal_genkey()
        elif args.func == "showpubkey":
            self.showpubkey()
        elif args.func == "copyfile":
            self.copyfile(args.server, args.direction, args.src, args.dst)
        elif args.func == "node-exec":
            self.node_exec(args.hostname, args.cmd)
        elif args.func == "cluster-exec":
            self.cluster_exec(args.cmd)
        elif args.func == "spray":
            self.spray()
        else:
            parser.print_help()

    def main(self):
        self.parse_args()


if __name__ == "__main__":
    ts = TorSpray()
    ts.main()
