import os
import io
import shutil
import json

import concurrent.futures

from concurrent.futures import ThreadPoolExecutor

import paramiko
import argparse

BASE_DIR = os.path.join(os.path.dirname(__file__), ".torspray")
CONFIGNAME = os.path.join(BASE_DIR, "torspray.json")
HOSTKEYS = os.path.join(BASE_DIR, "hostkeys")
USER = "root"
TIMEOUT = 30
MAX_WORKERS = 10


class TorSpray:
    def __init__(self):
        self.__config = self.__readconfig()
        self.__pkey = self.__load_private_key()

    def __load_private_key(self):
        keyname = os.path.join(BASE_DIR, "torspray_key")
        pkey = None
        try:
            pkey = paramiko.RSAKey.from_private_key_file(keyname)
        except FileNotFoundError:
            # TODO: fix this
            print("ERROR: SSH key files not found in {}".format(keyname))
            print("Look in the help for more info")
            print("ssh-keygen -f ./.torspray/torspray_key -t rsa -b 4096 -N \"\"")
            exit(1)
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
                print("Basic configuration written")
                print("This version doesn't yet support key generation, so please place your keys to:\n"
                      ".torspray/torspray_key\n"
                      ".torspray/torspray_key.pub\n")
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
        # print("[+] Opening connection to: {}@{}, ignore missing: {}".format(
        #     user, server, ignore_missing
        # ))
        client = self.__connect_ssh(server, user, ignore_missing)
        return client

    def __close_connection(self, connection):
        connection.close()

    def __run_command(self, client, command):
        # print("[+] Running command: {}".format(command))

        _stdin, stdout, stderr = client.exec_command(command)

        # TODO: merge stdout and stderr!
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()

        # WARNING: anything that comes out here can be MALICIOUS!
        return out, err

    def __get_server_addr(self, target):
        found = None
        servers = self.__list_servers()
        for nodename, data in servers.items():
            if nodename != target:
                pass
            found = data["address"]

        if found is None:
            print("ERROR: node {} was not found in db!".format(target))
            exit(1)

        return found

    def copyfile(self, nodename, direction, src, dst):
        addr = self.__get_server_addr(nodename)

        client = self.__connect_ssh(addr, "root")

        if direction not in ("get", "put"):
            raise ValueError("Invalid value for direction (not 'get' or 'put')")

        sftp = client.open_sftp()
        if direction == "get":
            sftp.get(src, dst)
        else:
            sftp.put(src, dst)
        sftp.close()

    def get_file(self, server, src, dst):
        print("[+] Get file from {}: {} -> {}".format(server, src, dst))
        self.__transfer_file(server, "get", src, dst)

    def put_file(self, server, src, dst):
        print("[+] Put file to {}: {} -> {}".format(server, src, dst))
        self.__transfer_file(server, "put", src, dst)

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

    def __list_servers(self):
        servers = {}
        config = self.__db_read()
        for name, data in config["servers"].items():
            servers[name] = data
        return servers

    def list_servers(self):
        print("[+] Servers in the DB:")
        servers = self.__list_servers()
        for name, data in servers.items():
            print("\t{}: {}".format(name, data))

    def remove_server(self, nodename):
        print("[+] Removing {}".format(nodename))
        config = self.__db_read()
        if config["servers"].get(nodename) is not None:
            del config["servers"][nodename]
            self.__db_write(config)
            print("Server removed")

    def node_exec(self, cmd):
        def run(server, cmd):
            conn = self.__get_connection(server, USER)
            out, err = self.__run_command(conn, cmd)
            return out, err

        servers = self.__list_servers()

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
                    print("{}:\n{} {}".format(server, out, err))

    def status(self):
        print("[+] Status:")
        self.node_exec("whoami")

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

        parser_copyfile = subparsers.add_parser('copyfile', help='copy file to/from node')
        parser_copyfile.add_argument('server', type=str)
        parser_copyfile.add_argument('direction', choices=["put", "get"], type=str)
        parser_copyfile.add_argument('src', type=str)
        parser_copyfile.add_argument('dst', type=str)
        parser_copyfile.set_defaults(func='copyfile')

        parser_node_exec = subparsers.add_parser('node-exec', help='execute commands on nodes')
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
        elif args.func == "copyfile":
            self.copyfile(args.server, args.direction, args.src, args.dst)
        elif args.func == "node-exec":
            self.node_exec(args.cmd)
        elif args.func == "spray":
            # TODO
            raise NotImplemented()
        else:
            parser.print_help()

    def main(self):
        self.parse_args()


if __name__ == "__main__":
    ts = TorSpray()
    ts.main()
