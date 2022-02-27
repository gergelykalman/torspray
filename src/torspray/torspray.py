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

#BASE_DIR = os.path.join(os.path.dirname(__file__), ".torspray")
# TODO: do this more properly
BASE_DIR = os.path.join(os.getcwd(), ".torspray")
VERSION = 0.1
CONFIGNAME = os.path.join(BASE_DIR, "torspray.json")
HOSTKEYS = os.path.join(BASE_DIR, "hostkeys")
PRIVKEY = os.path.join(BASE_DIR, "torspray_key")
PUBKEY = os.path.join(BASE_DIR, "torspray_key.pub")
PORTRANGE = (1025, 65534)
USER = "root"
TIMEOUT = 30
MAX_WORKERS = 10

UNATTENDED_UPGRADES_CFG = """

    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=TorProject";
};
Unattended-Upgrade::Package-Blacklist {
};
"""
UNATTENDED_AUTO_CFG = """
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::AutocleanInterval "5";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Verbose "1";
"""
TOR_SOURCES_LIST = """
deb     [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org ###DISTRIBUTION### main
deb-src [signed-by=/usr/share/keyrings/tor-archive-keyring.gpg] https://deb.torproject.org/torproject.org ###DISTRIBUTION### main
"""
CONFIG_TORRC = """
BridgeRelay 1

# Replace "TODO1" with a Tor port of your choice.
# This port must be externally reachable.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ORPort ###TODO1###

ServerTransportPlugin obfs4 exec /usr/bin/obfs4proxy

# Replace "TODO2" with an obfs4 port of your choice.
# This port must be externally reachable and must be different from the one specified for ORPort.
# Avoid port 9001 because it's commonly associated with Tor and censors may be scanning the Internet for this port.
ServerTransportListenAddr obfs4 0.0.0.0:###TODO2###

# Local communication port between Tor and obfs4.  Always set this to "auto".
# "Ext" means "extended", not "external".  Don't try to set a specific port number, nor listen on 0.0.0.0.
ExtORPort auto

# Replace "<address@email.com>" with your email address so we can contact you if there are problems with your bridge.
# This is optional but encouraged.
ContactInfo <###CONTACTINFO###>

# Pick a nickname that you like for your bridge.  This is optional.
#Nickname ###NICKNAME###
"""


class TorSpray:
    def __init__(self):
        self.__first_run = self.__is_first_run()
        self.__pkey = None

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

        if self.__pkey is None:
            self.__pkey = self.__load_private_key()

        client.connect(server, username=username, pkey=self.__pkey, timeout=TIMEOUT)
        return client

    def __is_first_run(self):
        try:
            self.__db_read()
        except FileNotFoundError:
            return True
        else:
            return False

    def __init_config(self, contactinfo):
        print("[+] Initializing torspray directory: {}".format(BASE_DIR))

        try:
            os.makedirs(BASE_DIR, 0o750)
        except FileExistsError:
            pass

        with open(CONFIGNAME, "w") as f:
            config = {
                "servers": {},
                "torspray": {
                    "contactinfo": contactinfo,
                    "version": VERSION,
                }
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

    def __get_connection(self, addr, user, ignore_missing=False):
        client = self.__connect_ssh(addr, user, ignore_missing)
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
            # exit(1)

        return found

    def need_init(func):
        def magic(self, *args, **kwargs):
            if self.__first_run:
                print("Torspray has not been initialized, run torspray init YOUR_EMAIL_ADDR")
                exit(1)
            return func(self, *args, **kwargs)
        return magic

    @need_init
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

    def __remove_hostkeys(self, address):
        print("Clearing host from hostkeys")
        hostkeys = paramiko.HostKeys(HOSTKEYS)
        if hostkeys.get(address) is not None:
            del hostkeys[address]
        hostkeys.save(HOSTKEYS)

    @need_init
    def add_server(self, hostname, address, password=None, overwrite=False):
        print("[+] Adding server {}, password: {}".format(address, password))

        if overwrite:
            self.__remove_hostkeys(address)

        try:
            client = self.__get_connection(address, USER, ignore_missing=True)
        except paramiko.ssh_exception.PasswordRequiredException:
            print("[-] Could not authenticate to the server, either the key is bad or the password")
            exit(1)
        except paramiko.ssh_exception.NoValidConnectionsError:
            print("[-] Failed to reach server, try again later")
            exit(1)

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

    @need_init
    def list_servers(self):
        servers = self.__list_servers()
        if len(servers) == 0:
            print("No servers in DB")
        else:
            print("[+] Servers in the DB:")
            for name, data in servers.items():
                print("\t{}: {}".format(name, data))

    @need_init
    def remove_server(self, nodename):
        print("[+] Removing {}".format(nodename))

        address = self.__get_server_data(nodename)
        if address is None:
            print("Server not in DB")
            exit(1)

        self.__remove_hostkeys(address)

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
        for result in self.__node_exec("whoami", servers):
            print(result)

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

    def __showpubkey(self):
        print("##################################################")
        print("#        Use this key when creating the VM:      #")
        print("##################################################")
        with open(PUBKEY) as f:
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

        self.__init_config(email)
        self.__genkey()
        print("Basic configuration written, SSH key generated:")
        self.__showpubkey()

    def __getcontactinfo(self):
        config = self.__db_read()
        return config["torspray"]["contactinfo"]

    def __spray_runcmd(self, conn, cmd):
        # TODO: check retvals and err!
        out, err = self.__run_command(conn, cmd)
        print("$ {}".format(cmd))
        print(out)
        if len(err) > 0:
            print("ERROR in command {}:".format(cmd))
            print(err)
            # exit(1)
        return out, err

    def __spray_verify_prerequisites(self, conn, conn_ftp):
        version = None
        codename = None
        with conn_ftp.file("/etc/os-release") as f:
            lines = f.read().decode("utf-8").splitlines()
            for l in lines:
                k, v = l.split("=")
                if k == "NAME":
                    version = v.strip("\"")
                    # print("Version: {}".format(version))
                elif k == "VERSION_CODENAME":
                    codename = v.strip("\"")
                    # print("Codename: {}".format(codename))
        if version is None or codename is None:
            print("ERROR: Version wasn't found")

        out, err = self.__spray_runcmd(conn, "dpkg --print-architecture")
        arch = out.strip()
        return version, codename, arch

    def __spray_enable_updates(self, conn, conn_ftp):
        """
        Based on: https://community.torproject.org/relay/setup/guard/debian-ubuntu/updates/
        """
        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get upgrade -y")

        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y unattended-upgrades apt-listchanges")

        with conn_ftp.file("/etc/apt/apt.conf.d/50unattended-upgrades", "wt") as f:
            f.write(UNATTENDED_UPGRADES_CFG)

        with conn_ftp.file("/etc/apt/apt.conf.d/20auto-upgrades", "wt") as f:
            f.write(UNATTENDED_AUTO_CFG)

        # self.__spray_runcmd(conn, "unattended-upgrade --debug --dry-run")

    def __spray_configure_tor_repo(self, conn, conn_ftp, codename):
        """
        Based on: https://support.torproject.org/apt/tor-deb-repo/
        """
        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y apt-transport-https gpg")

        with conn_ftp.file("/etc/apt/sources.list.d/tor.list", "wt") as f:
            config = TOR_SOURCES_LIST.replace("###DISTRIBUTION###",
                                              codename)
            f.write(config)

        self.__spray_runcmd(conn, "wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null")

        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get update")
        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y tor deb.torproject.org-keyring")

    def __spray_install_packages(self, conn, conn_ftp, contactinfo):
        """
        Based on: https://community.torproject.org/relay/setup/bridge/debian-ubuntu/
        """
        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get update")
        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y tor")
        self.__spray_runcmd(conn, "export DEBIAN_FRONTEND=noninteractive; apt-get install -y obfs4proxy")

        with conn_ftp.file("/etc/tor/torrc", "wt") as f:
            config = CONFIG_TORRC
            for old, new in (
                            ("###TODO1###", str(random.randint(*PORTRANGE))),
                            ("###TODO2###", str(random.randint(*PORTRANGE))),
                            ("###CONTACTINFO###", contactinfo),
                            # TODO: support this in the future
                            # ("###NICKNAME###", nickname),
            ):
                config = config.replace(old, new)
            f.write(config)

        self.__spray_runcmd(conn, "setcap cap_net_bind_service=+ep /usr/bin/obfs4proxy")

        for filename in ["/lib/systemd/system/tor@default.service",
                         "/lib/systemd/system/tor@.service"]:
            with conn_ftp.file(filename, "ra") as f:
                f.seek(os.SEEK_SET, 0)
                contents = f.read().decode("utf-8")
                contents = contents.replace("NoNewPrivileges=yes", "NoNewPrivileges=no")

                f.truncate(0)
                f.write(contents)

        self.__spray_runcmd(conn, "systemctl daemon-reload")

        self.__spray_runcmd(conn, "systemctl enable --now tor.service")
        self.__spray_runcmd(conn, "systemctl restart tor.service")

        # test, check logs:
        # TODO
        # self.__spray_runcmd(conn, "journalctl -e -u tor@default | grep \"Self-testing indicates\"")

    @need_init
    def spray(self, hostname):
        server = self.__get_server_data(hostname)
        contactinfo = self.__getcontactinfo()
        conn = self.__get_connection(server["address"], USER)
        conn_ftp = conn.open_sftp()

        print("[+] Spray verifying versions")
        version, codename, arch = self.__spray_verify_prerequisites(conn, conn_ftp)
        if version != "Debian GNU/Linux" or codename != "bullseye":
            print("ERROR This Distribution/version is unsupported: version: {}, codename: {}".format(version, codename))
            exit(1)
        if arch not in ("amd64",):
            print("ERROR This architecture is not supported: {}".format(arch))
            exit(1)
        print("\tversion: {}\n\tcodename: {}\n\tarch: {}".format(version, codename, arch))

        print("[+] Spray enabling updates")
        self.__spray_enable_updates(conn, conn_ftp)

        print("[+] Spray configuring tor repo")
        self.__spray_configure_tor_repo(conn, conn_ftp, codename)

        print("[+] Spray installing packages")
        self.__spray_install_packages(conn, conn_ftp, contactinfo)

        conn_ftp.close()
        conn.close()

    def parse_args(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        parser.set_defaults(func=parser.print_help)

        parser_init = subparsers.add_parser('init', help='sets contact email for tor')
        parser_init.add_argument('email', type=str, help='email address')
        parser_init.set_defaults(func='init')

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

        # do parse
        args = parser.parse_args()
        # print("DBG", args)

        if args.func == "init":
            self.init(args.email)
        elif args.func == "add":
            self.add_server(args.hostname, args.address, args.password, args.overwrite)
        elif args.func == "list":
            self.list_servers()
        elif args.func == "remove":
            self.remove_server(args.hostname)
        elif args.func == "status":
            self.status()
        elif args.func == "netstatus":
            self.netstatus()
        elif args.func == "showpubkey":
            self.showpubkey()
        elif args.func == "copyfile":
            self.copyfile(args.server, args.direction, args.src, args.dst)
        elif args.func == "node-exec":
            self.node_exec(args.hostname, args.cmd)
        elif args.func == "cluster-exec":
            self.cluster_exec(args.cmd)
        elif args.func == "spray":
            self.spray(args.hostname)
        else:
            parser.print_help()

    def main(self):
        self.parse_args()


def main():
    ts = TorSpray()
    ts.main()


if __name__ == "__main__":
    main()
