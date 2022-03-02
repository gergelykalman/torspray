import sys
import os
import re
import shutil
import time
from datetime import datetime as dt, timedelta as td

import concurrent.futures

from concurrent.futures import ThreadPoolExecutor

import argparse

from torspray.modules.config import CONFIG
from torspray.modules.db import DB
from torspray.modules.ssh_keys import generate_key, remove_hostkeys
from torspray.modules.node import Node, NodeAuthException, NodeTimeoutException
from torspray.modules.tui import TUI
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
            retval, out, err = node.run(cmd)
            return retval, out, err

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
                    retval, out, err = data
                    yield server, retval, out, err

    def need_init(f, *args, **kwargs):  # *args, **kwargs makes pycharm shut up
        def magic(self, *args, **kwargs):
            if self.__first_run:
                print("Torspray has not been initialized, run torspray init YOUR_EMAIL_ADDR")
                exit(1)
            return f(self, *args, **kwargs)
        return magic

    @need_init
    def add_server(self, hostname, address, password=None, keyfile=None, overwrite=False):
        print("[+] Adding server {}, password: {}".format(address, password))

        tmp = self.__list_servers(hostname)
        if not overwrite and len(tmp) > 0:
            print("{} is already in servers!".format(hostname))
            return

        if overwrite:
            remove_hostkeys(address, self.__HOSTKEYS)

        if keyfile is None:
            pkeypath = self.__PRIVPATH
        else:
            pkeypath = keyfile
        node = Node(hostname, address, self.__HOSTKEYS, pkeypath)

        try:
            node.connect(ignore_missing=True)
        except NodeAuthException:
            print("[-] Could not authenticate to the server, either the key is bad or the password")
            exit(1)
        except NodeTimeoutException:
            print("[-] Failed to reach server, try again later")
            exit(1)

        retval, out, err = node.run("whoami")
        ret_username = out.strip()

        retval, out, err = node.run("hostname")
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
                print("\t{} - {}".format(name, data))

    @need_init
    def remove_server(self, nodename):
        node = self.__get_server(nodename)
        remove_hostkeys(node.addr, self.__HOSTKEYS)
        self.__db.remove_server(nodename)

    @need_init
    def clear_all(self):
        resp = input("[!] You are about to remove EVERY server, are you sure? (y/N):")
        if resp not in ("y", "Y"):
            print("Aborting")
            exit(1)

        for s in self.__list_servers():
            self.remove_server(s.name)

    @need_init
    def exec(self, node, cmd):
        print("[+] Execing: {}".format(cmd))
        servers = self.__list_servers(filter=node)
        if len(servers) == 0:
            print("Error: node not found: {}".format(node))
            exit(1)

        for result in self.__node_exec(cmd, servers):
            server, retval, out, err = result
            print("{}:".format(server))
            print(out)

    @need_init
    def shell(self, nodename):
        print("[+] Starting shell on: {}".format(nodename))

        node = self.__get_server(nodename)

        term = os.environ.get("TERM")
        cols, lines = shutil.get_terminal_size()

        shell = node.invoke_shell(term=term, width=cols, height=lines)
        shell.settimeout(0)

        # nobody else needs these, so we import it here
        # TODO: move these to a TUI module later
        import termios
        import tty
        import select
        import socket

        old = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())

            abort = False
            while not abort:
                readable, writable, error = select.select([sys.stdin, shell], [], [])
                for fd in readable:
                    if fd == shell:
                        try:
                            buf = shell.recv(4096).decode("utf-8")
                            if len(buf) == 0:
                                abort = True
                                break
                            sys.stdout.write(buf)
                            sys.stdout.flush()
                        except socket.timeout:
                            pass
                    elif fd == sys.stdin:
                        char = sys.stdin.read(1)
                        if len(char) == 0:
                            abort = True
                            break
                        shell.send(char)
                    else:
                        # raise ValueError("unexpected fd ({}) is readable in select".format(fd))
                        pass
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)

        print("Done")

    @need_init
    def importhosts(self, filename, password=None, keyfile=None, overwrite=False):
        validlines = 0
        nodelist = []
        with open(filename, "r") as f:
            for line_raw in f:
                line = line_raw.strip()

                # ignore empty lines and lines starting with #
                if line == '' or line[0] == "#":
                    continue

                validlines += 1

                # hostname: alphanum, -, ., must begin with alpha
                match = re.match(r'^(?P<address>.*?)\s+(?P<name>[a-zA-Z][0-9a-zA-Z-.]*)', line)
                if match is None:
                    print("ERROR: Unable to match line: {}".format(line))
                    continue

                matchdict = match.groupdict()
                nodelist.append((matchdict["name"], matchdict["address"]))

        if len(nodelist) != validlines:
            print("Nodelist doesn't match valid lines: {} != {}".format(len(nodelist), validlines))

        print("[+] Loaded {} hosts:".format(len(nodelist)))
        for name, addr in nodelist:
            print("\t{}: {}".format(name, addr))

        for name, addr in nodelist:
            self.add_server(name, addr, password=password, keyfile=keyfile, overwrite=overwrite)


    @need_init
    def exporthosts(self, filename):
        buf = ""
        for server in self.__list_servers():
            buf += "{} {}\n".format(server.addr, server.name)

        with open(filename, "w") as f:
            f.write(buf)


    @need_init
    def status(self):
        print("[+] Status:")
        servers = self.__list_servers()
        for node, retval, out, err in self.__node_exec("whoami", servers):
            print("{}:".format(node))
            print(out, err)

    def __parse_ifconfig(self, buf):
        data = {}
        for line in buf.split("\n"):
            # TODO: this is very brittle
            match = re.search(r" +(?P<direction>[RT]X) packets (?P<packets>\d+) *bytes (?P<bytes>\d+)", line)
            if match is not None:
                matchdict = match.groupdict()
#                data[match["direction"]] = {
#                    "packets": matchdict["packets"],
#                    "bytes": matchdict["bytes"],
#                }
                data[match["direction"]] = int(matchdict["bytes"])
        return data

    def __netstatus_core(self, interval, tui):
        previous = dt.now()
        last = None
        servers = self.__list_servers()
        servernames = [s.name for s in servers]
        while True:
            tui.resetlines()
            tui.print_header()
            # tui.clear()

            current = {}
            for result in self.__node_exec("ifconfig eth0", servers):
                server, retval, out, err = result
                data = self.__parse_ifconfig(out)
                current[server.name] = data

            # calculate delta
            now = dt.now()
            delta = (now-previous).total_seconds()

            # print status
            all_rx, all_tx, all_diff_rx, all_diff_tx, = 0, 0, 0, 0
            for name in servernames:
                if last is None:
                    continue

                old = last.get(name, None)
                new = current.get(name, {})
                old_rx = old.get("RX", 0)
                new_rx = new.get("RX", 0)
                old_tx = old.get("TX", 0)
                new_tx = new.get("TX", 0)

                # TODO: make kbit/mbit etc calculation adaptive
                diff_rx = (new_rx - old_rx) * 8 / 1024 / 1024 / delta
                diff_tx = (new_tx - old_tx) * 8 / 1024 / 1024 / delta
                # tui.print("{} RX: {}, {} TX: {} {}".format(name, old_rx, new_rx, old_tx, new_tx))

                total_rx = new_rx / 1024/1024/1024
                total_tx = new_tx / 1024/1024/1024

                # tui.print("{} RX: {:10.2f} kbit/s TX: {:10.2f} kbit/s - total: RX: {:10.2f} GB TX: {:10.2f} GB".format(name, diff_rx, diff_tx, total_rx, total_tx))
                tui.print_bandwidth(name, diff_rx, diff_tx, total_rx, total_tx)

                all_diff_rx += diff_rx
                all_diff_tx += diff_tx

                all_rx += total_rx
                all_tx += total_tx

            # calculate time to sleep
            sleeptime = max(0, interval-delta)

            if last is not None:
                tui.print()
                # tui.print("date: {}, delta: {:.2f}, sleep time: {:.2f}     TOTAL: RX: {:10.2f} GB TX: {:10.2f} GB".format(now, delta, sleeptime, all_rx, all_tx))
                tui.print_footer(now, delta, sleeptime, all_diff_rx, all_diff_tx, all_rx, all_tx)

            last = current

            # render
            tui.refresh()
            tui.getch()

            # sleep
            # TODO: use sleeptime here, as we have to compensate for the time it takes the fetch to run
            time.sleep(interval)
            previous = now


    @need_init
    def netstatus(self, interval):
        print("[+] Status every {}s:".format(interval))

        tui = TUI()
        tui.start()

        try:
            self.__netstatus_core(interval, tui)
        except KeyboardInterrupt:
            pass
        finally:
            tui.stop()

    def __showpubkey(self):
        print("##################################################")
        print("#        Use this key when creating the VM:      #")
        print("##################################################")
        with open(self.__PUBPATH) as f:
            print(f.read())

    @need_init
    def pubkey(self):
        self.__showpubkey()

    def init(self, email):
        # TODO: validate email properly
        if not self.__first_run:
            print("[-] Torspray init already ran, if you want to re-run init, delete the {} directory".format(
                self.__CONF_DIR))
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
        parser_add.add_argument('-p', '--password', type=str, required=False, help='password')
        parser_add.add_argument('-k', '--keyfile', type=str, required=False, help='keyfile')
        parser_add.add_argument('-f', '--overwrite', action='store_true', required=False, help='overwrite')

        parser_add.set_defaults(func='add')

        parser_list = subparsers.add_parser('list', help='list nodes')
        parser_list.set_defaults(func='list')

        parser_add = subparsers.add_parser('remove', help='remove node from torspray')
        parser_add.add_argument('hostname', type=str, help='hostname')
        parser_add.set_defaults(func='remove')

        parser_clearall = subparsers.add_parser('clear_all', help='remove all servers')
        parser_clearall.set_defaults(func='clear_all')

        parser_importhosts = subparsers.add_parser('importhosts', help='import many hosts from file')
        parser_importhosts.add_argument('filename', type=str, help='filename containing "ip name" pairs, like in /etc/hosts')
        parser_importhosts.add_argument('-p', '--password', type=str, required=False, help='password')
        parser_importhosts.add_argument('-k', '--keyfile', type=str, required=False, help='keyfile')
        parser_importhosts.add_argument('-f', '--overwrite', action='store_true', required=False, help='overwrite')
        parser_importhosts.set_defaults(func='importhosts')

        parser_exporthosts = subparsers.add_parser('exporthosts', help='export hosts to file')
        parser_exporthosts.add_argument('filename', type=str, help='filename to dump hosts to')
        parser_exporthosts.set_defaults(func='exporthosts')

        parser_status = subparsers.add_parser('status', help='list node status')
        parser_status.set_defaults(func='status')

        parser_netstatus = subparsers.add_parser('netstatus', help='list node network status')
        parser_netstatus.add_argument('-i', '--interval', type=int, default=5, help='interval in seconds')
        parser_netstatus.set_defaults(func='netstatus')

        parser_pubkey = subparsers.add_parser('pubkey', help='show public key signature for VM creation')
        parser_pubkey.set_defaults(func='pubkey')

        parser_copyfile = subparsers.add_parser('copyfile', help='copy file to/from node')
        parser_copyfile.add_argument('hostname', type=str)
        parser_copyfile.add_argument('direction', choices=["put", "get"], type=str)
        parser_copyfile.add_argument('src', type=str)
        parser_copyfile.add_argument('dst', type=str)
        parser_copyfile.set_defaults(func='copyfile')

        parser_run = subparsers.add_parser('run', help='run command on node')
        parser_run.add_argument('hostname', type=str)
        parser_run.add_argument('cmd', type=str)
        parser_run.set_defaults(func='run')

        parser_run_all = subparsers.add_parser('run-all', help='run commands on all nodes')
        parser_run_all.add_argument('cmd', type=str)
        parser_run_all.set_defaults(func='run-all')

        parser_shell_exec = subparsers.add_parser('shell', help='spawn pty shell on the node')
        parser_shell_exec.add_argument('hostname', type=str)
        parser_shell_exec.set_defaults(func='shell')

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
            self.add_server(self.__args.hostname, self.__args.address, self.__args.password, self.__args.keyfile, self.__args.overwrite)
        elif func == "list":
            self.list_servers()
        elif func == "remove":
            self.remove_server(self.__args.hostname)
        elif func == "clear_all":
            self.clear_all()
        elif func == "importhosts":
            self.importhosts(self.__args.filename, self.__args.password, self.__args.keyfile, self.__args.overwrite)
        elif func == "exporthosts":
            self.exporthosts(self.__args.filename)
        elif func == "status":
            self.status()
        elif func == "netstatus":
            self.netstatus(self.__args.interval)
        elif func == "pubkey":
            self.pubkey()
        elif func == "copyfile":
            self.copyfile(self.__args.server, self.__args.direction, self.__args.src, self.__args.dst)
        elif func == "run":
            self.exec(self.__args.hostname, self.__args.cmd)
        elif func == "shell":
            self.shell(self.__args.hostname)
        elif func == "run-all":
            self.exec(None, self.__args.cmd)
        elif func == "spray":
            self.spray(self.__args.hostname)
        else:
            self.__parser.print_help()


def main():
    ts = TorSpray()
    ts.main()


if __name__ == "__main__":
    main()
