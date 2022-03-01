import os
import random

UNATTENDED_UPGRADES_CFG = """
Unattended-Upgrade::Origins-Pattern {
    "origin=Debian,codename=${distro_codename},label=Debian-Security";
    "origin=TorProject";
};
Unattended-Upgrade::Package-Blacklist {
};
Unattended-Upgrade::Automatic-Reboot "true";
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


class Debian11Bridge:
    def __init__(self, contactinfo, node, portrange):
        self.contactinfo = contactinfo
        self.node = node
        self.portrange = portrange

        self.env = {
            "DEBIAN_FRONTEND": "noninteractive"
        }

    def __run(self, cmd, env_param=None):
        # TODO: check retvals and err!
        if env_param is None:
            env = self.env
        else:
            env = env_param

        out, err = self.node.run(cmd, env)
        print("$ {}".format(cmd))
        print(out)
        if len(err) > 0:
            print("ERROR in command {}:".format(cmd))
            print(err)
            # exit(1)
        return out, err

    def __get_osrelease(self):
        version = None
        codename = None
        with self.node.file("/etc/os-release") as f:
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

        return version, codename

    def __get_arch(self):
        out, err = self.node.run("dpkg --print-architecture")
        arch = out.strip()
        return arch

    def spray(self):
        print("[+] Spray verifying versions")
        version, codename = self.__get_osrelease()
        arch = self.__get_arch()

        if version != "Debian GNU/Linux" or codename != "bullseye":
            print("ERROR This Distribution/version is unsupported: version: {}, codename: {}".format(version, codename))
            exit(1)

        if arch not in ("amd64",):
            print("ERROR This architecture is not supported: {}".format(arch))
            exit(1)

        print("\tversion: {}\n\tcodename: {}\n\tarch: {}".format(version, codename, arch))


        ### Based on: https://community.torproject.org/relay/setup/guard/debian-ubuntu/updates/
        print("[+] Spray enabling updates")
        self.__run("apt-get update")
        self.__run("apt-get upgrade -y")
        self.__run("apt-get install -y unattended-upgrades apt-listchanges")

        with self.node.file("/etc/apt/apt.conf.d/50unattended-upgrades", "wt") as f:
            f.write(UNATTENDED_UPGRADES_CFG)

        with self.node.file("/etc/apt/apt.conf.d/20auto-upgrades", "wt") as f:
            f.write(UNATTENDED_AUTO_CFG)

        # self.__run(conn, "unattended-upgrade --debug --dry-run")


        ### Based on: https://support.torproject.org/apt/tor-deb-repo/
        print("[+] Spray configuring tor repo")
        self.__run("apt-get install -y apt-transport-https gpg")

        with self.node.file("/etc/apt/sources.list.d/tor.list", "wt") as f:
            config = TOR_SOURCES_LIST.replace("###DISTRIBUTION###",
                                              codename)
            f.write(config)

        self.__run("wget -qO- https://deb.torproject.org/torproject.org/A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89.asc | gpg --dearmor | tee /usr/share/keyrings/tor-archive-keyring.gpg >/dev/null")

        self.__run("apt-get update")
        self.__run("apt-get install -y tor deb.torproject.org-keyring")


        ### Based on: https://community.torproject.org/relay/setup/bridge/debian-ubuntu/
        print("[+] Spray installing packages")
        self.__run("apt-get update")
        self.__run("apt-get install -y tor")
        self.__run("apt-get install -y obfs4proxy")

        with self.node.file("/etc/tor/torrc", "wt") as f:
            config = CONFIG_TORRC
            for old, new in (
                            ("###TODO1###", str(random.randint(*self.portrange))),
                            ("###TODO2###", str(random.randint(*self.portrange))),
                            ("###CONTACTINFO###", self.contactinfo),
                            # TODO: support this in the future
                            # ("###NICKNAME###", nickname),
            ):
                config = config.replace(old, new)
            f.write(config)

        self.__run("setcap cap_net_bind_service=+ep /usr/bin/obfs4proxy")

        for filename in ["/lib/systemd/system/tor@default.service",
                         "/lib/systemd/system/tor@.service"]:
            with self.node.file(filename, "ra") as f:
                f.seek(os.SEEK_SET, 0)
                contents = f.read().decode("utf-8")
                contents = contents.replace("NoNewPrivileges=yes", "NoNewPrivileges=no")

                f.truncate(0)
                f.write(contents)

        self.__run("systemctl daemon-reload")

        self.__run("systemctl enable --now tor.service")
        self.__run("systemctl restart tor.service")

        # test, check logs:
        # TODO
        # self.__run(conn, "journalctl -e -u tor@default | grep \"Self-testing indicates\"")
