import os
import json

from .config import CONFIG


class DB:
    def __init__(self, configname, hostkeys):
        self.__confdir = os.path.dirname(configname)
        self.__configname = configname
        self.__hostkeys = hostkeys

    def init_config(self, contactinfo):
        try:
            os.makedirs(self.__confdir, 0o750)
        except FileExistsError:
            pass

        with open(self.__configname, "w") as f:
            cfg = {
                "servers": {},
                "torspray": {
                    "contactinfo": contactinfo,
                    "version": CONFIG.VERSION,
                }
            }
            json.dump(cfg, f, sort_keys=True, indent=4)

        # create an empty hostkeys file
        with open(self.__hostkeys, "w") as f:
            pass

    def is_first_run(self):
        try:
            self.__read()
        except FileNotFoundError:
            return True
        else:
            return False

    def __read(self):
        with open(self.__configname, "r") as f:
            cfg = json.load(f)
        return cfg

    def __write(self, cfg):
        with open(self.__configname, "w") as f:
            json.dump(cfg, f, sort_keys=True, indent=4)

    def list_servers(self, filter=None):
        servers = {}
        cfg = self.__read()
        for name, data in cfg["servers"].items():
            if filter is None or name == filter:
                servers[name] = data
        return servers

    def getcontactinfo(self):
        cfg = self.__read()
        return cfg["torspray"]["contactinfo"]

    def get_server(self, nodename):
        cfg = self.__read()
        return cfg["servers"].get(nodename)

    def add_server(self, hostname, address, overwrite):
        cfg = self.__read()

        cfg["servers"][hostname] = {
            "hostname": hostname,
            "address": address,
        }

        self.__write(cfg)

    def remove_server(self, nodename):
        cfg = self.__read()
        if cfg["servers"].get(nodename) is not None:
            del cfg["servers"][nodename]
            self.__write(cfg)
