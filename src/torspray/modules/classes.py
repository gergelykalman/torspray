import os


class SprayBase:
    def __init__(self, node, env):
        self.__node = node
        self.__env = env

    def run(self, cmd, env_param=None):
        if env_param is None:
            env = self.__env
        else:
            env = env_param

        retval, out, err = self.__node.run(cmd, env)
        print("$ {}".format(cmd))
        print(out)
        if retval != 0:
            print("ERROR in command {} (retval: {}):".format(cmd, retval))
            print(err)
            exit(1)
        return retval, out, err

    def get_osrelease(self):
        version = None
        codename = None
        with self.__node.file("/etc/os-release") as f:
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

    def get_arch(self):
        retval, out, err = self.__node.run("dpkg --print-architecture")
        arch = out.strip()
        return arch

    def file(self, *args, **kwargs):
        f = self.__node.file(*args, **kwargs)
        return f

    def writeconfig(self, filename, content, map=None):
        if map is not None:
            for k, v in map.items():
                content = content.replace(k, v)

        with self.file(filename, "wt") as f:
            f.write(content)

    def editconfig(self, filename, old, new):
        # TODO: this is really stupid
        with self.file(filename, "ra") as f:
            f.seek(os.SEEK_SET, 0)
            contents = f.read().decode("utf-8")
            contents = contents.replace(old, new)
            f.truncate(0)
            f.write(contents)
