import paramiko

from .config import CONFIG


class NodeAuthException(Exception):
    pass


class NodeTimeoutException(Exception):
    pass


# TODO:
# - connection management should be improved, particularly unused connections
# - what happens if connection is lost? this should be handled gracefully
class Node:
    def __init__(self, name, addr, hostkeys, privpath, user=CONFIG.USER):
        self.name = name
        self.addr = addr
        self.__hostkeys = hostkeys
        self.__privpath = privpath
        self.__user = user

        self.__pkey = None
        self.__conn = None
        self.__sftp = None

    def __repr__(self):
        return "{} ({})".format(self.name, self.addr)

    def __load_private_key(self):
        if self.__pkey is None:
            self.__pkey = paramiko.RSAKey.from_private_key_file(self.__privpath)

    def __connect_ssh(self, ignore_missing=False):
        if self.__conn is not None:
            return

        client = paramiko.SSHClient()
        client.load_host_keys(self.__hostkeys)

        # load private key
        self.__load_private_key()

        # should we add missing keys?
        if ignore_missing:
            policy = paramiko.AutoAddPolicy()
            client.set_missing_host_key_policy(policy)

        client.connect(self.addr, username=self.__user, pkey=self.__pkey, timeout=CONFIG.TIMEOUT)
        self.__conn = client

    def __connect_sftp(self):
        self.__connect_ssh()
        self.__sftp = self.__conn.open_sftp()

    def connect(self, ignore_missing=False):
        try:
            self.__connect_ssh(ignore_missing)
        except paramiko.ssh_exception.PasswordRequiredException:
            raise NodeAuthException("Could not authenticate to the server, either the key is bad or the password")
        except paramiko.ssh_exception.NoValidConnectionsError:
            raise NodeTimeoutException("Failed to reach node, try again later")

    def disconnect(self):
        if self.__conn is not None:
            self.__conn.close()
            self.__conn = None

    def copyfile(self, direction, src, dst):
        if direction not in ("get", "put"):
            raise ValueError("Invalid value for direction (not 'get' or 'put')")

        self.__connect_sftp()

        if direction == "get":
            self.__sftp.get(src, dst)
        else:
            self.__sftp.put(src, dst)

    def file(self, *args, **kwargs):
        self.__connect_sftp()
        f = self.__sftp.file(*args, **kwargs)
        return f

    def run(self, command, env=None):
        self.__connect_ssh()

        _stdin, stdout, stderr = self.__conn.exec_command(command, environment=env)

        # TODO: merge stdout and stderr!
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()

        # WARNING: anything that comes out here can be MALICIOUS!
        return out, err
