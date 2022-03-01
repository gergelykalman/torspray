import os
import random

import paramiko


def generate_key(privname, pubname, overwrite=False):
    if not overwrite:
        for name, filename in (
                        ("private", privname),
                        ("public", pubname)):
            if os.path.exists(filename):
                return filename

    # private part
    privkey = paramiko.RSAKey.generate(4096)
    privkey.write_private_key_file(privname)

    # public part
    with open(os.path.expanduser(pubname), "w") as f:
        f.write("{} {} {}".format(
            privkey.get_name(),
            privkey.get_base64(),
            "torspray-{:x}@home".format(random.randint(2 ** 31, 2 ** 32)),
        ))


def remove_hostkeys(address, hostkeys_filename):
    print("Clearing host from hostkeys")
    hostkeys = paramiko.HostKeys(hostkeys_filename)
    if hostkeys.get(address) is not None:
        del hostkeys[address]
    hostkeys.save(hostkeys_filename)
