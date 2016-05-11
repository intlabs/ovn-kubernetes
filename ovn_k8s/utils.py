import random
import subprocess


def call_popen(cmd):
    """Invoke subprocess"""
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = child.communicate()
    if child.returncode:
        raise RuntimeError("Fatal error executing %s" % " ".join(cmd))
    if not output or not output[0]:
        output = ""
    else:
        output = output[0].strip()
    return output


def generate_mac(prefix="00:00:00"):
    random.seed()
    # This is obviously not collition free, but come on! Seriously,
    # please fix this, eventually
    mac = "%s:%02X:%02X:%02X" % (
        prefix,
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255))
    return mac
