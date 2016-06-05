import random
import subprocess


def call_popen(cmd, input_data):
    """Invoke subprocess"""
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE if input_data else None,
                            stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(input_data)
    if proc.returncode:
        raise RuntimeError("Fatal error executing %s: %s" %
                           (" ".join(cmd), stderr))
    if not stdout:
        stdout = ""
    else:
        stdout = stdout.strip()
    return stdout


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
