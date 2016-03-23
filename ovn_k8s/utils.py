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
