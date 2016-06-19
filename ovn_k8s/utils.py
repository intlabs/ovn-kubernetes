import json
import random
import subprocess

from oslo_log import log

LOG = log.getLogger(__name__)


def call_popen(cmd, input_data=None):
    """Invoke subprocess"""
    proc = subprocess.Popen(cmd,
                            stdin=subprocess.PIPE if input_data else None,
                            stdout=subprocess.PIPE)
    stdout, stderr = proc.communicate(input_data)
    if proc.returncode:
        raise RuntimeError("Fatal error executing %s: %s" %
                           (" ".join(cmd), stdout))
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


def process_stream(data_stream, event_callback):
    # StopIteration will be caught in the routine that sets up the stream
    # and reconnects it
    line = data_stream.next()
    try:
        event_callback(json.loads(line))
    except ValueError:
        LOG.debug("Invalid JSON data from response stream:%s", line)
