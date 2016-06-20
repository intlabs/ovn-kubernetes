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


def _scalar_diff(old_value, new_value):
    if old_value != new_value:
        return {'old': old_value, 'new': new_value}


def has_changes(new_value, old_value):
    """Detect changes in an object, assumed to be accessible as a dict.

    :param new_value: current state of the object
    :param old_value: previous state of the object
    :returns: a dict describing changes to the object
    """
    # Special case for strings. Treating them as lists is just unnecessary
    # complexity
    if isinstance(new_value, str) and isinstance(old_value, str):
        return _scalar_diff(old_value, new_value)

    # Check if we're dealing with a dict
    try:
        new_value = new_value.items()
        old_value_dict = old_value
        old_value = old_value.items()
        old_value_copy = old_value_dict.copy()
        is_dict = True
    except AttributeError:
        # not a dict, maybe it's iterable anyway
        is_dict = False
        try:
            old_value_copy = list(old_value[:])
        except TypeError:
            # if it's not iterabile, then it must be scalar. Or at least we
            # can consider it as a scalar.
            return _scalar_diff(old_value, new_value)

    compare_result = {}
    try:
        for new_item in new_value:
            if is_dict:
                # Leverage O(1) search in dicts
                try:
                    old_item = old_value_copy[new_item[0]]
                    ret_value = has_changes(
                        old_item, new_item[1])
                    if ret_value:
                        compare_result[new_item[0]] = ret_value
                    del old_value_copy[new_item[0]]
                except KeyError:
                    compare_result[new_item[0]] = {'added': new_item[1]}
            else:
                found = None
                for old_item in old_value:
                    ret_value = has_changes(old_item, new_item)
                    if not ret_value:
                        found = old_item
                        break
                if found is None:
                    compare_result[new_item] = {'added': None}
                else:
                    old_value_copy.remove(found)
        # Any iteam left in old_value_copy at this stage has been removed from
        # new_value
        for item in old_value_copy:
            compare_result[item] = {'deleted': None}
    except TypeError:
        # If we end up here either the old or new value, or both, are not
        # iterable. Do a scalar comparison.
        return _scalar_diff(old_value, new_value)

    return compare_result
