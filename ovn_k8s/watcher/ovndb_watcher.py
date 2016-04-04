import re

from oslo_log import log
from ovn_k8s import constants
from ovn_k8s import policy_processor as pp

LOG = log.getLogger(__name__)
ACTION_EVENT_MAP = {
    'new': constants.LPORT_ADD,
    'initial': constants.LPORT_ADD,
    'insert': constants.LPORT_ADD,
    'delete': constants.LPORT_DEL
}


def _build_external_ids_dict(ext_id_str):
    ext_id_str = ext_id_str.strip('{}').strip()
    if not ext_id_str:
        return {}
    ext_id_items = [item.split('=') for item in ext_id_str.split(',')]
    return dict((item[0].strip(' "'), item[1]) for item in ext_id_items)


class OvndbWatcher(object):
    """Watch ovsdb-client monitor output and generate events."""

    def __init__(self, monitor_output):
        self.monitor_output = monitor_output

    def _parse_line(self, line, updated_row=None):
        items = re.findall(r"\[.*?\]|\{.*?\}|\s*?[^\s\[\{\}\]]+?\s", line)
        # 'new' action does not begin with a row identifier
        if updated_row:
            row = None
            action_idx = 0
            external_ids_idx = 3
        else:
            row = items[0].strip()
            action_idx = 1
            external_ids_idx = 4

        action = items[action_idx].strip()
        # External ids is a composite attribute, here extracted as a string
        if external_ids_idx < len(items):
            external_ids_raw = items[external_ids_idx].strip()
        else:
            external_ids_raw = None
        return row, action, external_ids_raw

    def _send_event(self, row, action, external_ids):
        event = pp.Event(ACTION_EVENT_MAP[action],
                         source=row,
                         metadata=external_ids)
        pp.get_event_queue().put((constants.LPORT_EVENT_PRIORITY,
                                  event))

    def process(self):
        line = self.monitor_output.readline()
        if line.strip():
            row, action, external_ids_raw = self._parse_line(line)
            # This should automatically exclude lines which contain column
            # headers or dashes
            if action == 'old':
                # There should never be a 'old' event followed by the same
                # event before a 'new' event occurs (hopefully)
                # Read next line
                new_line = self.monitor_output.readline()
                _, action, external_ids_raw = self._parse_line(
                    new_line, True)
            elif action not in ('initial', 'new', 'delete'):
                return
            external_ids = _build_external_ids_dict(external_ids_raw)
            if 'pod_name' in external_ids:
                self._send_event(row, action, external_ids)
