import json

from oslo_log import log

import ovn_k8s
from ovn_k8s import constants
from ovn_k8s import policy_processor as pp
from ovn_k8s.lib import kubernetes as k8s
from ovn_k8s.watcher import registry

LOG = log.getLogger(__name__)
EVENT_MAP = {
    'ADDED': constants.NS_UPDATE,
    'MODIFIED': constants.NS_UPDATE,
}


class NamespaceWatcher(object):

    def __init__(self, ns_stream):
        self._ns_stream = ns_stream
        self.ns_cache = {}
        self.np_watcher = (
            registry.WatcherRegistry.get_instance().k8s_np_watcher)

    def _send_event(self, ns_name, event_type):
        event = ovn_k8s.Event(EVENT_MAP[event_type],
                              source=ns_name,
                              metadata=self.ns_cache[ns_name])
        pp.get_event_queue().put((constants.NS_EVENT_PRIORITY,
                                  event))

    def _set_np_ns_watcher(self, event, namespace):
        """Manage network policy watcher for the namespace."""
        if not self.np_watcher:
            return
        if event == 'ADDED':
            self.np_watcher.add_namespace(namespace)
        elif event == 'DELETED':
            self.np_watcher.remove_namespace(namespace)

    def _process_ns_event(self, event):
        ns_metadata = event['object']['metadata']
        ns_name = ns_metadata['name']
        event_type = event['type']
        self._set_np_ns_watcher(event_type, ns_name)
        if event_type not in EVENT_MAP:
            LOG.debug("Not interested in event:%s for namespace:%s",
                      event_type, ns_name)
            return
        cached_ns = self.ns_cache.get(ns_name, {})
        isolated = None
        was_isolated = None
        was_isolated = cached_ns.get('isolated', False)
        isolated = k8s.is_namespace_isolated(ns_name)
        ns_metadata['isolated'] = isolated
        self.ns_cache[ns_name] = ns_metadata
        # Always send events for namespaces that are not in cache
        if not cached_ns or isolated != was_isolated:
            # Must send event
            self._send_event(ns_name, event_type)
        else:
            LOG.debug("No change deteced in namespace isolation for:%s",
                      ns_name)

    def process(self):
        # This might raise StopIteration
        line = self._ns_stream.next()
        try:
            self._process_ns_event(json.loads(line))
        except ValueError:
            LOG.debug("Invalid JSON data:%s", line)
