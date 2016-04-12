import json

from eventlet import greenthread
from oslo_config import cfg
from oslo_log import log
from six.moves import queue

from ovn_k8s import constants
from ovn_k8s.lib import kubernetes as k8s
from ovn_k8s import policy_processor as pp

LOG = log.getLogger(__name__)
EVENT_MAP = {
    'ADDED': constants.NP_ADD,
    'MODIFIED': constants.NP_UPDATE,
    'DELETED': constants.NP_DEL
}


class NetworkPolicyNSWatcher(object):
    """Watch for changes in network policies for a given namespace."""

    def __init__(self, queue, namespace, np_stream):
        self._namespace = namespace
        self._np_stream = np_stream
        self._queue = queue

    def process(self):
        line = self._np_stream.next()
        try:
            self._queue.put(json.loads(line))
        except ValueError:
            LOG.debug("Invalid JSON data: received from policy watcher for "
                      "namespace %s: %s", self._namespace, line)


class NetworkPolicyWatcher(object):

    def __init__(self):
        self.np_cache = {}
        self.np_ns_map = {}
        self._np_watcher_threads = {}
        self.notifications = queue.Queue()

    def close(self):
        for namespace in self._np_watcher_threads:
            self.remove_namespace(namespace)

    def _generate_watcher(self, namespace):
        np_stream = k8s.watch_network_policies(
            cfg.CONF.k8s_api_server_host,
            cfg.CONF.k8s_api_server_port,
            namespace)
        return NetworkPolicyNSWatcher(self.notifications,
                                      namespace,
                                      np_stream)

    def add_namespace(self, namespace):
        """Add a namespace from which watch network policies."""
        if namespace in self._np_watcher_threads:
            # Already monitoring, do nothing
            LOG.debug("Network policies for namespace: %s already being "
                      "monitored", namespace)
            return
        LOG.debug("Starting network policy watcher for namespace: %s",
                  namespace)

        def _process_loop():
            np_watcher = self._generate_watcher(namespace)
            while True:
                try:
                    np_watcher.process()
                except StopIteration:
                    LOG.debug("The watch stream was closed. Re-opening policy "
                              "watch stream for namespace: %s", namespace)
                    np_watcher = self._generate_watcher(namespace)

        np_watcher_thread = greenthread.spawn(_process_loop)
        self._np_watcher_threads[namespace] = np_watcher_thread

    def remove_namespace(self, namespace):
        np_watcher_thread = self._np_watcher_threads[namespace]
        greenthread.kill(np_watcher_thread)
        del self._np_watcher_threads[namespace]
        policy_names = [policy for (policy, ns)
                        in self.np_ns_map.items()
                        if namespace == ns]
        for policy_name in policy_names:
            del self.np_cache[policy_name]

    def _send_event(self, np_name, event_type, **kwargs):
        event_metadata = self.np_cache[np_name]
        event_metadata.update(kwargs)
        event = pp.Event(EVENT_MAP[event_type],
                         source=np_name,
                         metadata=event_metadata)
        pp.get_event_queue().put((constants.NP_EVENT_PRIORITY,
                                  event))

    def _process_np_event(self, event):
        event_type = event['type']
        np_data = event['object']
        np_name = np_data['metadata']['name']
        ns_name = np_data['metadata']['namespace']
        if event_type not in EVENT_MAP:
            LOG.debug("Not interested in event:%s for namespace:%s",
                      event_type, ns_name)
            return
        cached_np = self.np_cache.get(np_name)
        pod_selector_changed = False
        from_changed = False
        ports_changed = False
        if cached_np:
            # TODO(me): the current code only manages a single ingress rule
            # for each policy.
            old_ingress = cached_np['ingress']
            current_ingress = np_data['ingress']
            # Check for changes in pod selector
            old_pod_selector = cached_np.get('podSelector')
            pod_selector = np_data.get('podSelector')
            pod_selector_changed = (old_pod_selector != pod_selector)
            # Check for changes in from clause
            old_from = old_ingress[0].get('from')
            current_from = current_ingress[0].get('from')
            from_changed = (old_from != current_from)
            # Check for changes in ports clause
            old_ports = old_ingress[0].get('ports')
            current_ports = current_ingress[0].get('ports')
            ports_changed = (old_ports != current_ports)
        if (not cached_np or pod_selector_changed or
            from_changed or ports_changed):
            # There are changes that need to be processed
            self.np_cache[np_name] = np_data
            self.np_ns_map[np_name] = ns_name
            self._send_event(np_name, event_type,
                             pod_selector_changed=pod_selector_changed,
                             from_changed=from_changed,
                             ports_changed=ports_changed)
        elif event_type == 'DELETED':
            # TODO(me): At some point the policy should be removed from the
            # cache
            self._send_event(np_name, event_type)

    def process(self):
        self._process_np_event(self.notifications.get())
