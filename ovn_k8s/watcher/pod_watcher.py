import json

from oslo_log import log

import ovn_k8s
from ovn_k8s import constants
from ovn_k8s import policy_processor as pp
from ovn_k8s import conn_processor as cp

LOG = log.getLogger(__name__)
EVENT_MAP = {
    'ADDED': constants.POD_ADD,
    'MODIFIED': constants.POD_UPDATE,
    'DELETED': constants.POD_DEL
}


class PodWatcher(object):

    def __init__(self, pod_stream):
        self._pod_stream = pod_stream
        self.pod_cache = {}

    def _send_policy_event(self, pod_name, event_type):
        ev = ovn_k8s.Event(EVENT_MAP[event_type],
                           source=pod_name,
                           metadata=self.pod_cache[pod_name])
        pp.get_event_queue().put((constants.POD_EVENT_PRIORITY, ev))

    def _send_connectivity_event(self, pod_name, event_type):
        ev = ovn_k8s.Event(EVENT_MAP[event_type],
                           source=pod_name,
                           metadata=self.pod_cache[pod_name])
        cp.get_event_queue().put((constants.POD_EVENT_PRIORITY, ev))

    def _process_pod_policies(self, pod_name, event_type, event, cached_pod):
        LOG.debug("Checking policy event %s for pod %s",
                  event_type, pod_name)
        pod_ip = event['object']['status'].get('podIP')
        pod_metadata = event['object']['metadata']
        if cached_pod and not pod_ip:
            pod_ip = cached_pod['status'].get('podIP')
        if not pod_ip:
            LOG.debug("No IP address yet assigned to pod %s - skipping",
                      pod_name)
            return
        if cached_pod:
            # Check whether the event is worth being considered
            if (pod_metadata['labels'] != cached_pod['metadata']['labels']):
                LOG.debug("Detected label change for pod %s", pod_name)
                return True

    def _process_pod_connectivity(self, pod_name, event_type,
                                  event, cached_pod):
        LOG.debug("Checking connectivity event %s for pod %s",
                  event_type, pod_name)
        # Always process upon deletion as logical port and acls must be
        # destroyed
        if event_type == 'DELETED':
            return True
        # Process when node Name, pod IP, pod MAC, and Infra container ID are
        # available, but avoid sending duplicate events
        pod_ip = event['object']['status'].get('podIP')
        pod_mac = event['object']['metadata']['annotations'].get('podMAC')
        pod_infra_id = event['object']['metadata']['annotations'].get(
            'infraContainerId')
        node_name = event['object']['spec'].get('nodeName')
        if pod_ip and pod_mac and pod_infra_id and node_name:
            if not cached_pod:
                return True
            if (pod_ip != cached_pod['status'].get('podIP') or
                pod_mac != cached_pod['metadata']['annotations'].get(
                    'podMAC') or
                pod_infra_id != cached_pod['metadata']['annotations'].get(
                    'infraContainerId') or
                node_name != cached_pod['spec'].get('nodeName')):
                return True
        LOG.debug("Will not send a connectivity event for pod: %s", pod_name)

    def _process_pod_event(self, event):
        pod_name = event['object']['metadata']['name']
        event_type = event['type']
        cached_pod = self.pod_cache.get(pod_name)
        conn_event = self._process_pod_connectivity(pod_name, event_type,
                                                    event, cached_pod)
        policy_event = self._process_pod_policies(pod_name, event_type,
                                                  event, cached_pod)
        if conn_event or policy_event:
            # Update cache
            self.pod_cache[pod_name] = event['object']
            if conn_event:
                LOG.debug("Sending connectivity event for event %s on pod %s",
                          event_type, pod_name)
                self._send_connectivity_event(pod_name, event_type)
            if policy_event:
                LOG.debug("Sending policy event %s for pod %s",
                          event_type, pod_name)
                self._send_policy_event(pod_name, event_type)

        # Remove item from cache if it was deleted
        if event_type == 'DELETED':
            del self.pod_cache[pod_name]

    def process(self):
        # This might raise StopIteration
        line = self._pod_stream.next()
        try:
            self._process_pod_event(json.loads(line))
        except ValueError:
            LOG.debug("Invalid JSON data:%s", line)
