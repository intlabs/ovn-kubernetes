from oslo_log import log

import ovn_k8s
from ovn_k8s import constants
from ovn_k8s import conn_processor as cp
from ovn_k8s import policy_processor as pp
from ovn_k8s import utils

LOG = log.getLogger(__name__)
EVENT_MAP = {
    'ADDED': constants.POD_ADD,
    'MODIFIED': constants.POD_UPDATE,
    'DELETED': constants.POD_DEL
}

INFRA_CTR_ID = "infraContainerID"
POD_IP = "podIP"
POD_MAC = "podMAC"
NODE_NAME = "nodeName"
CONN_REQUIRED_KEYS = set([POD_IP, POD_MAC, NODE_NAME, INFRA_CTR_ID])


class PodWatcher(object):

    def __init__(self, pod_stream):
        self._pod_stream = pod_stream
        self.pod_cache = {}

    def _send_policy_event(self, event_type, pod_name, pod_data):
        ev = ovn_k8s.Event(EVENT_MAP[event_type],
                           source=pod_name,
                           metadata=self.pod_cache[pod_name])
        pp.get_event_queue().put((constants.POD_EVENT_PRIORITY, ev))

    def _send_connectivity_event(self, event_type, pod_name, pod_data):
        ev = ovn_k8s.Event(EVENT_MAP[event_type],
                           source=pod_name,
                           metadata=pod_data)
        cp.get_event_queue().put((constants.POD_EVENT_PRIORITY, ev))

    def _check_pod_data(self, pod_name, pod_data):
        pod_annotations = pod_data['metadata'].get('annotations', {})
        required_conn_data = {
            POD_IP: pod_data['status'].get(POD_IP),
            POD_MAC: pod_annotations.get(POD_MAC),
            NODE_NAME: pod_data['spec'].get(NODE_NAME),
            INFRA_CTR_ID: pod_annotations.get(INFRA_CTR_ID)
        }
        return all(required_conn_data.values())

    def _update_pod_cache(self, event_type, pod_name, pod_data):
        # Remove item from cache if it was deleted
        if event_type == 'DELETED':
            del self.pod_cache[pod_name]
        else:
            # Update cache
            self.pod_cache[pod_name] = pod_data

    def _process_pod_event(self, event):
        pod_data = event['object']
        pod_name = pod_data['metadata']['name']
        event_type = event['type']
        cached_pod = self.pod_cache.get(pod_name, {})
        if not self._check_pod_data(pod_name, pod_data):
            LOG.info("Not enough data for configuring connectivity and "
                     "policies for Pod:%s", pod_name)
            return

        has_conn_event = False
        has_policy_event = False
        if not cached_pod:
            has_conn_event = True
            has_policy_event = True
        elif event_type == 'DELETED':
            has_conn_event = True
            has_policy_event = True
        else:
            pod_changes = utils.has_changes(cached_pod, pod_data)
            status_changes = POD_IP in pod_changes.get('status', {})
            spec_changes = NODE_NAME in pod_changes.get('spec')
            pod_meta_changes = pod_changes.get('metadata')
            ann_changes = (POD_MAC in pod_meta_changes.get('annotations') or
                           POD_IP in pod_meta_changes.get('annotations'))
            label_changes = pod_meta_changes.get('labels')

            if not any(status_changes, spec_changes, ann_changes):
                LOG.info("No relevant connectivity change for Pod:%s, "
                         "not sending event", pod_name)
            else:
                has_conn_event = True
            if not label_changes:
                LOG.info("No relevant network policy changes for Pod:%s, "
                         "not sending event", pod_name)
            else:
                has_policy_event = True

        if has_conn_event:
            LOG.debug("Sending connectivity event for event %s on pod %s",
                      event_type, pod_name)
            self._send_connectivity_event(event_type, pod_name, pod_data)
        if has_policy_event:
            LOG.debug("Sending policy event for event %s on pod %s",
                      event_type, pod_name)
            self._send_policy_event(event_type, pod_name, pod_data)

    def process(self):
        utils.process_stream(self._pod_stream,
                             self._process_pod_event)
