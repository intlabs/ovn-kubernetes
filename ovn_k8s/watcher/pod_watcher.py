import json

from oslo_log import log

from ovn_k8s import constants
from ovn_k8s import policy_processor as pp

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

    def _send_event(self, pod_name, event_type):
        event = pp.Event(EVENT_MAP[event_type],
                         source=pod_name,
                         metadata=self.pod_cache[pod_name])
        pp.get_event_queue().put((constants.POD_EVENT_PRIORITY,
                                  event))

    def _process_pod_event(self, event):
        pod_ip = event['object']['status'].get('podIP')
        pod_metadata = event['object']['metadata']
        cached_pod = self.pod_cache.get(pod_metadata['name'])
        if cached_pod and not pod_ip:
            pod_ip = cached_pod['status'].get('podIP')
        if not pod_ip:
            LOG.debug("No IP address yet assigned to pod %s - skipping",
                      pod_metadata['name'])
            return
        event_type = event['type']
        if cached_pod and event_type != 'DELETED':
            # Check whether the event is worth being considered
            if (pod_ip == cached_pod['status']['podIP'] and
                pod_metadata['labels'] == cached_pod['metadata']['labels']):
                LOG.debug("No relevant change for pod %s - skipping",
                          pod_metadata['name'])
                return
        # If we hit this line the cache needs to be updated
        self.pod_cache[pod_metadata['name']] = event['object']
        LOG.debug("Sending event %s for pod %s",
                  event_type, pod_metadata['name'])
        self._send_event(pod_metadata['name'], event_type)
        if event_type == 'DELETED':
            del self.pod_cache[pod_metadata['name']]

    def process(self):
        # This might raise StopIteration
        line = self._pod_stream.next()
        try:
            self._process_pod_event(json.loads(line))
        except ValueError:
            LOG.debug("Invalid JSON data:%s", line)
