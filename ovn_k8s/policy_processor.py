import time

from oslo_config import cfg
from oslo_log import log
from six.moves import queue

from ovn_k8s import constants
from ovn_k8s.lib import kubernetes as k8s
from ovn_k8s.lib import ovn
from ovn_k8s import utils
from ovn_k8s.watcher import registry

LOG = log.getLogger(__name__)
WATCHER_REGISTRY = registry.WatcherRegistry.get_instance()


class Event(object):

    def __init__(self, event_type, source, metadata):
        self.event_type = event_type
        self.source = source
        self.metadata = metadata


def _process_ovn_db_change(row, action, external_ids):
    pod_name = external_ids[constants.K8S_POD_NAME.lower()]
    pod_ns = external_ids.get(constants.K8S_POD_NAMESPACE.lower(), 'default')
    LOG.info("Processing OVN DB action '%s' for row %s - external_ids: %s",
             action, row, external_ids)
    old_acls_raw = ovn.ovn_nbctl('find', 'ACL',
                                 'external_ids:pod_name=%s' % pod_name)
    old_acls = ovn.parse_ovn_nbctl_output(old_acls_raw)
    acls = []
    if action != 'delete':
        LOG.debug("Retrieving isolation status for namespace: %s", pod_ns)
        if not _is_namespace_isolated(pod_ns):
            LOG.debug("Namespace %s not isolated, whitelisting all traffic",
                      pod_ns)
            acls.append((constants.DEFAULT_ACL_PRIORITY,
                         r'outport\=\=\"%s\"\ &&\ ip' % row,
                         'allow-related'))
            # Find lswitch for lport
            ls_data_raw = ovn.ovn_nbctl('find', 'Logical_Switch',
                                        'ports{>=}%s' % row)
            ls_data = ovn.parse_ovn_nbctl_output(ls_data_raw)
            ls_data = ls_data[0]
            ls_name = ls_data['name'].strip('"')
        else:
            # Do policies only if isolation is on
            LOG.debug("Retrieving policies in namespace ... for pod %s",
                      pod_name)
            LOG.debug("Fetching IP address for Pods in from clause")
    elif old_acls:
        # For delete operations the logical port is unfortunately gone... but
        # the logical switch can be found from existing ACLs, and if there are
        # no existing ACLs then there's just nothing to do e bonanott
        ls_data_raw = ovn.ovn_nbctl('find', 'Logical_Switch',
                                    'acls{>=}%s' % old_acls[0]['_uuid'])
        ls_data = ovn.parse_ovn_nbctl_output(ls_data_raw)
        ls_data = ls_data[0]
        ls_name = ls_data['name'].strip('"')

    # TODO(me): Program ACLs without leaving even a fraction of second in
    # which the container is not secured
    if acls:
        LOG.debug("Implementing OVN ACLS for pod %s on lswitch %s",
                  pod_name, ls_name)
    for acl in acls:
        ovn.create_ovn_acl(ls_name, pod_name, row, *acl)
    LOG.debug("Removing existing ACLS for pod %s on lswitch %s",
              pod_name, ls_name)
    for acl in old_acls:
        ovn.ovn_nbctl('remove', 'Logical_Switch', ls_name,
                      'acls', acl['_uuid'])
    LOG.info("ACLs for Pod: %s configured", pod_name)


def _find_lswitch(lport_name):
    # Find lswitch for lport... to this aim we might use the port uuid
    lp_data_raw = ovn.ovn_nbctl('find', 'Logical_Port',
                                'name=%s' % lport_name)
    lp_data = ovn.parse_ovn_nbctl_output(lp_data_raw)
    lp_data = lp_data[0]
    ls_data_raw = ovn.ovn_nbctl('find', 'Logical_Switch',
                                'ports{>=}%s' % lp_data['_uuid'])
    ls_data = ovn.parse_ovn_nbctl_output(ls_data_raw)
    ls_data = ls_data[0]
    return ls_data['name'].strip('"')


def _whitelist_pod_traffic(pod_name):
    lport_data_raw = ovn.ovn_nbctl(
        'find', 'Logical_Port', 'external_ids:pod_name=%s' % pod_name)
    lport_data = ovn.parse_ovn_nbctl_output(lport_data_raw)
    lport_data = lport_data[0]
    lport_name = lport_data['name'].strip('"')
    whitelist_acl = (constants.DEFAULT_ALLOW_ACL_PRIORITY,
                     r'outport\=\=\"%s\"\ &&\ ip' % lport_name,
                     'allow-related')
    ls_name = _find_lswitch(lport_name)
    ovn.create_ovn_acl(ls_name, pod_name, lport_name, *whitelist_acl)
    LOG.info("ACLs for Pod: %s configured", pod_name)


def _get_acls(pod_name):
    acls_raw = ovn.ovn_nbctl('find', 'ACL',
                             'external_ids:pod_name=%s' % pod_name)
    return ovn.parse_ovn_nbctl_output(acls_raw)


def _remove_acls(acls, remove_default_drop=False):
    # For delete operations the logical port is unfortunately gone... but
    # the logical switch can be found from existing ACLs, and if there are
    # no existing ACLs then there's just nothing to do e bonanott
    if not acls:
        return
    ls_data_raw = ovn.ovn_nbctl('find', 'Logical_Switch',
                                'acls{>=}%s' % acls[0]['_uuid'])
    ls_data = ovn.parse_ovn_nbctl_output(ls_data_raw)
    ls_data = ls_data[0]
    ls_name = ls_data['name'].strip('"')
    for acl in acls:
        if (not remove_default_drop and
            int(acl['priority']) == constants.DEFAULT_ACL_PRIORITY):
            # Do not drop the default drop rule
            continue
        ovn.ovn_nbctl('remove', 'Logical_Switch', ls_name,
                      'acls', acl['_uuid'])


def _remove_all_acls(pod_name):
    old_acls = _get_acls(pod_name)
    if not old_acls:
        # nothing to do - but log because it should never happen
        LOG.warn("No ACL found for pod:%s", pod_name)
        return
    _remove_acls(old_acls, remove_default_drop=True)
    LOG.info("ACLs for Pod: %s removed", pod_name)


def process_namespace_isolation_off(events):
    """Whitelist all traffic for pod in non-isolated namespaces.

    Select namepace events from events, then find those where isolation
    has been turned off. Find all pods in the namespace, and whitelist
    traffic for them.
    There is no need to take into account new pods from lport events,
    as such pods will be retrieved with the list operation performed here.

    :param events: Events to process
    """
    selected_namespaces = []
    selected_pods = []
    for event in events[:]:
        if (event.event_type == constants.NS_UPDATE and
            not event.metadata['isolated']):
            selected_namespaces.append(event.metadata['name'])
            events.remove(event)
    LOG.debug("Whitelisting all traffic for pods in namespaces:%s",
              ",".join(selected_namespaces))
    for namespace in selected_namespaces:
        pod_list = k8s.get_pods(cfg.CONF.k8s_api_server_host,
                                cfg.CONF.k8s_api_server_port,
                                namespace)
        selected_pods.extend([pod['metadata']['name'] for pod in pod_list])
    for pod in selected_pods:
        current_acls = _get_acls(pod)
        _whitelist_pod_traffic(pod)
        _remove_acls(current_acls)
    LOG.debug("Traffic for %d pods was whitelisted", len(selected_pods))
    return events


def process_pod_deletion(events):
    """Remove ACLs for deleted pods.

    This routine handles lport events for pod deletion, rather
    than Pod DELETED events - in order to ensure no network connection
    exists anymore when the ACLs are deleted.

    :param events: events to process
    """
    selected_pods = []
    for event in events[:]:
        if event.event_type == constants.LPORT_DEL:
            selected_pods.append(event.metadata['pod_name'])
            events.remove(event)
    for pod in selected_pods:
        _remove_all_acls(pod)
    return events


class PolicyProcessor(object):

    _instance = None

    def __init__(self):
        self.event_queue = queue.PriorityQueue()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def process_events(self, events):
        # Compile pod list PL where policies are applied. Also include pods
        # from new lport events.
        # namespace events on->off: immediately whitelist traffic for all
        # corresponding pods in PL; remove items from PL
        # namespace events off->on: add items to PL
        # if PL is empty goodbye
        # policy por pod event -> rebuild pseudo-acl list
        # for each element in PL -> apply OVN acls from pseudo-acl list
        LOG.debug("Processing %d events from queue", len(events))
        # The easy bits first. Whitelist all traffic for pod in namespaces
        # where isolation was turned off
        events = process_namespace_isolation_off(events)
        LOG.debug("Pod whitelisting performed. %d events remaining",
                  len(events))
        if not events:
            return
        events = process_pod_deletion(events)
        LOG.debug("ACLs for removed PODs deleted. %d events remaining",
                  len(events))
        if not events:
            return

        # Pods affected by events
        # 1) Pod event -> affects network policies -> affects all pods
        #    selected by policies
        # 2) Policy event -> affect all pods selected by policies
        # 3) lport event -> affects just that pod
        # 4) namespace event -> affect pods in the namespace
        affected_pods = {}
        for event in events:
            if event.event_type in (constants.POD_ADD,
                                    constants.POD_UPDATE,
                                    constants.POD_DEL):
                pod_name = event.metadata['metadata']['name']
                affected_pods[pod_name] = {
                    'namespace': event.metadata['metadata']['namespace'],
                    'events': [event]}
            elif event.event_type == constants.LPORT_ADD:
                affected_pods[event.metadata['pod_name']] = {
                    'namespace': event.metadata['ns_name'],
                    'events': [event]}
        LOG.debug("Rebuilding ACLs for pods:%s", affected_pods)
        pod_watcher = WATCHER_REGISTRY.k8s_pod_watcher
        if not pod_watcher:
            LOG.warn("Pod watcher not set. Unable to program ACLs")
            # TODO(me): Decide whether this should trigger exception
            return
        ns_watcher = WATCHER_REGISTRY.k8s_ns_watcher
        if not ns_watcher:
            LOG.warn("Namespace watcher not set. Unable to program ACLs")
            # TODO(me): Decide whether this should trigger exception
            return

        pod_cache = pod_watcher.pod_cache
        ns_cache = ns_watcher.ns_cache
        for pod, events in affected_pods.items():
            namespace = events['namespace']
            pod_data = pod_cache.get(pod)
            if not pod_data:
                # Note: the information needed are very likely to be in the
                # event metadata. The code could be optimized by parsing those
                # as well.
                pod_data = k8s.get_pod(cfg.CONF.k8s_api_server_host,
                                       cfg.CONF.k8s_api_server_port,
                                       namespace, pod)
            ns_data = ns_cache.get(namespace)
            if not ns_data:
                ns_data = k8s.get_namespace(cfg.CONF.k8s_api_server_host,
                                            cfg.CONF.k8s_api_server_port,
                                            namespace)
                ns_data['isolated'] = utils.is_namespace_isolated(namespace)

            current_acls = _get_acls(pod)
            if not ns_data.get('isolated', False):
                LOG.debug("Pod %s deployed in non-isolated namespace: %s."
                          "Whitelisting traffic", pod, namespace)
                _whitelist_pod_traffic(pod)
            _remove_acls(current_acls)
            LOG.debug("ACLs for Pod %s processed", pod)

        LOG.info("Event processing terminated. ACLs configured")

    def run(self):
        empty_loop_counter = 1
        events = []
        while True:
            # get will retrieve a tuple whose first element is the
            # priority that we can discard
            try:
                # Not sure how wait with timeout plays with eventlet
                event = self.event_queue.get_nowait()[1]
                events.append(event)
                LOG.debug("Received event %s from %s",
                          event.event_type,
                          event.source)
                empty_loop_counter = 1
            except queue.Empty:
                # no element in the queue
                if events:
                    empty_loop_counter = empty_loop_counter - 1
                    if empty_loop_counter < 0:
                        # process events
                        self.process_events(events)
                        events = []
                time.sleep(cfg.CONF.coalesce_interval)


def get_event_queue():
    """Returns the event queue from the Policy Processor instance."""
    return PolicyProcessor.get_instance().event_queue


def run_policy_processor():
    PolicyProcessor.get_instance().run()
