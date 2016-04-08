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


def _fetch_pod(pod, namespace):
    """Retrieve a pod from the cache or the API server.

    The routine invokes the API server in case a cache miss, but does
    not update the cache.
    """
    pod_watcher = WATCHER_REGISTRY.k8s_pod_watcher
    if not pod_watcher:
        pod_data = None
        LOG.warn("Pod watcher not set. This could be troublesome")
    else:
        pod_data = pod_watcher.pod_cache.get(pod)
    if not pod_data:
        # Note: the information needed are very likely to be in the
        # event metadata. The code could be optimized by parsing those
        # as well.
        pod_data = k8s.get_pod(cfg.CONF.k8s_api_server_host,
                               cfg.CONF.k8s_api_server_port,
                               namespace, pod)
    return pod_data


def _fetch_namespace(namespace):
    """Retrieve a namespace from the cache or the API server."""
    ns_watcher = WATCHER_REGISTRY.k8s_ns_watcher
    if not ns_watcher:
        ns_data = None
        LOG.warn("Namespace watcher not set. This could be troublesome")
    else:
        ns_data = ns_watcher.ns_cache.get(namespace)
    if not ns_data:
        ns_data = k8s.get_namespace(cfg.CONF.k8s_api_server_host,
                                    cfg.CONF.k8s_api_server_port,
                                    namespace)
        ns_data['isolated'] = utils.is_namespace_isolated(namespace)
    return ns_data


def _fetch_network_policy(network_policy, namespace=None):
    """Retrieve a policy from the cache or the API server."""
    np_watcher = WATCHER_REGISTRY.k8s_np_watcher
    if not np_watcher:
        np_data = None
        LOG.warn("Network Policy watcher not set. This could be troublesome")
    else:
        np_data = np_watcher.np_cache.get(network_policy)
    if not np_data:
        np_data = k8s.get_network_policy(
            cfg.CONF.k8s_api_server_host,
            cfg.CONF.k8s_api_server_port,
            namespace,
            network_policy)
    return np_data


def _find_policies_for_pod(pod_name, pod_namespace):
    pod_data = _fetch_pod(pod_name, pod_namespace)
    if not pod_data:
        # no pod, hence no policies
        return []
    pod_labels = pod_data['metadata'].get('labels', {})
    # TODO(me): Use cached policies?
    policies = k8s.get_network_policies(cfg.CONF.k8s_api_server_host,
                                        cfg.CONF.k8s_api_server_port,
                                        pod_namespace)
    for policy in policies[:]:
        pod_selector = policy.get('podSelector')
        # TODO(me): Implement not only equality based selectors
        if pod_selector:
            # NOTE: the current code assumes only equaility-based selectors
            match = False
            for label in set(pod_labels.keys()) & set(pod_selector.keys()):
                if pod_labels[label] == pod_selector[label]:
                    match = True
            if not match:
                policies.remove(policy)
    return policies


def _process_namespace_isolation_off(events):
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


def _process_pod_deletion(events):
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
        # Map policy with a list of pseudo-acls. Each of these pseduo-acls is
        # just a tuple with priority, port/protocol match, source ip match,
        # and action
        self._pseudo_acls = {}
        self._dirty_policies = {}
        self.event_queue = queue.PriorityQueue()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _process_pod_event(self, event, pod_ns_map, affected_pods):
        pod_name = event.metadata['metadata']['name']
        pod_ns_map[pod_name] = event.metadata['metadata']['namespace']
        if event.event_type != constants.POD_DEL:
            affected_pods.setdefault(pod_name, []).append(event)
        # Find policies whoe PodSelector matches this pod
        affected_policies = _find_policies_for_pod(
            pod_name, pod_ns_map[pod_name])
        if affected_policies:
            LOG.debug("Pod event affects %d network policies."
                      "Generatingpolicy events", len(affected_policies))
        else:
            LOG.debug("The pod event does not affect any network "
                      "policy. No further processing needed")
        # For each policy generate a policy update event and send it
        # back to the queue
        for policy in affected_policies:
            policy.update({'from_changed': True})
            get_event_queue().put(
                (constants.NP_EVENT_PRIORITY,
                 Event(constants.NP_UPDATE,
                       policy['metadata']['name'],
                       policy)))

    def _process_ns_event(self, event, pod_ns_map, affected_pods):
        namespace = event.source
        # TODO(me): Use the cache rather than querying the server
        ns_pods = k8s.get_pods(cfg.CONF.k8s_api_server_host,
                               cfg.CONF.k8s_api_server_port,
                               namespace)
        for pod in ns_pods:
            pod_name = pod['metadata']['name']
            pod_ns_map[pod_name] = namespace
            affected_pods.setdefault(pod_name, []).append(event)

    def _process_np_event(self, event, pod_ns_map, affected_pods):
        namespace = event.metadata['metadata']['namespace']
        policy = event.source
        ns_data = _fetch_namespace(namespace)
        if not ns_data['isolated']:
            LOG.warn("Policy %s applied to non-isolated namespace:%s."
                     "Skipping processing", policy, namespace)
            return
        policy_data = _fetch_network_policy(policy, namespace)
        # Retrieve pods matching policy selector
        # TODO: use pod cache, even if doing the selector query is so easy
        pod_selector = policy_data.get('podSelector', {})
        pods = k8s.get_pods(
            cfg.CONF.k8s_api_server_host,
            cfg.CONF.k8s_api_server_port,
            namespace=namespace,
            pod_selector=pod_selector)
        for pod in pods:
            pod_name = pod['metadata']['name']
            pod_ns_map[pod_name] = namespace
            affected_pods.setdefault(pod_name, []).append(event)
        from_changed = event.metadata.get('from_changed', False)
        ports_changed = event.metadata.get('ports_changed', False)
        if from_changed or ports_changed:
            self._dirty_policies[policy] = (from_changed, ports_changed)

    def _rebuild_pseudo_acl(self, policy, from_changed, ports_changed):
        # Build pseudo ACL list for policy
        pseudo_acl = self._pseudo_acls.get(
            policy,
            (constants.STANDARD_ACL_PRIORITY,
             [],
             [],
             'allow-related'))
        policy_data = _fetch_network_policy(policy)
        # Note: For the time being simplofy by assuming one ingress rule per
        # policy
        if ports_changed:
            ports_data = policy_data['ingress'][0].get('ports', [])
            protocol_ports = []
            for item in ports_data:
                protocol_ports.append((item['protocol'], item['port']))
        if from_changed:
            from_data = policy_data['ingress'][0].get('from', [])
            # TODO(me): The whole from logic
            src_pod_ips = []
        pseudo_acl = (constants.STANDARD_ACL_PRIORITY,
                      ports_changed and protocol_ports or pseudo_acl[1],
                      from_changed and src_pod_ips or pseudo_acl[2],
                      'allow-related')
        self._pseudo_acls[policy] = pseudo_acl
        return pseudo_acl

    def _apply_pod_acls(self, pod, namespace):
        for policy_name in [policy['metadata']['name'] for policy in
                            _find_policies_for_pod(pod, namespace)]:
            try:
                pseudo_acl = self._pseudo_acls[policy_name]
            except KeyError:
                LOG.debug("Pseudo ACLs for policy:%s not yet generated",
                            policy_name)
                pseudo_acl = self._rebuild_pseudo_acl(
                    policy_name, True, True)
            # NOTE: We do not validate that the protocol names are valid
            ports_clause = pseudo_acl[1]
            protocol_port_map = {}
            for (protocol, port) in ports_clause:
                protocol_port_map.setdefault(protocol, set()).add(port)
            ports_match = "\ &&\ ".join([r"%s.dst\=\=\{%s\}" % (
                                         protocol.lower(), ",".join(ports))
                                         for (protocol, ports) in
                                         protocol_port_map.items()])
            lport_data_raw = ovn.ovn_nbctl(
                'find', 'Logical_Port', 'external_ids:pod_name=%s' % pod)
            lport_data = ovn.parse_ovn_nbctl_output(lport_data_raw)
            lport_data = lport_data[0]
            lport_name = lport_data['name'].strip('"')
            outport_match = r'outport\=\=\"%s\"\ &&\ ip' % lport_name
            if ports_match:
                match = r'%s\ &&\ %s' % (outport_match, ports_match)
            else:
                match = outport_match
                LOG.debug("Policy: %s - ACL match: %s", policy_name, match)
            ovn_acl_data = (pseudo_acl[0], match, pseudo_acl[3])
            # TODO(me): lswitch & lport can be easily cached: pods don't move
            ls_name = _find_lswitch(lport_name)
            ovn.create_ovn_acl(ls_name, pod, lport_name, *ovn_acl_data)

    def _process_pod_acls(self, pod, namespace):
        LOG.debug("Processing ACLs for Pod: %s in namespace: %s",
                pod, namespace)
        pod_data = _fetch_pod(pod, namespace)
        ns_data = _fetch_namespace(namespace)
        current_acls = _get_acls(pod)
        if not ns_data.get('isolated', False):
            LOG.debug("Pod %s deployed in non-isolated namespace: %s."
                    "Whitelisting traffic", pod, namespace)
            _whitelist_pod_traffic(pod)
        else:
            LOG.debug("Applying ACLs to Pod: %s", pod_data['metadata']['name'])
            self._apply_pod_acls(pod, namespace)

        _remove_acls(current_acls)
        LOG.debug("ACLs for Pod %s processed", pod)

    def process_events(self, events):
        # Compile pod list PL where policies are applied. Also include pods
        # from new lport events.
        # namespace events on->off: immediately whitelist traffic for all pods
        # in the namespace
        # namespace events off->on: add items to PL
        # if PL is empty goodbye
        # policy event -> rebuild pseudo-acl lis
        # for each element in PL -> apply OVN acls from pseudo-acl list
        LOG.debug("Processing %d events from queue", len(events))
        # The easy bits first. Whitelist all traffic for pod in namespaces
        # where isolation was turned off
        events = _process_namespace_isolation_off(events)
        LOG.debug("Pod whitelisting performed. %d events remaining",
                  len(events))
        if not events:
            return
        events = _process_pod_deletion(events)
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
        # Associated pods affected with events
        affected_pods = {}
        # Map pod to namsepaces
        pod_ns_map = {}
        for event in events[:]:
            if event.event_type in (constants.POD_ADD,
                                    constants.POD_UPDATE,
                                    constants.POD_DEL):
                self._process_pod_event(event, pod_ns_map, affected_pods)
                if event.event_type == constants.POD_DEL:
                    events.remove(event)
            elif event.event_type == constants.LPORT_ADD:
                pod_name = event.metadata['pod_name']
                pod_ns_map[pod_name] = event.metadata['ns_name']
                affected_pods.setdefault(pod_name, []).append(event)
            elif event.event_type == constants.NS_UPDATE:
                # This event must be transition off->on for isolation
                self._process_ns_event(event, pod_ns_map, affected_pods)
            elif event.event_type in (constants.NP_ADD,
                                      constants.NP_UPDATE,
                                      constants.NP_DEL):
                self._process_np_event(event, pod_ns_map, affected_pods)
        for policy in self._dirty_policies:
            self._rebuild_pseudo_acl(policy,
                                     *self._dirty_policies[policy])
        for pod, pod_events in affected_pods.items():
            LOG.debug("Rebuilding ACL for pod:%s because of:%s",
                      pod, "; ".join(['%s from %s' % (event.event_type,
                                                      event.source)
                                      for event in events]))
            namespace = pod_ns_map[pod]
            self._process_pod_acls(pod, namespace)
            for pod_event in pod_events:
                try:
                    events.remove(pod_event)
                except ValueError:
                    # Don't mind as many pods might be affected by the same
                    # event
                    pass

        for event in events:
            LOG.warn("Event %s from %s was not processed. ACLs might not be "
                     "in sync with network policies",
                     event.event_type, event.source)
        else:
            LOG.info("Event processing terminated.")

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
