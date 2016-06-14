from oslo_config import cfg
from oslo_log import log

import ovn_k8s
from ovn_k8s import constants
from ovn_k8s.lib import kubernetes as k8s
from ovn_k8s.lib import ovn
from ovn_k8s.watcher import registry

LOG = log.getLogger(__name__)
WATCHER_REGISTRY = registry.WatcherRegistry.get_instance()


def _find_lswitch(lport_uuid):
    ls_data_raw = ovn.ovn_nbctl('find', 'Logical_Switch',
                                'ports{>=}%s' % lport_uuid)
    ls_data = ovn.parse_ovn_nbctl_output(ls_data_raw)
    ls_data = ls_data[0]
    return ls_data['name'].strip('"')


def _whitelist_pod_traffic(pod_name):
    lport_data = _fetch_lport(pod_name)
    lport_uuid = lport_data['_uuid'].strip('"')
    lport_name = lport_data['name'].strip('"')
    whitelist_acl = (constants.DEFAULT_ALLOW_ACL_PRIORITY,
                     r'outport\=\=\"%s\"\ &&\ ip' % lport_name,
                     'allow-related')
    ls_name = _find_lswitch(lport_uuid)
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


def _fetch_lport(pod):
    """Retrieve a logical from the OVN NB DB."""
    lport_data_raw = ovn.ovn_nbctl(
        'find', 'Logical_Switch_Port', 'external_ids:pod_name=%s' % pod)
    lport_data = ovn.parse_ovn_nbctl_output(lport_data_raw)
    return lport_data[0]


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
        ns_data['isolated'] = k8s.is_namespace_isolated(namespace)
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


def _find_policies_for_pod(pod_name, pod_namespace, policies=None):
    pod_data = _fetch_pod(pod_name, pod_namespace)
    if not pod_data:
        # no pod, hence no policies
        return []
    pod_labels = pod_data['metadata'].get('labels', {})
    # TODO(me): Use cached policies?i
    if not policies:
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


class PolicyProcessor(ovn_k8s.BaseProcessor):

    def __init__(self):
        super(PolicyProcessor, self).__init__()
        # Map policy with a list of pseudo-acls. Each of these pseduo-acls is
        # just a tuple with priority, port/protocol match, source ip match,
        # and action
        self._pseudo_acls = {}
        self._dirty_policies = {}

    def _process_pod_event(self, event, pod_ns_map, affected_pods):
        pod_name = event.metadata['metadata']['name']
        pod_ns_map[pod_name] = event.metadata['metadata']['namespace']
        if event.event_type != constants.POD_DEL:
            affected_pods.setdefault(pod_name, []).append(event)
        else:
            # Remove all acls for pod
            _remove_all_acls(pod_name)
        # Find policies whoe PodSelector matches this pod
        affected_policies = _find_policies_for_pod(
            pod_name, pod_ns_map[pod_name])
        if affected_policies:
            LOG.debug("Pod event affects %d network policies."
                      "Generating policy events", len(affected_policies))
        else:
            LOG.debug("The pod event does not affect any network "
                      "policy. No further processing needed")
        # For each policy generate a policy update event and send it
        # back to the queue
        for policy in affected_policies:
            policy.update({'from_changed': True})
            get_event_queue().put(
                (constants.NP_EVENT_PRIORITY,
                 event.Event(constants.NP_UPDATE,
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
        return ns_pods

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
        return pods

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
                protocol_ports.append((item['protocol'], item.get('port')))
        if from_changed:
            from_data = policy_data['ingress'][0].get('from')
            if not from_data:
                src_pod_ips = ['*']
        if from_changed and from_data:
            # TODO(me): Use caches rather than doing list operations
            def do_selector(key):
                final_selector = {}
                selectors = [item[key] for item in from_data if key in item]
                # Merge all selectors together
                for selector in selectors:
                    for (label, value) in selector.items():
                        final_selector.setdefault(label, set()).add(value)
                return final_selector

            # Verify selectors are valid
            for item in from_data:
                if 'namespace' in item and 'pods' in item:
                    LOG.warn("Policy %s has both namespace and pod selectors "
                             "in the from clause. ACLs for the policy will "
                             "not be implemented", policy)
                    return

            ns_selector = do_selector('namespaces')
            pod_selector = do_selector('pods')
            if ns_selector:
                # Query namespaces by label selector
                ns_data = k8s.get_namespaces(cfg.CONF.k8s_api_server_host,
                                             cfg.CONF.k8s_api_server_port,
                                             ns_selector)
                # Query all pods  in each namesoace
                pod_data = []
                for namespace in ns_data:
                    pod_data.extend(k8s.get_pods(
                        cfg.CONF.k8s_api_server_host,
                        cfg.CONF.k8s_api_server_port,
                        namespace=namespace['metadata']['name']))
            else:
                # Query pod in policy namespace by selector
                pod_data = k8s.get_pods(
                    cfg.CONF.k8s_api_server_host,
                    cfg.CONF.k8s_api_server_port,
                    namespace=policy_data['metadata']['namespace'],
                    pod_selector=pod_selector)

            src_pod_ips = [pod['status']['podIP'] for pod in pod_data
                           if 'podIP' in pod['status']]

        pseudo_acl = (constants.STANDARD_ACL_PRIORITY,
                      ports_changed and protocol_ports or pseudo_acl[1],
                      from_changed and src_pod_ips or pseudo_acl[2],
                      'allow-related')
        self._pseudo_acls[policy] = pseudo_acl
        return pseudo_acl

    def _apply_pod_acls(self, pod, namespace, network_policies):
        for policy_name in [policy['metadata']['name'] for policy in
                            _find_policies_for_pod(pod, namespace,
                                                   network_policies)]:
            try:
                pseudo_acl = self._pseudo_acls[policy_name]
            except KeyError:
                LOG.debug("Pseudo ACLs for policy:%s not yet generated",
                          policy_name)
                pseudo_acl = self._rebuild_pseudo_acl(
                    policy_name, True, True)
            # In some cases a pseudo acl could be empty.
            if not pseudo_acl:
                continue
            # NOTE: We do not validate that the protocol names are valid
            ports_clause = pseudo_acl[1]
            from_clause = pseudo_acl[2]
            # If the from clause is an empty list then no IP matches
            if not from_clause:
                LOG.debug("The ACL for policy %s matches no IP address and "
                          "will not be programmed", policy_name)
                continue
            src_ip_list = "\,".join(from_clause)
            src_match = None
            if src_ip_list != '*':
                # '*' means every address matches and therefore no source IP
                # match should be added to the ACL
                src_match = r"ip4.src\=\=\{%s\}" % src_ip_list
            match_items = set()
            protocol_port_map = {}
            for (protocol, port) in ports_clause:
                ports = protocol_port_map.setdefault(protocol, set())
                if port:
                    ports.add(port)
            for protocol, ports in protocol_port_map.items():
                if ports:
                    item_match_str = (r"%s.dst\=\=\{%s\}" %
                                      (protocol.lower(), ",".join(
                                          [str(port) for port in ports
                                           if port is not None])))
                else:
                    item_match_str = protocol.lower()
                match_items.add(item_match_str)
            ports_match = "\ ||\ ".join(match_items)
            lport_data = _fetch_lport(pod)
            lport_uuid = lport_data['_uuid'].strip('"')
            lport_name = lport_data['name'].strip('"')
            if ports_match and src_match:
                policy_match = "%s\ &&\ %s" % (ports_match, src_match)
            elif ports_match:
                policy_match = ports_match
            elif src_match:
                policy_match = src_match
            outport_match = r'outport\=\=\"%s\"\ &&\ ip' % lport_name
            if policy_match:
                match = r'%s\ &&\ %s' % (outport_match, policy_match)
            else:
                match = outport_match
            LOG.debug("Policy: %s - ACL match: %s", policy_name, match)
            ovn_acl_data = (pseudo_acl[0], match, pseudo_acl[3])
            # TODO(me): lswitch & lport can be easily cached: pods don't move
            ls_name = _find_lswitch(lport_uuid)
            # Also store policy name in external ids. It could be useful for
            # debugging
            ovn.create_ovn_acl(ls_name, pod, lport_name, *ovn_acl_data,
                               k8s_policy=policy_name)

    def _process_pod_acls(self, pod, namespace, network_policies):
        pod_data = _fetch_pod(pod, namespace)
        ns_data = _fetch_namespace(namespace)
        current_acls = _get_acls(pod)
        if not ns_data.get('isolated', False):
            LOG.debug("Pod %s deployed in non-isolated namespace: %s."
                      "Whitelisting traffic", pod, namespace)
            _whitelist_pod_traffic(pod)
        else:
            LOG.debug("Applying ACLs to Pod: %s", pod_data['metadata']['name'])
            self._apply_pod_acls(pod, namespace, network_policies)

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
                if not self._process_ns_event(event, pod_ns_map,
                                              affected_pods):
                    # It is ok to remove the event as no pods were affected
                    events.remove(event)
            elif event.event_type in (constants.NP_ADD,
                                      constants.NP_UPDATE,
                                      constants.NP_DEL):
                if not self._process_np_event(event, pod_ns_map,
                                              affected_pods):
                    # It is ok to remove the event as no pods were affected
                    events.remove(event)

        for policy in self._dirty_policies:
            self._rebuild_pseudo_acl(policy,
                                     *self._dirty_policies[policy])
        network_policies = []
        for pod, pod_events in affected_pods.items():
            # Load network policies only once for all pods. In theory it should
            # be possible to use the cache in the network policy watcher,
            # however as the cache might not be reliable, especially at
            # startup, the policies will be fetched from the API server here
            namespace = pod_ns_map[pod]
            if not network_policies:
                network_policies = k8s.get_network_policies(
                    cfg.CONF.k8s_api_server_host,
                    cfg.CONF.k8s_api_server_port,
                    namespace)
            LOG.debug("Rebuilding ACL for pod:%s because of:%s",
                      pod, "; ".join(['%s from %s' % (event.event_type,
                                                      event.source)
                                      for event in events]))
            self._process_pod_acls(pod, namespace, network_policies)
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


def get_event_queue():
    """Returns the event queue from the Policy Processor instance."""
    return PolicyProcessor.get_instance().event_queue


def run_processor():
    PolicyProcessor.get_instance().run()
