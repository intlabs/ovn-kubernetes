import json
import re
import subprocess

from oslo_config import cfg
from oslo_log import log
import requests

from ovn_k8s import constants
from ovn_k8s.lib import ovn
from ovn_k8s.lib import kubernetes as k8s

LOG = log.getLogger(__name__)

# TODO(me): Remove remaining code duplication


def _build_external_ids_dict(ext_id_str):
    ext_id_str = ext_id_str.strip('{}').strip()
    if not ext_id_str:
        return {}
    ext_id_items = [item.split('=') for item in ext_id_str.split(',')]
    return dict((item[0].strip(' "'), item[1]) for item in ext_id_items)


def _get_ns_annotations(api_server, api_port, namespace):
    # TODO(me): https and authentication
    url = ("http://%s:%d/api/v1/namespaces/%s" %
           (api_server, api_port, namespace))
    response = requests.get(url)
    if not response or response.status_code != 200:
        # TODO(me): raise here
        return
    json_response = response.json()
    annotations = json_response['metadata'].get('annotations')
    LOG.debug("Annotations for namespace %s: %s",
              namespace, annotations)
    return annotations


def _is_namespace_isolated(namespace):
    annotations = _get_ns_annotations(cfg.CONF.k8s_api_server_host,
                                      cfg.CONF.k8s_api_server_port,
                                      namespace)
    isolation = annotations and annotations.get(constants.K8S_ISOLATION_ANN)
    if isolation == 'on':
        return True
    else:
        return False


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


def ovn_watcher():
    """Monitor changes in OVN NB DB."""
    LOG.info("Monitoring OVN Northbound DB")
    proc = subprocess.Popen(['sudo', 'ovsdb-client', 'monitor',
                             cfg.CONF.ovn_nb_remote, 'Logical_Port'],
                            stdout=subprocess.PIPE)
    updated_row = None
    while True:
        line = proc.stdout.readline()
        if line.strip():
            items = re.findall(r"\[.*?\]|\{.*?\}|\s*?[^\s\[\{\}\]]+?\s", line)
            # 'new' action does not begin with a row identifier
            if updated_row:
                row = updated_row
                action_idx = 0
                external_ids_idx = 3
            else:
                row = items[0].strip()
                action_idx = 1
                external_ids_idx = 4

            action = items[action_idx].strip()
            # This should automatically exclude lines which contain column
            # headers or dashes
            if action == 'old':
                # There should never be a 'old' event followed by another 'old'
                # event before a 'new' event occurs (hopefully)
                updated_row = items[0].strip()
                continue
            else:
                updated_row = None
                if action not in ('initial', 'new', 'delete'):
                    continue
            external_ids = _build_external_ids_dict(items[external_ids_idx])
            if constants.K8S_POD_NAME.lower() in external_ids:
                _process_ovn_db_change(row, action, external_ids)


def k8s_ns_watcher():
    """Monitor changes in namespace isolation annotations."""
    LOG.info("Monitoring Kubernetes Namespaces")


def k8s_nw_policy_watcher():
    """Monitor network policy changes."""
    LOG.info("Monitoring Kubernetes Network Policies")


def _refresh_network_policies(action, pod_spec, pod_metadata, pod_ip):
    LOG.debug("Refreshing network policies for IP:%s and action:%s",
              pod_ip, action)


def _process_pod_event(event):
    pod_ip = event['object']['status']['podIP']
    pod_spec = event['object']['spec']
    pod_metadata = event['object']['metadata']
    event_type = event['type']
    LOG.debug("Processing event %s for pod %s",
              event_type, pod_metadata['name'])
    # Processing events one-by-one is not the best solution from a scale and
    # performance perspective, espcially as pods are usually created and
    # destroyed in groups. This routine might therefore uses logic for adding
    # events to a queue and do some batch processing when possible.
    _refresh_network_policies(event_type, pod_spec, pod_metadata, pod_ip)


def k8s_pod_watcher():
    """Monitor pod create/destroy events."""
    LOG.info("Monitoring Kubernetes pods")
    pod_stream = k8s.watch_pods(cfg.CONF.k8s_api_server_host,
                                cfg.CONF.k8s_api_server_port)
    for line in pod_stream:
        try:
            _process_pod_event(json.loads(line))
        except ValueError:
            LOG.debug("Not valid JSON data:%s", line)
