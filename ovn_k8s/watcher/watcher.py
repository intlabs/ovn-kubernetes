import subprocess

from oslo_config import cfg
from oslo_log import log
import requests

from ovn_k8s import constants
from ovn_k8s.lib import ovn

LOG = log.getLogger(__name__)

# TODO(me): Remove remaining code duplication


def _build_external_ids_dict(ext_id_str):
    ext_id_str = ext_id_str.strip('{}')
    if not ext_id_str:
        return {}
    ext_id_items = [item.split('=') for item in ext_id_str.split(',')]
    return dict((item[0].strip('"'), item[1]) for item in ext_id_items)


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
    LOG.info("Processing OVN DB %s for row %s - external_ids: %s",
             action, row, external_ids)
    LOG.debug("Retrieving isolation status for namespace: %s", pod_ns)
    acls = []
    if not _is_namespace_isolated(pod_ns):
        LOG.debug("Namespace %s not isolated, whitelisting all traffic",
                  pod_ns)
        acls.append((constants.DEFAULT_ACL_PRIORITY,
                     'outport==\\"%s\\" && ip' % row,
                     'allow-related'))
    else:
        # Do policies only if isolation is on
        LOG.debug("Retrieving policies in namespace ... for pod %s", pod_name)
        LOG.debug("Fetching IP address for Pods in from clause")
    # TODO(me): Program ACLs without leaving even a fraction of second in
    # which the container is not secured
    # Find lswitch for port
    ls_data_raw = ovn.ovn_nbctl('find', 'Logical_Switch', 'ports{>=}%s' % row)
    ls_data = ovn.parse_ovn_nbctl_output(ls_data_raw)
    ls_data = ls_data[0]
    ls_name = ls_data['name'].strip('"')
    current_acls_raw = ovn.ovn_nbctl('find', 'ACL',
                                     'external_ids:pod_name=%s' % pod_name)
    current_acls = ovn.parse_ovn_nbctl_output(current_acls_raw)
    LOG.debug("Implementing OVN ACLS for pod %s on lswitch %s",
              pod_name, ls_name)
    LOG.debug("Removing existing ACLS for pod %s on lswitch %s",
              pod_name, ls_name)
    for acl in acls:
        ovn.create_ovn_acl(ls_name, pod_name, row, *acl)
    for acl in current_acls:
        ovn.ovn_nbctl('remove', 'Logical_Switch', ls_name,
                      'acls', acl['_uuid'])
    LOG.info("ACLs for Pod: %s configured", pod_name)


def ovn_watcher():
    """Monitor changes in OVN NB DB."""
    LOG.info("Monitoring OVN Northbound DB")
    proc = subprocess.Popen(['sudo', 'ovsdb-client', 'monitor',
                             'OVN_Northbound', 'Logical_Port'],
                            stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if line:
            # hack for whitespace in external_ids
            line = line.replace(', ', ',')
            items = line.split()
            row = items[0]
            action = items[1]
            if action not in ('initial', 'update', 'delete'):
                continue
            external_ids = _build_external_ids_dict(items[4])
            if constants.K8S_POD_NAME.lower() in external_ids:
                _process_ovn_db_change(row, action, external_ids)


def k8s_ns_watcher():
    """Monitor changes in namespace isolation annotations."""
    LOG.info("Monitoring Kubernetes Namespaces")


def k8s_nw_policy_watcher():
    """Monitor network policy changes."""
    LOG.info("Monitoring Kubernetes Network Policies")
