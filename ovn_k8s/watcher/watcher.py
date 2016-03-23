import logging
import subprocess
import sys

from oslo_config import cfg
from oslo_log import log
import requests

LOG = log.getLogger(__name__)

K8S_POD_NAME = 'k8s_pod_name'
K8S_POD_NAMESPACE = 'k8s_pod_namespace'
K8S_ISOLATION_ANN = 'net.alpha.kubernetes.io/network-isolation'

DEFAULT_ACL_PRIORITY = 1001

# TODO: Remove code duplication


def call_popen(cmd):
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = child.communicate()
    if child.returncode:
        raise RuntimeError("Fatal error executing %s" % " ".join(cmd))
    if not output or not output[0]:
        output = ""
    else:
        output = output[0].strip()
    return output


def call_prog(args):
    cmd = (args[0], "--timeout=5", "-vconsole:off") + args[1:]
    return call_popen(cmd)


def ovs_vsctl(*args):
    return call_prog(("ovs-vsctl",) + args)


def ovn_nbctl(*args):
    # MOTE: this only works if northbound DB is on local host
    args = ('ovn-nbctl', ) + args
    return call_prog(args)


def parse_ovn_nbctl_output(data, scalar=False):
    # Simply use _uuid as a separator between elements assuming it always
    # is the first element returned by ovn-nbctl
    items = []
    item = {}
    for line in data.split('\n'):
        if not line:
            continue
        # This is very rough at some point I'd like to stop shelling out
        # to ovn-nbctl
        if line.startswith('_uuid'):
            if item:
                if scalar:
                    return item
                items.append(item.copy())
                item = {}
        item[line.split(':')[0].strip()] = line.split(':')[-1].strip()
    # append last item
    if item:
        if scalar:
            return item
        items.append(item)
    return items


def _build_external_ids_dict(ext_id_str):
    ext_id_str = ext_id_str.strip('{}')
    if not ext_id_str:
        return {}
    ext_id_items = [item.split('=') for item in ext_id_str.split(',')]
    return dict((item[0].strip('"'), item[1]) for item in ext_id_items)


def _get_ns_annotations(api_server, api_port, namespace):
    # TODO: https and authentication
    url = ("http://%s:%d/api/v1/namespaces/%s" %
           (api_server, api_port, namespace))
    response = requests.get(url)
    if not response or response.status_code != 200:
        # TODO: raise here
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
    isolation = annotations and annotations.get(K8S_ISOLATION_ANN)
    if isolation == 'on':
        return True
    else:
        return False


def _create_ovn_acl(ls_name, pod_name, lport_name, acl):
    # Note: The reason rather complicated expression is to be able to set
    # an external id for the ACL as well (acl-add won't return the ACL id)
    ovn_nbctl('--', '--id=@acl_id', 'create', 'ACL', 'action=%s' % acl[2],
              'direction=to-lport', 'priority=%d' % acl[0],
              'match="%s"' % acl[1],
              'external_ids:lport_name=%s' % lport_name,
              'external_ids:pod_name=%s' % pod_name, '--',
              'add', 'Logical_Switch', ls_name, 'acls', '@acl_id')


def _process_ovn_db_change(row, action, external_ids):
    pod_name = external_ids[K8S_POD_NAME]
    pod_ns = external_ids.get(K8S_POD_NAMESPACE, 'default')
    LOG.info("Processing OVN DB %s for row %s - external_ids: %s",
             action, row, external_ids)
    LOG.debug("Retrieving isolation status for namespace: %s", pod_ns)
    acls = []
    if not _is_namespace_isolated(pod_ns):
        LOG.debug("Namespace %s not isolated, whitelisting all traffic",
                  pod_ns)
        acls.append((DEFAULT_ACL_PRIORITY,
                     'outport==\\"%s\\" && ip' % row,
                     'allow-related'))
    else:
        # Do policies only if isolation is on
        LOG.debug("Retrieving policies in namespace ... for pod %s", pod_name)
        LOG.debug("Fetching IP address for Pods in from clause")
    # TODO: Program ACLs without leaving even a fraction of second in which
    # the container is not secured
    # Find lswitch for port
    ls_data_raw = ovn_nbctl('find', 'Logical_Switch', 'ports{>=}%s' % row)
    ls_data = parse_ovn_nbctl_output(ls_data_raw)
    ls_data = ls_data[0]
    ls_name = ls_data['name'].strip('"')
    current_acls_raw = ovn_nbctl('find', 'ACL',
                                 'external_ids:pod_name=%s' % pod_name)
    current_acls = parse_ovn_nbctl_output(current_acls_raw)
    LOG.debug("Implementing OVN ACLS for pod %s on lswitch %s",
              pod_name, ls_name)
    LOG.debug("Removing existing ACLS for pod %s on lswitch %s",
              pod_name, ls_name)
    for acl in acls:
        _create_ovn_acl(ls_name, pod_name, row, acl)
    for acl in current_acls:
        ovn_nbctl('remove', 'Logical_Switch', ls_name, 'acls', acl['_uuid'])
    LOG.info("ACLs for Pod: %s configured", pod_name)


def ovn_watcher():
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
            if K8S_POD_NAME in external_ids:
                _process_ovn_db_change(row, action, external_ids)


def k8s_ns_watcher():
    LOG.info("Monitoring Kubernetes Namespaces")


def k8s_nw_policy_watcher():
    LOG.info("Monitoring Kubernetes Network Policies")
