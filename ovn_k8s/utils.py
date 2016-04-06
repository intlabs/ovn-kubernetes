import subprocess

from oslo_config import cfg

from ovn_k8s import constants
from ovn_k8s.lib import kubernetes as k8s


def call_popen(cmd):
    """Invoke subprocess"""
    child = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    output = child.communicate()
    if child.returncode:
        raise RuntimeError("Fatal error executing %s" % " ".join(cmd))
    if not output or not output[0]:
        output = ""
    else:
        output = output[0].strip()
    return output


def is_namespace_isolated(namespace):
    annotations = k8s.get_ns_annotations(cfg.CONF.k8s_api_server_host,
                                         cfg.CONF.k8s_api_server_port,
                                         namespace)
    isolation = annotations and annotations.get(constants.K8S_ISOLATION_ANN)
    # Interpret anythingthat is not "on" as "off"
    if isolation == 'on':
        return True
    else:
        return False
