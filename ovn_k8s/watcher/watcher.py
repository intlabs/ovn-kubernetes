import subprocess

from oslo_config import cfg
from oslo_log import log

from ovn_k8s.lib import kubernetes as k8s
from ovn_k8s.watcher import ns_watcher
from ovn_k8s.watcher import ovndb_watcher
from ovn_k8s.watcher import pod_watcher

LOG = log.getLogger(__name__)


def ovn_watcher():
    """Monitor changes in OVN NB DB."""
    LOG.info("Monitoring OVN Northbound DB")
    proc = subprocess.Popen(['sudo', 'ovsdb-client', 'monitor',
                             cfg.CONF.ovn_nb_remote, 'Logical_Port'],
                            stdout=subprocess.PIPE)
    watcher = ovndb_watcher.OvndbWatcher(proc.stdout)
    while True:
        watcher.process()


def k8s_ns_watcher(np_watcher=None):
    """Monitor changes in namespace isolation annotations."""
    LOG.info("Monitoring Kubernetes Namespaces")
    ns_stream = k8s.watch_namespaces(cfg.CONF.k8s_api_server_host,
                                     cfg.CONF.k8s_api_server_port)
    watcher = ns_watcher.NamespaceWatcher(ns_stream, np_watcher)
    while True:
        watcher.process()


def k8s_nw_policy_watcher(watcher):
    """Monitor network policy changes."""
    LOG.info("Monitoring Kubernetes Network Policies")
    while True:
        watcher.process()
    watcher.close()


def k8s_pod_watcher():
    """Monitor pod create/modify/destroy events."""
    LOG.info("Monitoring Kubernetes pods")
    pod_stream = k8s.watch_pods(cfg.CONF.k8s_api_server_host,
                                cfg.CONF.k8s_api_server_port)
    watcher = pod_watcher.PodWatcher(pod_stream)
    while True:
        watcher.process()
