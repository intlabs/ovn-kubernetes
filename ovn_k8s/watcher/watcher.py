import subprocess

from eventlet import greenpool
from oslo_config import cfg
from oslo_log import log

from ovn_k8s.lib import kubernetes as k8s
from ovn_k8s import policy_processor as pp
from ovn_k8s.watcher import np_watcher
from ovn_k8s.watcher import ns_watcher
from ovn_k8s.watcher import ovndb_watcher
from ovn_k8s.watcher import pod_watcher
from ovn_k8s.watcher import registry

LOG = log.getLogger(__name__)
WATCHER_REGISTRY = registry.WatcherRegistry.get_instance()


def _process_func(watcher):
    while True:
        watcher.process()


def _create_ovndb_watcher():
    proc = subprocess.Popen(['sudo', 'ovsdb-client', 'monitor',
                             cfg.CONF.ovn_nb_remote, 'Logical_Port'],
                            stdout=subprocess.PIPE)
    watcher = ovndb_watcher.OvndbWatcher(proc.stdout)
    WATCHER_REGISTRY.ovndb_watcher = watcher
    return watcher


def _create_k8s_ns_watcher():
    ns_stream = k8s.watch_namespaces(cfg.CONF.k8s_api_server_host,
                                     cfg.CONF.k8s_api_server_port)
    watcher = ns_watcher.NamespaceWatcher(ns_stream)
    WATCHER_REGISTRY.k8s_ns_watcher = watcher
    return watcher


def _create_k8s_pod_watcher():
    pod_stream = k8s.watch_pods(cfg.CONF.k8s_api_server_host,
                                cfg.CONF.k8s_api_server_port)
    watcher = pod_watcher.PodWatcher(pod_stream)
    WATCHER_REGISTRY.k8s_pod_watcher = watcher
    return watcher


def _create_k8s_np_watcher():
    watcher = np_watcher.NetworkPolicyWatcher()
    WATCHER_REGISTRY.k8s_np_watcher = watcher
    return watcher


def start_threads():
    np_watcher_inst = _create_k8s_np_watcher()
    ns_watcher_inst = _create_k8s_ns_watcher()
    pod_watcher_inst = _create_k8s_pod_watcher()
    ovn_db_watcher_inst = _create_ovndb_watcher()
    pool = greenpool.GreenPool()
    LOG.debug("Starting Policy processor")
    pool.spawn(pp.run_policy_processor)
    LOG.info("Starting OVN Northbound DB watcher")
    pool.spawn(_process_func, ovn_db_watcher_inst)
    LOG.info("Starting Kubernetes Namespace watcher")
    pool.spawn(_process_func, ns_watcher_inst)
    LOG.info("Starting Kubernetes Pod watcher")
    pool.spawn(_process_func, pod_watcher_inst)
    LOG.info("Starting Kubernetes Network Policy watcher")
    pool.spawn(_process_func, np_watcher_inst)
    pool.waitall()
    np_watcher_inst.close()
