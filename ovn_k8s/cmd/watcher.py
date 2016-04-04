import logging
import sys

import eventlet
eventlet.monkey_patch()
from oslo_config import cfg
from oslo_log import log

from ovn_k8s import config
from ovn_k8s import policy_processor as pp
from ovn_k8s.watcher import np_watcher
from ovn_k8s.watcher import watcher

LOGFILE = 'k8s_ovn_watcher.log'
LOG = log.getLogger(__name__)


def main():
    log.register_options(cfg.CONF)
    config.init_conf(sys.argv[1:])
    cfg.CONF.set_override('log_file', LOGFILE)
    cfg.CONF.set_override('debug', True)
    log.setup(cfg.CONF, 'k8s_ovn_watcher')
    LOG.info("Kubernetes-OVN watcher process started")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)

    np_watcher_inst = np_watcher.NetworkPolicyWatcher()
    pool = eventlet.greenpool.GreenPool()
    pool.spawn(pp.run_policy_processor)
    pool.spawn(watcher.ovn_watcher)
    pool.spawn(watcher.k8s_ns_watcher, np_watcher_inst)
    pool.spawn(watcher.k8s_pod_watcher)
    pool.spawn(watcher.k8s_nw_policy_watcher, np_watcher_inst)
    pool.waitall()
    np_watcher_inst.close()
    LOG.info("Kubernetes-OVN watcher terminated")
