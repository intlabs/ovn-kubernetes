import logging
import sys

import eventlet
eventlet.monkey_patch()
from oslo_config import cfg
from oslo_log import log

from ovn_k8s.watcher import watcher

LOGFILE = 'k8s_ovn_watcher.log'
LOG = log.getLogger(__name__)


def _init_conf():
    # Register options
    watcher_opts = [
        cfg.StrOpt('k8s_api_server_host', default='192.168.0.54'),
        cfg.IntOpt('k8s_api_server_port', default='8080')]
    cfg.CONF.register_opts(watcher_opts)
    cfg.CONF(args=sys.argv[1:], project='ovn-k8s')

def main():
    log.register_options(cfg.CONF)
    _init_conf()
    cfg.CONF.set_override('log_file', LOGFILE)
    cfg.CONF.set_override('debug', True)
    log.setup(cfg.CONF, 'k8s_ovn_watcher')
    LOG.info("Kubernetes-OVN watcher process started")
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)
    pool = eventlet.greenpool.GreenPool()
    pool.spawn(watcher.ovn_watcher)
    pool.spawn(watcher.k8s_ns_watcher)
    pool.spawn(watcher.k8s_nw_policy_watcher)
    pool.waitall()
    LOG.info("Kubernetes-OVN watcher terminated")
