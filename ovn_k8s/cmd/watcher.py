import logging
import sys

import eventlet
eventlet.monkey_patch()
from oslo_config import cfg
from oslo_log import log

from ovn_k8s import config
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
    watcher.start_threads()
    LOG.info("Kubernetes-OVN watcher terminated")
