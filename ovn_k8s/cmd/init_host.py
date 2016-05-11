import logging
import sys

from oslo_config import cfg
from oslo_log import log

from ovn_k8s import config

opts = [
    cfg.StrOpt('host_name'),
    cfg.StrOpt('host_subnet')
]
LOGFILE = 'k8s_init_host.log'
LOG = log.getLogger(__name__)


def main():
    log.register_options(cfg.CONF)
    cfg.CONF.register_cli_opts(opts)
    config.init_conf(sys.argv[1:])
    cfg.CONF.set_override('log_file', LOGFILE)
    cfg.CONF.set_override('debug', True)
    log.setup(cfg.CONF, 'k8s_init_host')
    cfg.CONF.log_opt_values(LOG, logging.DEBUG)
    config.init_host(cfg.CONF.host_name, cfg.CONF.host_subnet)
