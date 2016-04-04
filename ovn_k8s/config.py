from oslo_config import cfg


def init_conf(args):
    # Register options
    opts = [
        cfg.StrOpt('k8s_api_server_host', default='127.0.0.1'),
        cfg.IntOpt('k8s_api_server_port', default='8080'),
        cfg.StrOpt('ovn_nb_remote',
                   default='unix:/var/run/openvswitch/nb_db.sock'),
        cfg.FloatOpt('coalesce_interval', default='0.1',
                     help=('Interval in seconds for coalescing events.'
                           'There will be a delay in event processing equal '
                           'to the value of this parameter'))]
    cfg.CONF.register_opts(opts)
    cfg.CONF(args=args, project='ovn-k8s')
