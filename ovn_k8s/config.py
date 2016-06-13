import netaddr
from oslo_config import cfg
from oslo_log import log

from ovn_k8s import constants
from ovn_k8s.lib import ovn
from ovn_k8s import utils

LOG = log.getLogger(__name__)


def init_conf(args):
    # Register options
    opts = [
        cfg.StrOpt('lrouter_name', default=constants.DEFAULT_LROUTER_NAME),
        cfg.StrOpt('k8s_api_server_host', default='127.0.0.1'),
        cfg.IntOpt('k8s_api_server_port', default='8080'),
        cfg.StrOpt('ovn_nb_remote',
                   default='unix:/var/run/openvswitch/nb_db.sock'),
        cfg.FloatOpt('coalesce_interval', default='0.1',
                     help=('Interval in seconds for coalescing events.'
                           'There will be a delay in event processing equal '
                           'to the value of this parameter')),
        cfg.BoolOpt('enable_networkpolicy', default=False,
                    help=('Set to True to enable watching and processing '
                          'network policy objects'))]
    cfg.CONF.register_opts(opts)
    cfg.CONF(args=args, project='ovn-k8s')


def _check_vswitch(lswitch_name):
    lswitch_raw_data = ovn.ovn_nbctl('find', 'Logical_Switch',
                                     'name=%s' % lswitch_name)
    lswitch_data = ovn.parse_ovn_nbctl_output(lswitch_raw_data)
    if len(lswitch_data) > 1:
        LOG.warn("I really was not expecting more than one switch... I'll "
                 "pick the first, there's a %.2f\% chance I'll get it right" %
                 (100 / len(lswitch_data)))
    if lswitch_data:
        lswitch_data = lswitch_data[0]
        LOG.debug("OVN Logical Switch for K8S host found. Skipping creation")
        return lswitch_data


def init_host(host_name, host_subnet):
    """Initializes a host adding it to the logical topology"""
    # Check for logical router, if not found create one
    lrouter_name = cfg.CONF.lrouter_name
    lrouter_raw_data = ovn.ovn_nbctl('find', 'Logical_Router',
                                     'name=%s' % lrouter_name)
    lrouter_data = ovn.parse_ovn_nbctl_output(lrouter_raw_data)
    if len(lrouter_data) > 1:
        LOG.warn("I really was not expecting more than one router... I'll "
                 "pick the first, there's a %.2f\% chance I'll get it right",
                 (100 / len(lrouter_data)))
    if lrouter_data:
        lrouter_data = lrouter_data[0]
        LOG.debug("Logical router for K8S networking found. "
                  "Skipping creation")
    else:
        LOG.debug("Creating Logical Router for K8S networking with name:%s",
                  lrouter_name)
        output = ovn.ovn_nbctl('create', 'Logical_Router',
                               'name=%s' % lrouter_name)
        LOG.debug("Will use OVN Logical Router:%s", output)
    # Check for host logical switch. If not found create one
    lswitch_name = host_name
    LOG.info("OVN lswitch for the host: %s", lswitch_name)
    lswitch_data = _check_vswitch(lswitch_name)
    if lswitch_data:
        LOG.debug("OVN Logical Switch for K8S host found. Skipping creation")
    else:
        LOG.debug("Creating LogicalSwitch for K8S host with name: %s",
                  lswitch_name)
        ovn.ovn_nbctl('lswitch-add', lswitch_name)

    # Check for logical router port connecting local logical switch to
    # kubernetes router.
    # If not found create one, and connect it to both router and switch
    lrp_raw_data = ovn.ovn_nbctl('find', 'Logical_Router_port',
                                 'name=%s' % lswitch_name)
    lrp_data = ovn.parse_ovn_nbctl_output(lrp_raw_data)
    if len(lrp_data) > 1:
        LOG.warn("I really was not expecting more than one router port... "
                 "I'll pick the first, there's a %.2f\% chance I'll get it "
                 "right", (100 / len(lrp_data)))
    if lrp_data:
        lrp_data = lrp_data[0]
        LOG.debug("OVN logical router port for K8S host found."
                  "Skipping creation")
        # TODO: worry about changes in IP address and subnet
    else:
        lrp_mac = utils.generate_mac()
        cidr = netaddr.IPNetwork(host_subnet)
        ip_address = netaddr.IPAddress(cidr.first + 1)
        lrp_uuid = ovn.ovn_nbctl('--', '--id=@lrp', 'create',
                                 'Logical_Router_port',
                                 'name=%s' % lswitch_name,
                                 'network=%s/%s' % (ip_address,
                                                    cidr.prefixlen),
                                 'mac="%s"' % lrp_mac, '--', 'add',
                                 'Logical_Router', lrouter_name, 'ports',
                                 '@lrp', '--', 'lport-add',
                                 lswitch_name, 'rp-%s' % lswitch_name)
        ovn.ovn_nbctl('set', 'Logical_port', 'rp-%s' % lswitch_name,
                      'type=router', 'options:router-port=%s' % lswitch_name,
                      'addresses="%s"' % lrp_mac)
        LOG.debug("Configured logical router port: %s", lrp_uuid)
