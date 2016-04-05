import shlex

from oslo_config import cfg
from oslo_log import log

from ovn_k8s import utils

LOG = log.getLogger(__name__)


def call_prog(args):
    cmd = (args[0], "--timeout=5", "-vconsole:off") + args[1:]
    return utils.call_popen(cmd)


def ovs_vsctl(*args):
    return call_prog(("ovs-vsctl",) + args)


def _get_ovn_remote():
    if not _get_ovn_remote.location:
        try:
            _get_ovn_remote.location = ovs_vsctl(
                "get", "Open_vSwitch", ".",
                "external_ids:ovnnb-remote").strip('"')
        except Exception as e:
            raise Exception("Unable to find a location for the "
                            "OVN NorthBound DB:%s" % e)
    return _get_ovn_remote.location
_get_ovn_remote.location = None


def ovn_nbctl(*args):
    # Try to get OVN remote from config first
    try:
        ovn_remote = cfg.CONF.ovn_nb_remote
    except cfg.NoSuchOptError:
        ovn_remote = None
    if not ovn_remote:
        ovn_remote = _get_ovn_remote()
    LOG.debug("Using OVN remote:%s", ovn_remote)
    db_option = "%s=%s" % ("--db", ovn_remote)
    args = ('ovn-nbctl', db_option) + args
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


def create_ovn_acl(ls_name, pod_name, lport_name, priority, match, action):
    # Note: The reason rather complicated expression is to be able to set
    # an external id for the ACL as well (acl-add won't return the ACL id)
    command = ('-- --id=@acl_id create ACL action=%s direction=to-lport '
               'priority=%d match="%s" external_ids:lport_name=%s '
               'external_ids:pod_name=%s -- '
               'add Logical_Switch %s acls @acl_id' %
               (action, priority, match, lport_name, pod_name, ls_name))
    command_items = tuple(shlex.split(command))
    ovn_nbctl(*command_items)
