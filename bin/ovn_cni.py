#!/usr/bin/python
import argparse
import json
import netaddr
import os
import random
import re
import requests
import shlex
import sys

from oslo_config import cfg
from oslo_log import log

from ovn_k8s import constants
from ovn_k8s.lib import ovn
from ovn_k8s import utils

LOG = log.getLogger(__name__)


class OVNCNIException(Exception):

    def __init__(self, code, message, details=None):
        super(OVNCNIException, self).__init__("%s - %s" % (code, message))
        self._code = code
        self._msg = message
        self._details = details

    def cni_error(self):
        error_data = {'cniVersion': constants.CNI_VERSION,
                      'code': self._code,
                      'message': self._msg}
        if self._details:
            error_data['details'] = self._details
        return json.dumps(error_data)


def _parse_stdin():
    LOG.info("Waiting for configuration on standard input")
    input_data = sys.stdin.read()
    try:
        return json.loads(input_data)
    except ValueError:
        raise OVNCNIException(101, 'invalid JSON input')


def _generate_mac(prefix="00:00:00"):
    random.seed()
    # This is obviously not collition free, but come on! Seriously,
    # please fix this, eventually
    mac = "%s:%02X:%02X:%02X" % (
        prefix,
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255))
    return mac


def _get_host_lswitch_name():
    # Use kubelet introspection API to grab machine ID.
    # TODO: Some error checking might be worth
    response = requests.get("http://localhost:%d/spec" %
                            constants.KUBELET_PORT)
    data = response.json()
    # Use that machine ID as OVN lswitch name
    return data['machine_id']


def _check_vswitch(lswitch_name):
    LOG.info("OVN lswitch for the host: %s", lswitch_name)
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


def _check_host_vswitch(args, network_config):
    # Check for host logical switch
    lswitch_name = _get_host_lswitch_name()
    if not _check_vswitch(lswitch_name):
        message = "Node OVN logical switch not configured"
        LOG.error(message)
        raise OVNCNIException(199, message)
    return lswitch_name


def _setup_interface(pid, container_id, dev, mac,
                     ip_address, prefixlen, gateway_ip):
    """Configure veth pair for container

    :param pid: pod's infra container pid.
    :param container_id: pod's infra container docker id
    :param dev: the interface on the pod infra container to configure
    :param mac: MAC address for the container-side veth
    :param ip_address: IP address to be assigned to the pod
    :param prefixlen: prefix lenght for IP address
    :param gateway_ip: gateway IP address for the interface

    :returns: veth pair name as a tuple
    """
    try:
        veth_outside = container_id[:15]
        veth_inside = container_id[:13] + "_c"
        LOG.debug("Creating veth pair for container %s", container_id)
        command = "ip link add %s type veth peer name %s" \
                  % (veth_outside, veth_inside)
        utils.call_popen(shlex.split(command))
        # Up the outer interface
        LOG.debug("Bringing up veth outer interface %s", veth_outside)
        command = "ip link set %s up" % veth_outside
        utils.call_popen(shlex.split(command))
        # Create a link for the container namespace
        netns_dst = "/var/run/netns/%s" % pid
        if not os.path.isfile(netns_dst):
            netns_src = "/proc/%s/ns/net" % pid
            command = "ln -s %s %s" % (netns_src, netns_dst)
            utils.call_popen(shlex.split(command))
        # Move the inner veth inside the container namespace
        LOG.debug("Adding veth inner interface to namespace for container %s",
                  container_id)
        command = "ip link set %s netns %s" % (veth_inside, pid)
        utils.call_popen(shlex.split(command))
        # Change the name of veth_inside to $dev
        LOG.debug("Renaming veth inner interface '%s' to '%s'",
                  veth_inside, dev)
        command = "ip netns exec %s ip link set dev %s name %s" \
                  % (pid, veth_inside, dev)
        utils.call_popen(shlex.split(command))
        # Up the inner interface
        LOG.debug("Bringing veth inner interface '%s' up", dev)
        command = "ip netns exec %s ip link set %s up" % (pid, dev)
        utils.call_popen(shlex.split(command))
        # Set the mtu to handle tunnels
        LOG.debug("Adjusting veth interface '%s' MTU for tunneling to %d",
                  dev, 1450)
        command = "ip netns exec %s ip link set dev %s mtu %s" \
                  % (pid, dev, 1450)
        utils.call_popen(shlex.split(command))
        # Set the ip address
        LOG.debug("Setting IP address for container:%s interface:%s",
                  container_id, dev)
        command = "ip netns exec %s ip addr add %s/%s dev %s" \
                  % (pid, ip_address, prefixlen, dev)
        utils.call_popen(shlex.split(command))
        # Set the mac address
        LOG.debug("Setting MAC address for container:%s interface:%s",
                  container_id, dev)
        command = "ip netns exec %s ip link set dev %s address %s" \
                  % (pid, dev, mac)
        utils.call_popen(shlex.split(command))
        # Set the gateway
        command = "ip netns exec %s ip route add default via %s" \
                  % (pid, gateway_ip)
        utils.call_popen(shlex.split(command))
        return veth_inside, veth_outside
    except Exception:
        # TODO: cleanup
        LOG.exception("Failed to setup veth pair for pod")
        raise OVNCNIException(103, "veth setup failure")


def _generate_container_ip(cidr):
    # The ultra poor man's IPAM.
    # TODO: store at least used ips somewhere
    try:
        random.seed()
        ip_address = netaddr.IPAddress(random.randint(
            cidr.first + 2, cidr.last - 1))
        gateway_ip = netaddr.IPAddress(cidr.first + 1)
        return ip_address, gateway_ip
    except Exception:
        LOG.exception("Error while generating IP adress from CIDR:%s", cidr)
        raise OVNCNIException(104, "Failure while generating pod IP address")


def _create_ovn_logical_port(lswitch_name, container_id, mac,
                             ip_address, pod_name, ns_name=None):
    # TODO: This should use the OVSDB transact capability.
    try:
        # Create logical port
        LOG.debug("Creating logical port on switch %s for container %s",
                  lswitch_name, container_id)
        ovn.ovn_nbctl('lport-add', lswitch_name, container_id)
        # Set the ip address and mac address
        LOG.debug("Setting up MAC (%s) and IP (%s) addresses for logical port",
                  mac, ip_address)
        cmd_items = tuple(shlex.split('lport-set-addresses %s "%s %s"' %
                                      (container_id, mac, ip_address)))
        ovn.ovn_nbctl(*cmd_items)
        # Block all ingress traffic
        # TODO: also block egress if Kubernetes network policy allow to
        # discipline it
        LOG.debug("Adding drop-all ACL for port %s", container_id)
        # Note: The reason rather complicated expression is to be able to set
        # an external id for the ACL as well (acl-add won't return the ACL id)
        ovn.create_ovn_acl(lswitch_name, pod_name, container_id,
                           constants.DEFAULT_ACL_PRIORITY,
                           'outport\=\=\"%s\"\ &&\ ip' % container_id,
                           'drop')
        # Store the port name and the kubernetes pod name in the ACL's external
        # IDs. This will make retrieval easier
        # Store pod name and, if provided, the namespace name in port's
        # external ids in order to keep track of the association between
        # pod and logical port
        if ns_name:
            ovn.ovn_nbctl('set', 'Logical_port', container_id,
                          'external_ids:k8s_pod_name=%s' % pod_name,
                          'external_ids:k8s_ns_name=%s' % ns_name)
        else:
            ovn.ovn_nbctl('set', 'Logical_port', container_id,
                          'external_ids:k8s_pod_name=%s' % pod_name)
    except Exception:
        LOG.exception("Unable to configure OVN logical port for pod on "
                      "lswitch %s", lswitch_name)
        raise OVNCNIException(105, "Failure while setting up OVN logical port")


def _cni_add(network_config, lswitch_name):
    try:
        netns_dst = os.environ[constants.CNI_NETNS]
        container_id = os.environ[constants.CNI_CONTAINER_ID]
        cni_args_str = os.environ[constants.CNI_ARGS]
        # CNI_ARGS has the format key=value;key2=value2;...
        cni_args = dict(item.split('=') for item in cni_args_str.split(';'))
        pod_name = cni_args[constants.K8S_POD_NAME]
        # Not sure whether K8S_POD_NAMESPACE is an 'official' CNI arg
        ns_name = cni_args.get(constants.K8S_POD_NAMESPACE)
        dev = os.environ.get(constants.CNI_IFNAME, 'eth0')
        pid_match = re.match("^/proc/(.\d*)/ns/net$", netns_dst)
        if not pid_match:
            raise OVNCNIException(
                103, "Unable to extract container pid from namespace")
        pid = pid_match.groups()[0]
        cidr = netaddr.IPNetwork(network_config['ipam']['subnet'])
        mac = _generate_mac()
    except KeyError:
        raise OVNCNIException(102, 'Required CNI variables missing')

    # Generate container IP
    ip_address, gateway_ip = _generate_container_ip(cidr)

    LOG.debug("Container network namespace:%s", netns_dst)
    LOG.debug("Container ID: %s", container_id)
    LOG.debug("Chosen pod IP: %s", ip_address)

    # Create OVN logical port
    _create_ovn_logical_port(lswitch_name, container_id, mac,
                             ip_address, pod_name, ns_name)

    # Configure the veth pair for the pod
    veth_inside, veth_outside = _setup_interface(
        pid, container_id, dev, mac, ip_address, cidr.prefixlen, gateway_ip)

    # Add the port to a OVS bridge and set the vlan
    try:
        ovn.ovs_vsctl('add-port', constants.OVN_BRIDGE,
                      veth_outside,  '--', 'set',
                      'interface', veth_outside,
                      'external_ids:attached_mac=%s' % mac,
                      'external_ids:iface-id=%s' % container_id,
                      'external_ids:ip_address=%s' % ip_address)
    except Exception:
        LOG.exception("Unable to plug interface into OVN bridge")
        ovn.ovn_nbctl("lport-del", container_id)
        raise OVNCNIException(106, "Failure in plugging pod interface")

    return {
        'ip_address': ip_address,
        'gateway_ip': gateway_ip,
        'mac_address': mac,
        'network': cidr}


def _cni_output(result):
    output = {'cniVersion': constants.CNI_VERSION,
              'ip4': {'ip': '%s/%s' % (result['ip_address'],
                                       result['network'].prefixlen),
                      'gateway': str(result['gateway_ip'])}}
    print(json.dumps(output))


def init_host(args, network_config=None):
    # Check for logical router, if not found create one
    lrouter_name = args.lrouter_name
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
    lswitch_name = _get_host_lswitch_name()
    LOG.info("OVN lswitch for the host: %s", lswitch_name)
    lswitch_data = _check_vswitch(lswitch_name)
    if lswitch_data:
        LOG.debug("OVN Logical Switch for K8S host found. Skipping creation")
    else:
        LOG.debug("Creating LogicalSwitch for K8S host with name: %s",
                  lswitch_name)
        ovn.ovn_nbctl('lswitch-add', lswitch_name)

    if network_config:
        # Grab subnet from nework config
        subnet = network_config['ipam']['subnet']
    elif args.subnet:
        # Maybe we have passed it as an argument?
        subnet = args.subnet
    else:
        LOG.debug("As no subnet was specified host configuration will "
                  "not be completed")
        return
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
        lrp_mac = _generate_mac()
        cidr = netaddr.IPNetwork(subnet)
        ip_address = netaddr.IPAddress(cidr.first + 1)
        lrp_uuid = ovn.ovn_nbctl('--', '--id=@lrp', 'create',
                                 'Logical_Router_port',
                                 'name=%s' % lswitch_name,
                                 'network=%s' % ip_address,
                                 'mac="%s"' % lrp_mac, '--', 'add',
                                 'Logical_Router', lrouter_name, 'ports',
                                 '@lrp', '--', 'lport-add',
                                 lswitch_name, 'rp-%s' % lswitch_name)
        ovn.ovn_nbctl('set', 'Logical_port', 'rp-%s' % lswitch_name,
                      'type=router', 'options:router-port=%s' % lswitch_name,
                      'addresses="%s"' % lrp_mac)
        LOG.debug("Configured logical router port: %s", lrp_uuid)


def _cni_del(container_id, network_config):
    # Remove IP allocation
    # Oh wait, we do not store them anyway, so why bother at all?
    # Remove OVN ACLs...
    # TODO: We might first want to have the code that adds them
    # Remove OVN Logical port
    try:
        ovn.ovn_nbctl("lport-del", container_id)
    except Exception:
        message = "Unable to remove OVN logical port"
        LOG.exception(message)
        raise OVNCNIException(110, message)
    try:
        ovn.ovs_vsctl("del-port", container_id[:15])
    except Exception:
        # Do not make this critical - in some cases the port appears to
        # have already been deleted (need more investigation)
        message = "failed to delete OVS port %s" % container_id[:15]
        LOG.exception(message)
    # Remove namespace
    netns_dst = os.environ[constants.CNI_NETNS]
    pid_match = re.match("^/proc/(.\d*)/ns/net$", netns_dst)
    if not pid_match:
        raise OVNCNIException(
            103, "Unable to extract container pid from namespace")
    pid = pid_match.groups()[0]
    LOG.debug("Container pid: %s; Removing namespace link", pid)
    command = "rm -f /var/run/netns/%s" % pid
    utils.call_popen(shlex.split(command))


def cni_add(args):
    try:
        LOG.debug("Reading configuration on standard input")
        LOG.debug("As for the env...")
        network_config = _parse_stdin()
        container_id = os.environ.get(constants.CNI_CONTAINER_ID)
        LOG.info("Configuring networking for container:%s", container_id)
        LOG.debug("Network config from input: %s", network_config)
        LOG.debug("Verifying host setup")
        lswitch_name = _check_host_vswitch(args, network_config)
        LOG.debug("Configuring pod networking on container %s",
                  container_id)
        result = _cni_add(network_config, lswitch_name)
        LOG.info("Pod networking configured on container %s."
                 "OVN logical port: %s; IP address: %s",
                 container_id, "TODO", result['ip_address'])
        _cni_output(result)
    except OVNCNIException as oce:
        print(oce.cni_error())
        sys.exit(1)


def cni_del(args):
    try:
        LOG.debug("Reading configuration on standard input")
        network_config = _parse_stdin()
        container_id = os.environ.get(constants.CNI_CONTAINER_ID)
        LOG.info("Deconfiguring networking for container:%s", container_id)
        LOG.debug("Verifying host setup")
        _check_host_vswitch(args, network_config)
        LOG.debug("Network config from input: %s", network_config)
        _cni_del(container_id, network_config)
        LOG.info("Pod networking de-configured on container %s", container_id)
    except OVNCNIException as oce:
        print(oce.cni_error())
        sys.exit(1)


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(title='Subcommands',
                                       dest='command_name')

    # Parser for init command (not a CNI command)
    parser_host_init = subparsers.add_parser('init')
    parser_host_init.add_argument('--lrouter-name',
                                  default=constants.DEFAULT_LROUTER_NAME)
    parser_host_init.add_argument('--subnet', default=None)
    parser_host_init.set_defaults(func=init_host)
    # Parser for CNI ADD command
    parser_cni_add = subparsers.add_parser("ADD")
    parser_cni_add.set_defaults(func=cni_add)
    # Parser for CNI DEL command
    parser_cni_del = subparsers.add_parser("DEL")
    parser_cni_del.set_defaults(func=cni_del)
    args = parser.parse_args()
    args.func(args)


def main():
    log.register_options(cfg.CONF)
    cfg.CONF.set_override('log_file', constants.CNI_LOGFILE)
    cfg.CONF.set_override('debug', True)
    log.setup(cfg.CONF, 'ovn_cni')
    cni_command = os.environ.get(constants.CNI_COMMAND)
    LOG.debug("CNI Command in environment: %s", cni_command)
    if cni_command:
        sys.argv = [sys.argv[0], cni_command] + sys.argv[1:]
    LOG.info("ovn_cni plugin invoked with arguments:%s",
             ",".join(sys.argv[1:]))
    # parse_args is also expected to launch the appropriate subcommand
    parse_args()


if __name__ == '__main__':
    main()