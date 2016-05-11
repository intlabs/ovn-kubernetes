#!/usr/bin/python
import argparse
import json
import netaddr
import os
import random
import re
import shlex
import sys

from oslo_config import cfg
from oslo_log import log

from ovn_k8s import constants
from ovn_k8s.lib import ovn
from ovn_k8s.lib import kubernetes as k8s
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


def _cni_add(network_config):
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
        mac = utils.generate_mac()
    except KeyError:
        raise OVNCNIException(102, 'Required CNI variables missing')

    # Generate container IP
    ip_address, gateway_ip = _generate_container_ip(cidr)

    api_server_host, api_server_port = k8s.get_k8s_api_server()
    # TODO(me): This should be a single class
    # Annotate pod with MAC address
    # Annotate pod with Infra container ID
    k8s.set_pod_annotation(
        api_server_host, api_server_port, ns_name, pod_name,
        'podMAC', mac)
    LOG.debug("MAC:%s annotated on pod %s", mac, pod_name)
    k8s.set_pod_annotation(
        api_server_host, api_server_port, ns_name, pod_name,
        'infraContainerId', container_id)
    LOG.debug("Infra Container Id:%s annotated on pod %s",
              container_id, pod_name)
    LOG.debug("Container network namespace:%s", netns_dst)
    LOG.debug("Container ID: %s", container_id)
    LOG.debug("Chosen pod IP: %s", ip_address)

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


def init_host(args):
    ovn.ovs_vsctl("set", "Open_vSwitch", ".",
                  "external_ids:k8s-api-server-host=%s" %
                  args.k8s_api_server_host)
    ovn.ovs_vsctl("set", "Open_vSwitch", ".",
                  "external_ids:k8s-api-server-port=%s" %
                  args.k8s_api_server_port)


def _cni_del(container_id, network_config):
    # Remove IP allocation
    # Oh wait, we do not store them anyway, so why bother at all?
    # Remove OVN ACLs...
    # TODO: We might first want to have the code that adds them
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
        LOG.debug("Configuring pod networking on container %s",
                  container_id)
        result = _cni_add(network_config)
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
    parser_host_init.add_argument('--subnet')
    parser_host_init.add_argument('--k8s_api_server_host')
    parser_host_init.add_argument('--k8s_api_server_port')
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
