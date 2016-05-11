import shlex

from oslo_log import log

import ovn_k8s
from ovn_k8s import constants
from ovn_k8s.lib import ovn
from ovn_k8s import policy_processor as pp

LOG = log.getLogger(__name__)


class ConnectivityProcessor(ovn_k8s.BaseProcessor):

    def _check_lswitch(self, lswitch_name):
        LOG.info("OVN lswitch for the host: %s", lswitch_name)
        lswitch_raw_data = ovn.ovn_nbctl('find', 'Logical_Switch',
                                         'name=%s' % lswitch_name)
        lswitch_data = ovn.parse_ovn_nbctl_output(lswitch_raw_data)
        if len(lswitch_data) > 1:
            LOG.warn("I really was not expecting more than one switch... "
                     "I'll pick the first, there's a %.2f\% chance I'll "
                     "get it right" % (100 / len(lswitch_data)))
        if lswitch_data:
            return lswitch_data[0]

    def _add_lport(self, container_id, event):
        lswitch_name = event.metadata['spec']['nodeName']
        pod_name = event.source
        ns_name = event.metadata['metadata']['namespace']

        if not self._check_lswitch(lswitch_name):
            # TODO(me): Consider setting an error annotation in the pod so that
            # the plugin will become aware of the error condition and fail the
            # CNI operation, which should hopefully trigger a reschedule for
            # the pod
            LOG.warn("No logical switch for host %s was found."
                     "No logical port will be created for the pod %s",
                     lswitch_name, pod_name)
            return
        LOG.debug("Creating logical port on switch %s for container %s",
                  lswitch_name, pod_name)
        # Use pod name as port name
        try:
            ovn.ovn_nbctl('lport-add', lswitch_name, container_id)
            # Store the port name and the kubernetes pod name in the ACL's
            # external  IDs. This will make retrieval easier
            # Store pod and amespace names in port's external ids in order
            # to keep track of the association between pod and logical port
            ovn.ovn_nbctl('set', 'Logical_port', container_id,
                          'external_ids:pod_name=%s' % pod_name,
                          'external_ids:ns_name=%s' % ns_name)
            # Block all ingress traffic
            # TODO: also block egress if Kubernetes network policy allow to
            # discipline it
            LOG.debug("Adding drop-all ACL for pod %s", pod_name)
            # Note: The rather complicated expression is to be able to set an
            # external id for the ACL (acl-add won't return the ACL id)
            ovn.create_ovn_acl(lswitch_name, pod_name, container_id,
                               constants.DEFAULT_ACL_PRIORITY,
                               r'outport\=\=\"%s\"\ &&\ ip' % container_id,
                               'drop')
        except Exception:
            LOG.exception("Unable to created logical port for pod %s on "
                          "logical switch %s", pod_name, lswitch_name)
            return

    def _del_lport(self, event):
        try:
            container_id = (event.metadata['metadata']['annotations']
                            ['infraContainerId'])
            ovn.ovn_nbctl("lport-del", container_id)
        except Exception:
            LOG.exception("Unable to remove OVN logical port %s for pod: %s",
                          container_id, event.source)
        # Process policies too for this event
        pp.get_event_queue().put((constants.POD_EVENT_PRIORITY, event))

    def _configure_lport(self, event):
        pod_name = event.source
        pod_ip = event.metadata['status'].get('podIP')
        pod_mac = event.metadata['metadata']['annotations'].get('podMAC')
        container_id = (event.metadata['metadata']['annotations']
                        ['infraContainerId'])
        lport_data_raw = ovn.ovn_nbctl(
            'find', 'Logical_Port', 'external_ids:pod_name=%s' % pod_name)
        lport_data = ovn.parse_ovn_nbctl_output(lport_data_raw)
        if not lport_data:
            self._add_lport(container_id, event)

        if not pod_ip:
            LOG.warn("Unable to configure logical port as pod IP address "
                     "was not found")
            return
        if not pod_mac:
            LOG.warn("Unable to configure logical port as pod MAC address "
                     "was not found")
            return
        LOG.debug("Setting up MAC (%s) and IP (%s) addresses for logical port",
                  pod_mac, pod_ip)
        cmd_items = tuple(shlex.split('lport-set-addresses %s "%s %s"' %
                                      (container_id, pod_mac, pod_ip)))
        ovn.ovn_nbctl(*cmd_items)
        # Process policies too for this event
        pp.get_event_queue().put((constants.POD_EVENT_PRIORITY, event))

    def process_events(self, events):
        for event in events:
            # We do not expect any POD_ADD event, as they cannot contain enough
            # information to create the logical port
            if event.event_type == constants.POD_UPDATE:
                self._configure_lport(event)
            elif event.event_type == constants.POD_DEL:
                self._del_lport(event)


def get_event_queue():
    return ConnectivityProcessor.get_instance().event_queue


def run_processor():
    ConnectivityProcessor.get_instance().run()
