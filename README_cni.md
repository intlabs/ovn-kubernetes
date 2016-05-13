OVN CNI plugin 
==============

The `ovn_cni.py` script partially implements the Container Network Interface,
providing a plugin for its 'main' interface - i.e.: the one responsible for
setting up and tearing down networking for a plugin.

There is currently no integration with CNI IPAM plugins. The `ovn_cni` plugin
provides a very rough IPAM solution which is not recommended at all for
production deployments.

OVN logical network topology

This CNI plugin build a rather simple OVN topology. Each node is assumed to
have a distinct, dedicated logical switch and IP subnet, which shall be
described in a CNI network configuration file.

Every node switch is then connected to a OVN logical router, thus enabling
L3 forwarding across all logical switches.

Plugin installation
--------------------

If the package is install using setup.py then the script should be in the
system path. To locate it use `which ovn_cni.py`.

In order to use it with Kubernetes create a symbolic link to this script
to Kubernetes CNI plugin directory - usually /opt/ovn_cni/bin.
The actual path depends on Kubernetes CNI network configuration.
The network configuration should be stored in the following path:

```
/usr/libexec/kubernetes/kubelet-plugins/net/exec
```

The network configuration, in json format, contains informations such
as network CIDR, bridge to use, IP allocation strategy, network gateway
and masquerade behaviour. More information on networking configuration
can be found on the [CNI github repo](https://github.com/containernetworking/cni).

Adding a container to a network
--------------------------------

The CNI ADD operation performs the following operations:

1. Fetch needed information from standard input and environment. In particular,
   retrieve the CNI container ID (which for Kubernetes is the Infra Pod
   Container), and its network namespace location.
2. Select an IP and MAC address for the container interface. This is currently
   achieved in a rather rough way, to put it nicely. Using more realistic words
   it is a wild hack which shall be removed as soon as possible.
3. Annotate the POD with the chosen MAC address and the POD infra container ID,
   by sending a PATCH request to the Kubernetes API server.
4. Setup the network interface for the container - note that when the plugin is
   invoked the container has not yet been created. This implies creating a veth
   pair, adding a peer interface to the container namespace, and configuring
   addresses and MTU for this interface.
5. Plug the other veth peer (the one in the root namespace) into the node OVN
   bridge (which for this plugin is always `br-int`)


The plugin stores the Kubernetes pod name and namespace name in the
*external_ids* attribute of the OVN Logical Port. This information
will be leveraged when applying ACLs to the OVN logical port.


Removing a container from a network
-----------------------------------

The CNI DEL operation simplytakes care of removing the veth interfaces for
the container (the pod infra container in the Kubernetes case).

Given the massive hack the IPAM logic currently is, there is no code for
reclaiming the IP address used by the container. Eventually something will
be done about this.


Securing containers
-------------------

TODO: This section must be reviewed in light of recent changes

This section concern an experimental implementation of the proposed 
[Network Isolation Policies](https://docs.google.com/document/d/1qAm-_oSap-f1d6a-xRTj6xaH1sYQBfK36VyjB5XOZug)
for Kubernetes. This section is therefore entirely specific to
Kubernetes integration.

Enforcement of isolation policies is performed asynchronously with regards to
container interface creation and plugging.
A watcher process - which ideally would run on the same node as the OVN
northbound daemon - detects changes in the OVN Northbound DB *Logical_Port*
table.

As soon as a new logical port is detected, the watcher reads its *external_ids*
attribute to fetch Kubernetes pod name and namespace.

The watcher then looks at namespace annotations. If network isolation
(`net.alpha.kubernetes.io/network-isolation`) is not defined or set to *off*
for the namespace, it simply configures a pass-all ACL rule with a priority
higher than the drop-all rule which is added to the default for each logical
port.

If network isolation is enabled on the namespace, then the watcher process
queries the Kubernetes API server to retrieve all network policies configured
for the namespace whose pod selector matches the current pod.

For the remaining network policies, they are converted into OVN ACLs in the
following way:

* If no `ingress` specification is found, white list all traffic with a single
  ACL rule.
* Otherwise, look up `from` clause, and fetch both namespace and pod selectors
  in the clause.
* Assuming at least a selector has been specified, the API server will be
  queried to select from which namespace, and then from which pods, traffic
  should be allowed. This will result in a list of IP addresses.
* Create an ACL allowing IP traffic for each address identified in the
  previous step. If the network policy specifies one or more ports, only allow
  incoming traffic from those ports.

For every ACL rule created the relevant Kubernetes Network policy is stored
in its *external-ids* attribute  this assumes Kubernetes network policy names
are unique and immutable).

NOTE: As the Kubernetes spec only defines ingress policies, only `to-lport`
OVN ACLs are created.

The watcher process will also periodically poll Network Policy objects for
every namespace where isolation is turned on, reacting to CRUD operations,
such as creation of a new policy or removal of an existing Policy.

It will also monitor namespace objects to react to isolation annotations being
turned on or off.
