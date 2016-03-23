OVN CNI plugin 
==============

The `ovn_cni.py` script partially implements the Container Network Interface,
providing a plugin for the 'main' interface - i.e.: the one responsible for
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

If installed via pip or setup.py the CNI plugin should be in your path:

```
which ovn_cni
```

In order to use it with Kubernetes create a symbolic link to this script
to Kubernetes CNI plugin directory - usually /opt/cni/bin

Host Initialization
--------------------

Initialization can be performed by invoking the command *init* on the plugin
script:

```bash
$ ovn_cni.py init --subnet 192.168.0.0/24
```

As this plugin is currently specifically tailored for Kubernetes, the init
process will look for an OVN logical router called *k8s_router*. If not
found, it will create it. It also possible to use a customised router name
by passing it to the init command:

```bash
$ ovn_cni.py init --subnet 192.168.0.0/24 --lrouter-name another_router
```

The *subnet* parameter is the node IP subnet, which must coincide with the CNI
network CIDR passed to the plugin. The plugin indeed currently assumes a single
and distinct IP network per node.
Then the init process will perform the following operations:

1. Check for the presence of a node logical switch
2. Create the node logical switch if necessary
3. Connect the node logical switch to the router (if not already done)

The logic for the logical node switch is currently very kubernetes-dependent.
Indeed it assumes that a `kubelet` is running on the same node and uses the
kubelet introspection API to fetch the node machine ID, which is then used as
the name for the node logical switch.


Adding a container to a network
-------------------------------

The CNI ADD operation performs the following operations:

1. Fetch needed information from standard input and environment. In particular,
   retrieve the CNI container ID (which for Kubernetes is the Infra Pod
   Container), and its network namespace location.
2. Setup the network interface for the container - note that when the plugin is
   invoked the container has not yet been created. This implies creating a veth
   pair, adding a peer interface to the container namespace, and configuring
   addresses and MTU for this interface.
3. Select an IP address for the container interface. This is currently achieved
   in a rather rough way, to put it nicely. Using more realistic words it is a
   wild hack which shall be removed as soon as possible.
4. Configure the logical port for the container in the OVN NorthBound database.
5. Apply a baseline security policy to the container interface. So far, this
   simply means that all traffic coming into the interface is blocked. This is
   achieved with OVN ACLs. See the securing container section for more
   information.
6. Plug the other veth peer (the one in the root namespace) into the node OVN
   bridge (which for this plugin is always `br-int`)


The plugin stores the Kubernetes pod name in the *external_ids* attribute of
the OVN Logical Port. The key for the pod is *k8s_pod_name*. This information
will be leveraged when applying ACLs to the OVN logical port.


Removing a container from a network
-----------------------------------

The CNI DEL operation takes care of removing the veth interfaces for the
container (the pod infra container in the Kubernetes case), and destroying
the OVN logical port.

Given the massive hack the IPAM logic currently is, there is no code for
reclaiming the IP address used by the container. Eventually something will
be done about this.


Securing containers
-------------------

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
