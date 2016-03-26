Kubernetes Network Policies
-----------------------------

Network policies are currently managed via ThirdPartyResources.
These resource are a particular kind of extension which enables to add pretty
much anything to Kubernetes API - by simply calling the Kubernetes API.

This means that new resources can be added "on-the-fly" without even having
to restart the API server. As one might expect however, these resources have
no structure, and their content is not validated at all.

The yaml file for the resource and the json files for policies reflect the
current upstream consensus, but are far from stable.

API server configuration
~~~~~~~~~~~~~~~~~~~~~~~~~

ThirdPartyResources must be explicitly enabled in the API server.
To do so add the following parameters to the `runtime-config` option:

```
extensions/v1beta1=true
extensions/v1beta1/thirdpartyresources=true
```

or set these values, separated by a comma in the `RUNTIME_CONFIG` environment
variable before running `hack/local-up-cluster.sh`

Creating the ThirdPartyResource
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is very similar to any other resource (expect for the --validate parameter)

```
kubectl create -f network_policy.yaml --validate=False
```

Creating and retrieving network policies
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ThirdPartyResource name defines its URI path.
Therefore to create a network policy, the following POST request should
be issued:

```
curl -X POST -H "Content-Type: application/json" -d @sample_policy_1.json \
http://localhost:8080/apis/experimental.kubernetes.io/v1/namespaces/default/networkpolicys
```

A few example policy definitions are available in this directory.

Network policies can be simply retrieved with a GET operation"

```
curl http://localhost:8080/apis/experimental.kubernetes.io/v1/namespaces/default/networkpolicys/
```
