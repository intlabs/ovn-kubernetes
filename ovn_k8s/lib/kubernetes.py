import json

from oslo_config import cfg
from oslo_log import log
import requests

from ovn_k8s import constants
from ovn_k8s.lib import ovn

LOG = log.getLogger(__name__)


def _stream_api(url):
    # TODO(me): HTTPS and authentication
    response = requests.get(url, stream=True)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    return response.iter_lines(chunk_size=10, delimiter='\n')


def _list_resource(host, port, resource, namespace=None,
                   label_selectors=None):
    # Scope URL by namespace if necessary
    if namespace:
        namespace_str = "namespaces/%s/" % namespace
    else:
        namespace_str = ""
    url = "http://%s:%d/api/v1/%s%s" % (host, port, namespace_str, resource)
    query_params = {'labelSelector': label_selectors}
    response = requests.get(url, params=query_params)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    return response


def _get_resource(host, port, resource, name, namespace=None):
    # Scope URL by namespace if necessary
    if namespace:
        namespace_str = "namespaces/%s/" % namespace
    else:
        namespace_str = ""
    url = "http://%s:%d/api/v1/%s%s/%s" % (host, port, namespace_str,
                                           resource, name)
    response = requests.get(url)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    return response


def _watch_resource(host, port, resource):
    url = "http://%s:%d/api/v1/%s?watch=true" % (host, port, resource)
    return _stream_api(url)


def watch_namespaces(host, port):
    return _watch_resource(host, port, 'namespaces')


def watch_pods(host, port):
    return _watch_resource(host, port, 'pods')


def watch_network_policies(host, port, namespace):
    # Use API path for 3rd party resource
    url = ("http://%s:%d/apis/experimental.kubernetes.io/v1/namespaces/"
           "%s/networkpolicys?watch=True") % (host, port, namespace)
    return _stream_api(url)


def get_k8s_api_server():
    if not get_k8s_api_server.location:
        try:
            host = ovn.ovs_vsctl(
                "get", "Open_vSwitch", ".",
                "external_ids:k8s-api-server-host").strip('"')
            port = int(ovn.ovs_vsctl(
                "get", "Open_vSwitch", ".",
                "external_ids:k8s-api-server-port").strip('"'))
            get_k8s_api_server.location = (host, port)
        except Exception as e:
            raise Exception("Unable to find a location for the "
                            "Kubernetes API server :%s" % e)
    return get_k8s_api_server.location
get_k8s_api_server.location = None


def get_pods(host, port, namespace=None, pod_selector=None):
    label_selectors = []
    if pod_selector:
        for name, value in pod_selector.items():
            label_selectors.append('%s in (%s)' % (
                name, ",".join([item for item in value])))
    resources = _list_resource(host, port, 'pods',
                               namespace=namespace,
                               label_selectors=label_selectors)
    if not resources:
        return []
    return resources.json()['items']


def get_pod(host, port, namespace, pod_name):
    resource = _get_resource(host, port, 'pods', pod_name, namespace)
    if not resource:
        return
    return resource.json()


def get_pod_annotations(host, port, namespace, pod):
    url = ("http://%s:%d/api/v1/namespaces/%s/pods/%s" %
           (host, port, namespace, pod))
    response = requests.get(url)
    if not response or response.status_code != 200:
        # TODO(me): raise here
        return
    json_response = response.json()
    annotations = json_response['metadata'].get('annotations')
    LOG.debug("Annotations for pod %s: %s", pod, annotations)
    return annotations


def set_pod_annotation(host, port, namespace, pod, name, value):
    url = ("http://%s:%d/api/v1/namespaces/%s/pods/%s" %
           (host, port, namespace, pod))
    patch = {'op': 'add',
             'path': '/metadata/annotations/%s' % name,
             'value': value}
    response = requests.patch(
        url,
        data=json.dumps([patch]),
        headers={'Content-Type': 'application/json-patch+json'})
    if not response or response.status_code != 200:
        # TODO(me): Raise appropriate exception
        raise Exception("Something went wrong while annotating pod: %s" %
                        response.text)
    json_response = response.json()
    annotations = json_response['metadata'].get('annotations')
    LOG.debug("Annotations for pod after update %s: %s", pod, annotations)
    return annotations


def get_network_policies(host, port, namespace):
    # Use API path for 3rd party resource
    url = ("http://%s:%d/apis/experimental.kubernetes.io/v1/namespaces/"
           "%s/networkpolicys") % (host, port, namespace)
    response = requests.get(url)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    resources = response.json()
    if not resources:
        return []
    return resources['items']


def get_network_policy(host, port, namespace, network_policy):
    # Use API path for 3rd party resource
    url = ("http://%s:%d/apis/experimental.kubernetes.io/v1/namespaces/"
           "%s/networkpolicys/%s") % (host, port, namespace, network_policy)
    response = requests.get(url)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    return response.json()


def get_namespaces(host, port, ns_selector=None):
    label_selectors = []
    if ns_selector:
        for name, value in ns_selector.items():
            label_selectors.append('%s in (%s)' % (
                name, ",".join([item for item in value])))
    resources = _list_resource(host, port, 'namespaces',
                               label_selectors=label_selectors)
    if not resources:
        return []
    return resources.json()['items']


def get_namespace(host, port, name):
    resource = _get_resource(host, port, 'namespaces', name)
    if not resource:
        return
    return resource.json()


def get_ns_annotations(host, port, namespace):
    # TODO(me): https and authentication
    url = ("http://%s:%d/api/v1/namespaces/%s" %
           (host, port, namespace))
    response = requests.get(url)
    if not response or response.status_code != 200:
        # TODO(me): raise here
        return
    json_response = response.json()
    annotations = json_response['metadata'].get('annotations')
    LOG.debug("Annotations for namespace %s: %s",
              namespace, annotations)
    return annotations


def is_namespace_isolated(namespace):
    annotations = get_ns_annotations(cfg.CONF.k8s_api_server_host,
                                     cfg.CONF.k8s_api_server_port,
                                     namespace)
    isolation = annotations and annotations.get(constants.K8S_ISOLATION_ANN)
    # Interpret anythingthat is not "on" as "off"
    if isolation == 'on':
        return True
    else:
        return False
