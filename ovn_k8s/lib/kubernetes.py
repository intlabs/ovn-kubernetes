from oslo_log import log
import requests

LOG = log.getLogger(__name__)


def _stream_api(url):
    # TODO(me): HTTPS and authentication
    response = requests.get(url, stream=True)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    return response.iter_lines(chunk_size=10, delimiter='\n')


def _list_resource(host, port, resource, namespace=None):
    # Scope URL by namespace if necessary
    if namespace:
        namespace_str = "namespaces/%s/" % namespace
    else:
        namespace_str = ""
    url = "http://%s:%d/api/v1/%s%s" % (host, port, namespace_str, resource)
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


def get_pods(host, port, namespace=None):
    resources = _list_resource(host, port, 'pods', namespace)
    if not resources:
        return []
    return resources.json()['items']


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
