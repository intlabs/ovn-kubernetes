from oslo_log import log
import requests

LOG = log.getLogger(__name__)


def watch_pods(host, port):
    url = "http://%s:%d/api/v1/pods?watch=true" % (host, port)
    # TODO(me): HTTPS and authentication
    response = requests.get(url, stream=True)
    if response.status_code != 200:
        # TODO(me): raise here
        return
    return response.iter_lines(chunk_size=10, delimiter='\n')
