POD = 'k8s_pod'
NS = 'k8s_ns'
NP = 'k8s_np'


class WatcherRegistry(object):

    _instance = None

    def __init__(self):
        self._watchers = {}

    @classmethod
    def get_instance(cls):
        if not cls._instance:
            cls._instance = cls()
        return cls._instance

    @property
    def k8s_pod_watcher(self):
        return self._watcher.get(POD)

    @k8s_pod_watcher.setter
    def k8s_pod_watcher(self, watcher):
        self._watchers[POD] = watcher

    @k8s_pod_watcher.deleter
    def k8s_pod_watcher(self):
        del self._watchers[POD]

    @property
    def k8s_ns_watcher(self):
        return self._watchers.get(NS)

    @k8s_ns_watcher.setter
    def k8s_ns_watcher(self, watcher):
        self._watchers[NS] = watcher

    @k8s_ns_watcher.deleter
    def k8s_ns_watcher(self):
        del self._watchers[NS]

    @property
    def k8s_np_watcher(self):
        return self._watchers.get(NP)

    @k8s_np_watcher.setter
    def k8s_np_watcher(self, watcher):
        self._watchers[NP] = watcher

    @k8s_np_watcher.deleter
    def k8s_np_watcher(self):
        del self._watchers[NP]
