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
        return self._watchers['k8s_pod']

    @k8s_pod_watcher.setter
    def k8s_pod_watcher(self, watcher):
        self._watchers['k8s_pod'] = watcher

    @k8s_pod_watcher.deleter
    def k8s_pod_watcher(self):
        del self._watchers['k8s_pod']

    @property
    def k8s_ns_watcher(self):
        return self._watchers['k8s_ns']

    @k8s_ns_watcher.setter
    def k8s_ns_watcher(self, watcher):
        self._watchers['k8s_ns'] = watcher

    @k8s_ns_watcher.deleter
    def k8s_ns_watcher(self):
        del self._watchers['k8s_ns']

    @property
    def k8s_np_watcher(self):
        return self._watchers['k8s_np']

    @k8s_np_watcher.setter
    def k8s_np_watcher(self, watcher):
        self._watchers['k8s_np'] = watcher

    @k8s_np_watcher.deleter
    def k8s_np_watcher(self):
        del self._watchers['k8s_np']

    @property
    def ovndb_watcher(self):
        return self._watchers['ovndb']

    @ovndb_watcher.setter
    def ovndb_watcher(self, watcher):
        self._watchers['ovndb'] = watcher

    @ovndb_watcher.deleter
    def ovndb_watcher(self):
        del self._watchers['ovndb']
