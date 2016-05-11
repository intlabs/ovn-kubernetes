import abc
import six
import time

from oslo_config import cfg
from oslo_log import log
from six.moves import queue

LOG = log.getLogger(__name__)


class Event(object):

    def __init__(self, event_type, source, metadata):
        self.event_type = event_type
        self.source = source
        self.metadata = metadata


@six.add_metaclass(abc.ABCMeta)
class BaseProcessor(object):

    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self.event_queue = queue.PriorityQueue()

    @abc.abstractmethod
    def process_events(self, events):
        pass

    def run(self):
        empty_loop_counter = 1
        events = []
        while True:
            # get will retrieve a tuple whose first element is the
            # priority that we can discard
            try:
                # Not sure how wait with timeout plays with eventlet
                event = self.event_queue.get_nowait()[1]
                events.append(event)
                LOG.debug("Received event %s from %s",
                          event.event_type,
                          event.source)
                empty_loop_counter = 1
            except queue.Empty:
                # no element in the queue
                if events:
                    empty_loop_counter = empty_loop_counter - 1
                    if empty_loop_counter < 0:
                        # process events
                        self.process_events(events)
                        events = []
                time.sleep(cfg.CONF.coalesce_interval)
