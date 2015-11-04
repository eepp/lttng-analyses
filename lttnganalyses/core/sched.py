# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
#               2015 - Antoine Busque <abusque@efficios.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from .analysis import Analysis


class SchedEvent():
    def __init__(self, wakeup_ts, waker, switch_ts):
        self.wakeup_ts = wakeup_ts
        self.waker = waker
        self.switch_ts = switch_ts


class SchedAnalysis(Analysis):
    def __init__(self, state, min_latency, max_latency):
        notification_cbs = {
            'sched_switch_per_tid': self._process_sched_switch,
        }

        self._state = state
        self._state.register_notification_cbs(notification_cbs)
        self._min_latency = min_latency
        self._max_latency = max_latency
        # µs to ns
        if self._min_latency is not None:
            self._min_latency *= 1000
        if self._max_latency is not None:
            self._max_latency *= 1000

        # Log of individual wake scheduling events
        self.sched_list = []
        # Index scheduling latencies by tid
        self.sched_stats = {}

    def process_event(self, ev):
        pass

    def reset(self):
        self.sched_list = []

    def _process_sched_switch(self, **kwargs):
        timestamp = kwargs['timestamp']
        prev_tid = kwargs['prev_tid']
        next_tid = kwargs['next_tid']
        next_comm = kwargs['next_comm']

        if next_tid not in self.tids:
            return

        process = self.tids[next_tid]
        if process.last_wakeup is None:
            return

        latency = timestamp - process.last_wakeup
        if self._min_latency is not None and latency < self._min_latency:
            return
        if self._max_latency is not None and latency > self._max_latency:
            return
        if not next_tid in self.sched_stats:
            self.sched_stats[next_tid] = SchedStats(process.tid, process.comm)
        self.sched_stats[next_tid].update_stats(process.last_wakeup,
                                                process.last_waker, timestamp)


class SchedStats():
    def __init__(self, tid, comm):
        self.tid = tid
        self.comm = comm
        self.min_latency = None
        self.max_latency = None
        self.total_latency = 0
        self.sched_list = []

    @property
    def count(self):
        return len(self.sched_list)

    def update_stats(self, wakeup, waker, switch):
        latency = switch - wakeup

        if self.min_latency is None or latency < self.min_latency:
            self.min_latency = latency

        if self.max_latency is None or latency > self.max_latency:
            self.max_latency = latency

        self.total_latency += latency
        sched_event = SchedEvent(wakeup, waker, switch)
        self.sched_list.append(sched_event)

    def reset(self):
        self.min_latency = None
        self.max_latency = None
        self.total_latency = 0
        self.sched_list = []
