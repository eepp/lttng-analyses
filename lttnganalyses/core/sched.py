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

from . import stats
from .analysis import Analysis


class SchedAnalysis(Analysis):
    def __init__(self, state, conf):
        self._notification_cbs = {
            'sched_switch_per_tid': self._process_sched_switch,
            'prio_changed': self._process_prio_changed,
        }
        super().__init__(state, conf)

    def count(self, period):
        return len(period.sched_list)

    def reset(self, period):
        # Log of individual wake scheduling events
        period.sched_list = []
        period.min_latency = None
        period.max_latency = None
        period.total_latency = 0
        period.tids = {}
        self._state.register_notification_cbs(period, self._notification_cbs)

    def _process_sched_switch(self, period, **kwargs):
        cpu_id = kwargs['cpu_id']
        switch_ts = kwargs['timestamp']
        wakee_proc = kwargs['wakee_proc']
        waker_proc = kwargs['waker_proc']
        next_tid = kwargs['next_tid']
        wakeup_ts = wakee_proc.last_wakeup
#        print(period)

        if not self._filter_process(wakee_proc):
            return
        if not self._filter_cpu(cpu_id):
            return

        if wakeup_ts is None:
            return

        latency = switch_ts - wakeup_ts
        if self._conf.min_duration is not None and \
           latency < self._conf.min_duration:
            return
        if self._conf.max_duration is not None and \
           latency > self._conf.max_duration:
            return

        if waker_proc is not None and waker_proc.tid not in period.tids:
            period.tids[waker_proc.tid] = \
                ProcessSchedStats.new_from_process(waker_proc)
            period.tids[waker_proc.tid].update_prio(switch_ts, waker_proc.prio)

        if next_tid not in period.tids:
            period.tids[next_tid] = \
                ProcessSchedStats.new_from_process(wakee_proc)
            period.tids[next_tid].update_prio(switch_ts, wakee_proc.prio)

        sched_event = SchedEvent(
            wakeup_ts, switch_ts, wakee_proc, waker_proc, cpu_id)
        period.tids[next_tid].update_stats(sched_event)
        self._update_stats(period, sched_event)

    def _process_prio_changed(self, period, **kwargs):
        timestamp = kwargs['timestamp']
        prio = kwargs['prio']
        tid = kwargs['tid']

        if tid not in period.tids:
            return

        period.tids[tid].update_prio(timestamp, prio)

    def _update_stats(self, period, sched_event):
        if period.min_latency is None or \
                sched_event.latency < period.min_latency:
            period.min_latency = sched_event.latency

        if period.max_latency is None or \
                sched_event.latency > period.max_latency:
            period.max_latency = sched_event.latency

        period.total_latency += sched_event.latency
        period.sched_list.append(sched_event)


class ProcessSchedStats(stats.Process):
    def __init__(self, pid, tid, comm):
        super().__init__(pid, tid, comm)

        self.min_latency = None
        self.max_latency = None
        self.total_latency = 0
        self.sched_list = []

    @property
    def count(self):
        return len(self.sched_list)

    def update_stats(self, sched_event):
        if self.min_latency is None or sched_event.latency < self.min_latency:
            self.min_latency = sched_event.latency

        if self.max_latency is None or sched_event.latency > self.max_latency:
            self.max_latency = sched_event.latency

        self.total_latency += sched_event.latency
        self.sched_list.append(sched_event)

    def reset(self):
        super().reset()
        self.min_latency = None
        self.max_latency = None
        self.total_latency = 0
        self.sched_list = []


class SchedEvent():
    def __init__(self, wakeup_ts, switch_ts, wakee_proc, waker_proc,
                 target_cpu):
        self.wakeup_ts = wakeup_ts
        self.switch_ts = switch_ts
        self.wakee_proc = wakee_proc
        self.waker_proc = waker_proc
        self.prio = wakee_proc.prio
        self.target_cpu = target_cpu
        self.latency = switch_ts - wakeup_ts
