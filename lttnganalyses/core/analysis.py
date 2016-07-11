# The MIT License (MIT)
#
# Copyright (C) 2015 - Julien Desfossez <jdesfossez@efficios.com>
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

from . import period as core_period
from . import event as core_event


class PeriodData:
    def __init__(self, start_ts, begin_context=None):
        self._period_start_ts = start_ts
        self._begin_context = begin_context

    @property
    def period_start_ts(self):
        return self._period_start_ts

    @property
    def begin_context(self):
        return self._begin_context


class AnalysisConfig:
    def __init__(self):
        self.refresh_period = None
        self.begin_ts = None
        self.end_ts = None
        self.min_duration = None
        self.max_duration = None
        self.proc_list = None
        self.tid_list = None
        self.cpu_list = None
        self.period_defs = []


class Analysis:
    TICK_CB = 'tick'

    def __init__(self, state, conf):
        self._state = state
        self._conf = conf
        self._period_key = None
        self._last_event_ts = None
        self._notification_cli_cbs = {}
        self._cbs = {}
        self._periods = set()

        self.started = False
        self.ended = False

    def process_event(self, ev):
        self._check_analysis_end(ev)
        if self.ended:
            return

        self._last_event_ts = ev.timestamp

        if not self.started:
            if self._conf.begin_ts:
                self._check_analysis_begin(ev)
                if not self.started:
                    return
            else:
#                self._period_start_ts = ev.timestamp
                self.started = True

        # match context: current event
        match_context = core_period.MatchContext(ev)

        # check for end of current periods
        for period in self._periods:
            if core_period.expr_matches(period_def.end_expr, match_context,
                                        period.begin_context):

        # check for begin of period
        for period_def in self._conf.period_defs:
            if core_period.expr_matches(period_def.begin_expr, match_context):
                begin_ev = core_event.Event(ev)
                begin_context = MatchContext(begin_ev)
                self._open_period(period_def, ev.timestamp, begin_context)

        # FIXME: julien
        if self._conf.period_begin_ev_name is not None:
            self._handle_period_event(ev)
        for period in self._periods:
            if self._conf.refresh_period is not None:
                self._check_refresh(period, ev)

    def reset(self, period):
        raise NotImplementedError()

    def begin_analysis(self, first_event):
        # If we do not have any period defined, create a
        # period starting at the first event
        if self._conf.period_begin_ev_name is None and \
                self._conf.begin_ts is None:
            self._open_period(None, first_event.timestamp)

    def end_analysis(self):
        for period in self._periods:
            self._close_period(period)

    def register_notification_cbs(self, cbs):
        for name in cbs:
            if name not in self._notification_cli_cbs:
                self._notification_cli_cbs[name] = []

            self._notification_cli_cbs[name].append(cbs[name])

    def _send_notification_cb(self, period, name, **kwargs):
        if name in self._notification_cli_cbs:
            for cb in self._notification_cli_cbs[name]:
                cb(period, **kwargs)

    def _register_cbs(self, cbs):
        self._cbs = cbs

    def _process_event_cb(self, ev):
        name = ev.name

        if name in self._cbs:
            self._cbs[name](ev)
        elif 'syscall_entry' in self._cbs and \
             (name.startswith('sys_') or name.startswith('syscall_entry_')):
            self._cbs['syscall_entry'](ev)
        elif 'syscall_exit' in self._cbs and \
                (name.startswith('exit_syscall') or
                 name.startswith('syscall_exit_')):
            self._cbs['syscall_exit'](ev)

    def _check_analysis_begin(self, ev):
        if self._conf.begin_ts and ev.timestamp >= self._conf.begin_ts:
            self._open_period(None, ev.timestamp)
            self.started = True

    def _check_analysis_end(self, ev):
        if self._conf.end_ts and ev.timestamp > self._conf.end_ts:
            self.ended = True

    def _check_refresh(self, period, ev):
        if not period.period_start_ts:
            print("TMP DEBUG: should not happen")
#                self.period_start_ts = ev.timestamp
        elif ev.timestamp >= (period.period_start_ts +
                              self._conf.refresh_period):
            # close the current period and create a new one
            self._close_period(period)
            self._open_period(None, ev.timestamp)

    def _handle_period_event(self, ev):
        # FIXME: does not work
        period = None
        if ev.name != self._conf.period_begin_ev_name and \
           ev.name != self._conf.period_end_ev_name:
            return

        if self._period_key:
            period_key = Analysis._get_period_event_key(
                ev, self._conf.period_end_key_fields)

            if not period_key:
                # There was an error caused by a missing field, ignore
                # this period event
                return

            if period_key == self._period_key:
                if self._conf.period_end_ev_name:
                    if ev.name == self._conf.period_end_ev_name:
                        self._close_period()
                        self._period_key = None
                        period.period_start_ts = None
                elif ev.name == self._conf.period_begin_ev_name:
                    self._close_period(period)
                    self._open_period(period_key, ev.timestamp)
        elif ev.name == self._conf.period_begin_ev_name:
            period_key = Analysis._get_period_event_key(
                ev, self._conf.period_begin_key_fields)

            if not period_key:
                return

            if self._conf.period_key_value:
                # Must convert the period key to string for comparison
                str_period_key = tuple(map(str, period_key))
                if self._conf.period_key_value != str_period_key:
                    return

            self._open_period(period_key, ev.timestamp)

    def _open_period(self, period_def, timestamp, begin_context):
        new_period = PeriodData(period_def, timestamp, begin_context)
        self._periods.add(new_period)
        self.reset(new_period)

    def _close_period(self, period):
        self._send_notification_cb(period, Analysis.TICK_CB,
                                   begin_ns=period.period_start_ts,
                                   end_ns=self._last_event_ts)
        self._state.clear_period_notification_cbs(period)
        self._periods.remove(period)

    @staticmethod
    def _get_period_event_key(ev, key_fields):
        if not key_fields:
            return None

        key_values = []

        for field in key_fields:
            try:
                key_values.append(ev[field])
            except KeyError:
                # Error: missing field
                return None

        return tuple(key_values)

    def _filter_process(self, proc):
        if not proc:
            return True
        if self._conf.proc_list and proc.comm not in self._conf.proc_list:
            return False
        if self._conf.tid_list and proc.tid not in self._conf.tid_list:
            return False
        return True

    def _filter_cpu(self, cpu):
        return not (self._conf.cpu_list and cpu not in self._conf.cpu_list)
