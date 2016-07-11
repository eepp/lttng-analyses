# The MIT License (MIT)
#
# Copyright (C) 2016 - Philippe Proulx <pproulx@efficios.com>
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

from functools import partial
import babeltrace as bt
import enum


# definition of a period
class PeriodDefinition:
    def __init__(self, name, begin_expr, end_expr):
        self._name = name
        self._begin_expr = begin_expr
        self._end_expr = end_expr

    @property
    def name(self):
        return self._name

    @property
    def begin_expr(self):
        return self._begin_expr

    @property
    def end_expr(self):
        return self._end_expr


class _Expression:
    pass


class _BinaryExpression(_Expression):
    def __init__(self, lh_expr, rh_expr):
        self._lh_expr = lh_expr
        self._rh_expr = rh_expr

    @property
    def lh_expr(self):
        return self._lh_expr

    @property
    def rh_expr(self):
        return self._rh_expr


class _UnaryExpression(_Expression):
    def __init__(self, expr):
        self._expr = expr

    @property
    def expr(self):
        return self._expr


class LogicalNotExpression(_UnaryExpression):
    def __repr__(self):
        return '(!{})'.format(self.expr)


class LogicalAndExpression(_BinaryExpression):
    def __repr__(self):
        return '({} && {})'.format(self.lh_expr, self.rh_expr)


class EqExpression(_BinaryExpression):
    def __repr__(self):
        return '({} == {})'.format(self.lh_expr, self.rh_expr)


class LtExpression(_BinaryExpression):
    def __repr__(self):
        return '({} < {})'.format(self.lh_expr, self.rh_expr)


class LtEqExpression(_BinaryExpression):
    def __repr__(self):
        return '({} <= {})'.format(self.lh_expr, self.rh_expr)


class GtExpression(_BinaryExpression):
    def __repr__(self):
        return '({} > {})'.format(self.lh_expr, self.rh_expr)


class GtEqExpression(_BinaryExpression):
    def __repr__(self):
        return '({} >= {})'.format(self.lh_expr, self.rh_expr)


class NumberExpression(_Expression):
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return '({})'.format(self.value)


class StringExpression(_Expression):
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

    def __repr__(self):
        return '("{}")'.format(self.value)


@enum.unique
class DynScope(enum.Enum):
    AUTO = 'auto'
    TPH = '$pkt_header.'
    SPC = '$pkt_ctx.'
    SEH = '$header.'
    SEC = '$stream_ctx.'
    EC = '$ctx.'
    EP = '$payload.'


class EventFieldExpression(_Expression):
    def __init__(self, is_begin, dyn_scope, name):
        self._is_begin = is_begin
        self._dyn_scope = dyn_scope
        self._name = name

    @property
    def is_begin(self):
        return self._is_begin

    @property
    def dyn_scope(self):
        return self._dyn_scope

    @property
    def name(self):
        return self._name

    def __repr__(self):
        r = ''

        if self.is_begin:
            r += '$begin.'

        r += '$evt.{}'.format(self.name)

        return '({})'.format(r)


class EventNameExpression(_Expression):
    def __init__(self, is_begin):
        self._is_begin = is_begin

    @property
    def is_begin(self):
        return self._is_begin

    def __repr__(self):
        r = ''

        if self.is_begin:
            r += '$begin.'

        r += '$name'

        return '({})'.format(r)


class IllegalExpression(Exception):
    pass


class ExpressionValidator:
    def __init__(self, expr, is_begin):
        self._expr = expr
        self._is_begin = is_begin
        self._is_valid = False
        self._validate_cbs = {
            LogicalNotExpression: self._validate_not,
            LogicalAndExpression: self._validate_and_expr,
            EqExpression: self._validate_comp,
            LtExpression: self._validate_comp,
            LtEqExpression: self._validate_comp,
            GtExpression: self._validate_comp,
            GtEqExpression: self._validate_comp,
        }
        self._validate(expr)

    def _validate_not(self, not_expr):
        self._validate(not_expr.expr)

    def _validate_and_expr(self, and_expr):
        self._validate(and_expr.lh_expr)
        self._validate(and_expr.rh_expr)

    def _validate_field(self, field_expr):
        if self._is_begin:
            if field_expr.is_begin:
                raise IllegalExpression('Illegal reference to $begin context in begin expression')

    def _validate_comp(self, comp_expr):
        lh_expr = comp_expr.lh_expr
        rh_expr = comp_expr.rh_expr

        if type(lh_expr) is EventFieldExpression:
            self._validate_field(lh_expr)

        if type(rh_expr) is EventFieldExpression:
            self._validate_field(rh_expr)

    def _validate(self, expr):
        if type(expr) in self._validate_cbs:
            self._validate_cbs[type(expr)](expr)


class MatchContext:
    def __init__(self, cur_event):
        self._cur_event = cur_event

    @property
    def cur_event(self):
        return self._cur_event


_DYN_SCOPE_TO_BT_CTF_SCOPE = {
    DynScope.TPH: bt.common.CTFScope.TRACE_PACKET_HEADER,
    DynScope.SPC: bt.common.CTFScope.STREAM_PACKET_CONTEXT,
    DynScope.SEH: bt.common.CTFScope.STREAM_EVENT_HEADER,
    DynScope.SEC: bt.common.CTFScope.STREAM_EVENT_CONTEXT,
    DynScope.EC: bt.common.CTFScope.EVENT_CONTEXT,
    DynScope.EP: bt.common.CTFScope.EVENT_FIELDS,
}


class _Matcher:
    def __init__(self, expr, cur_context, begin_context):
        self._cur_context = cur_context
        self._begin_context = begin_context
        self._expr_matchers = {
            LogicalAndExpression: self._and_expr_matches,
            LogicalNotExpression: self._not_expr_matches,
            EqExpression: partial(self._comp_expr_matches, lambda lh, rh: lh == rh),
            LtExpression: partial(self._comp_expr_matches, lambda lh, rh: lh < rh),
            LtEqExpression: partial(self._comp_expr_matches, lambda lh, rh: lh <= rh),
            GtExpression: partial(self._comp_expr_matches, lambda lh, rh: lh > rh),
            GtEqExpression: partial(self._comp_expr_matches, lambda lh, rh: lh >= rh),
        }
        self._matches = self._expr_matches(expr)

    def _and_expr_matches(self, expr):
        return (self._expr_matches(expr.lh_expr) and
                self._expr_matches(expr.rh_expr))

    def _not_expr_matches(self, expr):
        return not self._expr_matches(expr.expr)

    def _get_context(self, is_begin):
        assert(not(is_begin and self._begin_context is None))

        return self._begin_context if is_begin else self._cur_context

    def _event_name_matches(self, expr):
        context = self._get_context(expr.lh_expr.is_begin)

        return context.cur_event.name == expr.rh_expr.value

    def _get_event_field_from_expr(self, expr):
        context = self._get_context(expr.is_begin)

        if expr.dyn_scope == DynScope.AUTO:
            # automatic dynamic scope
            if expr.name in context.cur_event:
                return context.cur_event[expr.name]

            return
        else:
            # specific dynamic scope
            bt_ctf_scope = _DYN_SCOPE_TO_BT_CTF_SCOPE[expr.dyn_scope]

            return context.cur_event.field_with_scope(expr.name, bt_ctf_scope)

    def _comp_expr_matches(self, compfn, expr):
        if type(expr.lh_expr) is EventNameExpression:
            # we do not need compfn here because the event name must
            # match exactly
            return self._event_name_matches(expr)
        elif type(expr.lh_expr) is EventFieldExpression:
            lh_field_value = self._get_event_field_from_expr(expr.lh_expr)
        else:
            # this is not supposed to happen with the current grammar
            assert(False)

        if type(expr.rh_expr) in (NumberExpression, StringExpression):
            rh_value = expr.rh_expr.value

            # cast RH to int if field is an int
            if type(lh_field_value) is int and type(rh_value) is float:
                rh_value = int(rh_value)

            # compare types first
            if type(lh_field_value) is not type(rh_value):
                return False

            # compare field to a literal value
            return compfn(lh_field_value, expr.rh_expr.value)
        elif type(expr.rh_expr) is EventFieldExpression:
            # compare field to another field
            rh_field_value = self._get_event_field_from_expr(expr.rh_expr)

            return compfn(lh_field_value, rh_field_value)

    def _expr_matches(self, expr):
        return self._expr_matchers[type(expr)](expr)

    @property
    def matches(self):
        return self._matches


def expr_matches(expr, cur_context, begin_context=None):
    return _Matcher(expr, cur_context, begin_context).matches


def create_conjunction_from_exprs(exprs):
    if len(exprs) == 0:
        return

    cur_expr = exprs[0]

    for expr in exprs[1:]:
        cur_expr = LogicalAndExpression(cur_expr, expr)

    return cur_expr
