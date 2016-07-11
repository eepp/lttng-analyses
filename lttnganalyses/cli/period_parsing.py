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

import pyparsing as pp
from ..core import period


class MalformedExpression(Exception):
    pass


# basic expression grammar
_e = pp.CaselessLiteral('e')
_number = pp.Combine(pp.Word('+-' + pp.nums, pp.nums) +
                     pp.Optional('.' + pp.Optional(pp.Word(pp.nums))) +
                     pp.Optional(_e + pp.Word('+-' + pp.nums, pp.nums))).setResultsName('number')
_quoted_string = pp.QuotedString('"', '\\').setResultsName('quoted-string')
_identifier = pp.Word(pp.alphas + '_', pp.alphanums + '_').setResultsName('id')
_tph_scope = pp.Literal('$pkt_header.').setResultsName('tph-scope')
_spc_scope = pp.Literal('$pkt_ctx.').setResultsName('spc-scope')
_seh_scope = pp.Literal('$header.').setResultsName('seh-scope')
_sec_scope = pp.Literal('$stream_ctx.').setResultsName('sec-scope')
_ec_scope = pp.Literal('$ctx.').setResultsName('ec-scope')
_ep_scope = pp.Literal('$payload.').setResultsName('ep-scope')
_dyn_scope = pp.Group(_tph_scope | _spc_scope | _seh_scope |
                      _sec_scope | _ec_scope | _ep_scope).setResultsName('dyn-scope')
_begin_scope = pp.Literal('$begin.').setResultsName('begin-scope')
_event_scope = pp.Literal('$evt.').setResultsName('event-scope')
_event_field = pp.Group(pp.Optional(_begin_scope) +
                        _event_scope +
                        pp.Optional(_dyn_scope) +
                        _identifier).setResultsName('field')
_event_name = pp.Group(pp.Optional(_begin_scope) +
                       _event_scope +
                       '$name').setResultsName('name')
_relop = pp.Group(pp.Literal('==') | '!=' | '<=' | '>=' | '<' | '>').setResultsName('relop')
_eqop = pp.Group(pp.Literal('==') | '!=').setResultsName('eqop')
_name_comp_expr = pp.Group(_event_name + _eqop + _quoted_string).setResultsName('name-comp-expr')
_number_comp_expr = pp.Group(_event_field + _relop + _number).setResultsName('number-comp-expr')
_string_comp_expr = pp.Group(_event_field + _eqop + _quoted_string).setResultsName('string-comp-expr')
_field_comp_expr = pp.Group(_event_field.setResultsName('lh') + _relop +
                            _event_field.setResultsName('rh')).setResultsName('field-comp-expr')
_conj_exprs = pp.delimitedList(_name_comp_expr |
                               _number_comp_expr |
                               _string_comp_expr |
                               _field_comp_expr, '&&')
_period_name = pp.Word(pp.alphanums + '_-').setResultsName('period-name')
_period = pp.Optional(_period_name) + ':' + _conj_exprs.setResultsName('begin-expr') + \
          pp.Optional(pp.Literal(':') + _conj_exprs).setResultsName('end-expr')


# operator string -> function which creates an expression
_OP_TO_EXPR = {
    '==': lambda lh, rh: period.EqExpression(lh, rh),
    '!=': lambda lh, rh: period.LogicalNotExpression(period.EqExpression(lh, rh)),
    '<': lambda lh, rh: period.LtExpression(lh, rh),
    '<=': lambda lh, rh: period.LtEqExpression(lh, rh),
    '>': lambda lh, rh: period.GtExpression(lh, rh),
    '>=': lambda lh, rh: period.GtEqExpression(lh, rh),
}


def _res_event_name_to_event_name_expression(res_ev_name):
    return period.EventNameExpression('begin-scope' in res_ev_name)


def _res_quoted_string_to_string_expression(res_quoted_string):
    return period.StringExpression(str(res_quoted_string))


def _res_number_to_number_expression(res_number):
    return period.NumberExpression(float(str(res_number)))


def _res_field_to_field_expression(res_field):
    is_begin = 'begin-scope' in res_field
    dyn_scope = period.DynScope.AUTO

    if 'dyn-scope' in res_field:
        dyn_scope = period.DynScope(str(res_field['dyn-scope'][0]))

    field_name = str(res_field['id'])

    return period.EventFieldExpression(is_begin, dyn_scope, field_name)


def _create_binary_op(eqop, lh, rh):
    return _OP_TO_EXPR[eqop[0]](lh, rh)


def _parse_results_to_expression(res_conj_exprs):
    cur_expr = None

    for res_expr in res_conj_exprs:
        res_expr_name = res_expr.getName()

        if res_expr_name == 'name-comp-expr':
            ev_name_expr = _res_event_name_to_event_name_expression(res_expr['name'])
            str_expr = _res_quoted_string_to_string_expression(res_expr['quoted-string'])
            expr = _create_binary_op(res_expr['eqop'], ev_name_expr, str_expr)
        elif res_expr_name == 'number-comp-expr':
            field_expr = _res_field_to_field_expression(res_expr['field'])
            number_expr = _res_number_to_number_expression(res_expr['number'])
            expr = _create_binary_op(res_expr['relop'], field_expr, number_expr)
        elif res_expr_name == 'string-comp-expr':
            field_expr = _res_field_to_field_expression(res_expr['field'])
            str_expr = _res_quoted_string_to_string_expression(res_expr['quoted-string'])
            expr = _create_binary_op(res_expr['eqop'], field_expr, str_expr)
        elif res_expr_name == 'field-comp-expr':
            lh_field_expr = _res_field_to_field_expression(res_expr['lh'])
            rh_field_expr = _res_field_to_field_expression(res_expr['rh'])
            expr = _create_binary_op(res_expr['relop'], lh_field_expr,
                                     rh_field_expr)

        if cur_expr is None:
            cur_expr = expr
        else:
            cur_expr = period.LogicalAndExpression(cur_expr, expr)

    return cur_expr


def parse_period_arg(arg):
    try:
        period_res = _period.parseString(arg, parseAll=True)
    except Exception as e:
        raise MalformedExpression(arg)

    if 'period-name' in period_res:
        name = str(period_res['period-name'])
    else:
        name = None

    if 'end-expr' in period_res:
        begin_expr = _parse_results_to_expression(period_res['begin-expr'])
        end_expr = _parse_results_to_expression(period_res['end-expr'])
    else:
        begin_expr = _parse_results_to_expression(period_res['begin-expr'])
        end_expr = begin_expr

    period.ExpressionValidator(begin_expr, True)
    period.ExpressionValidator(end_expr, False)

    return period.PeriodDefinition(name, begin_expr, end_expr)
