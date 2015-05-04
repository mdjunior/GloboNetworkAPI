# -*- coding:utf-8 -*-

"""
 Licensed to the Apache Software Foundation (ASF) under one or more
 contributor license agreements.  See the NOTICE file distributed with
 this work for additional information regarding copyright ownership.
 The ASF licenses this file to You under the Apache License, Version 2.0
 (the "License"); you may not use this file except in compliance with
 the License.  You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 """
from django.forms import model_to_dict
from networkapi.ambiente.models import EnvironmentVip
from networkapi.equipamento.models import Equipamento

from networkapi.requisicaovips.models import RequisicaoVips, VipPortToPool
from networkapi.util import is_valid_int_greater_zero_param, convert_boolean_to_int, mount_ipv4_string, \
    mount_ipv6_string
from networkapi.api_vip_request import exceptions
from networkapi.api_rest import exceptions as api_exceptions


def get_by_pk(pk):
    """
    Get Vip Request By Pk

    :param pk: Identifier For Vip Request

    :return: Dict

    """

    if not is_valid_int_greater_zero_param(pk):
        raise exceptions.InvalidIdVipRequestException()

    vip_request = RequisicaoVips.objects.get(id=pk)

    data = vip_request.variables_to_map()

    pools = []

    vip_to_ports_query = VipPortToPool.objects.filter(requisicao_vip=vip_request)

    for vip_port in vip_to_ports_query:

        pools_members = []

        server_pool = vip_port.server_pool
        pool_raw = model_to_dict(server_pool)
        pool_raw["port_vip"] = vip_port.port_vip
        pool_raw["port_vip_id"] = vip_port.id

        for pool_member in server_pool.serverpoolmember_set.all():

            pools_member_raw = model_to_dict(pool_member)

            ipv4 = pool_member.ip
            ipv6 = pool_member.ipv6
            ip_equipment_set = ipv4 and ipv4.ipequipamento_set or ipv6 and ipv6.ipv6equipament_set
            ip_equipment_obj = ip_equipment_set.select_related().uniqueResult()

            healthcheck_type = pool_member.healthcheck and pool_member.healthcheck.healthcheck_type

            pools_member_raw['healthcheck'] = {'healthcheck_type': healthcheck_type}
            pools_member_raw['equipment_name'] = ip_equipment_obj.equipamento.nome

            ip_formated = ip_equipment_obj.ip.ip_formated

            if ipv4:
                pools_member_raw["ip"] = {'ip_formated': ip_formated}
            else:
                pools_member_raw["ipv6"] = {'ip_formated': ip_formated}

            pools_members.append(pools_member_raw)

        pool_raw['server_pool_members'] = pools_members

        pools.append(pool_raw)

    data["pools"] = pools

    vip_port_list, reals_list, reals_priority, reals_weight = get_vips_and_reals(
        vip_request.id,
    )

    if reals_list:
        data['reals'] = {'real': reals_list}
        data['reals_prioritys'] = {'reals_priority': reals_priority}
        data['reals_weights'] = {'reals_weight': reals_weight}

    data['portas_servicos'] = vip_port_list
    data['id'] = vip_request.id
    data['validado'] = convert_boolean_to_int(vip_request.validado)
    data['vip_criado'] = convert_boolean_to_int(vip_request.vip_criado)
    data['id_ip'] = vip_request.ip_id
    data['id_ipv6'] = vip_request.ipv6_id
    data['id_healthcheck_expect'] = vip_request.healthcheck_expect_id
    data['l7_filter'] = vip_request.l7_filter
    data['rule_id'] = vip_request.rule_id

    return data


def validate_reals(data):
    """
    Validate Reals to save/update
    :param data: Reals
    :return:
    """

    reals_data = data.get('reals')

    if reals_data is not None:

        finality = data.get('finalidade')
        client = data.get('cliente')
        environment = data.get('ambiente')

        environment_vip = EnvironmentVip.get_by_values(
            finality,
            client,
            environment
        )

        for real in reals_data.get('real'):

            real_ip = real.get('real_ip')
            real_name = real.get('real_name')

            if real_name:
                equip = Equipamento.get_by_name(real_name)
            else:
                message = u'The real_name parameter is not a valid value'
                raise api_exceptions.ValidationException(message)

            RequisicaoVips.valid_real_server(real_ip, equip, environment_vip, False)


def set_l7_filter_for_vip(obj_req_vip):

    if obj_req_vip.rule:
        obj_req_vip.l7_filter = '\n'.join(
            obj_req_vip.rule.rulecontent_set.all().values_list(
                'content',
                flat=True
            )
        )


def get_vips_and_reals(id_vip, omit_port_real=False):

    vip_ports = VipPortToPool.get_by_vip_id(id_vip)

    vip_port_list = list()
    reals_list = list()
    reals_priority = list()
    reals_weight = list()

    for v_port in vip_ports:
        full_port = str(v_port.port_vip)

        if not omit_port_real:
            full_port += ':' + str(v_port.server_pool.default_port)

        if full_port not in vip_port_list:
            vip_port_list.append({'porta': full_port, 'vip_port_id': v_port.id })

        members = v_port.server_pool.serverpoolmember_set.all()

        for member in members:
            try:
                ip_equip = member.ip.ipequipamento_set.all().uniqueResult()
                equip_name = ip_equip.equipamento.nome
                ip_string = mount_ipv4_string(member.ip)
                ip_id = member.ip.id
            except:
                ip_equip = member.ipv6.ipv6equipament_set.all().uniqueResult()
                equip_name = ip_equip.equipamento.nome
                ip_string = mount_ipv6_string(member.ipv6)
                ip_id = member.ipv6.id

            real_raw = {
                'real_ip': ip_string,
                'real_name': equip_name,
                'port_vip': v_port.port_vip,
                'port_real': member.port_real,
                'id_ip': ip_id
            }

            if real_raw not in reals_list:
                reals_list.append(real_raw)

            reals_priority.append(member.priority)
            reals_weight.append(member.weight)

    return vip_port_list, reals_list, reals_priority, reals_weight