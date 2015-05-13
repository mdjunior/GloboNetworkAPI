# -*- coding:utf-8 -*-

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from networkapi.api_pools import exceptions
from networkapi.healthcheckexpect.models import Healthcheck
from networkapi.infrastructure.script_utils import exec_script, ScriptError
from networkapi.ip.models import Ipv6, Ip
from networkapi.requisicaovips.models import ServerPoolMember, ServerPool
from networkapi.util import is_valid_int_greater_zero_param, is_valid_list_int_greater_zero_param

def get_or_create_healthcheck(user, healthcheck_expect, healthcheck_type, healthcheck_request):
    try:
        # Query HealthCheck table for one equal this
        hc = Healthcheck.objects.get(healthcheck_expect=healthcheck_expect, healthcheck_type=healthcheck_type,
                                     healthcheck_request=healthcheck_request)
    # Else, add a new one
    except ObjectDoesNotExist:
        hc = Healthcheck(identifier='', healthcheck_type=healthcheck_type, healthcheck_request=healthcheck_request,
                         healthcheck_expect=healthcheck_expect, destination='')
        hc.save(user)

    return hc


def save_server_pool(user, id, identifier, default_port, hc, env, balancing, maxcom, id_pool_member):
    # Save Server pool
    old_healthcheck_id = None

    if id:
        sp = ServerPool.objects.get(id=id)

        # storage old healthcheck id
        old_healthcheck_id = sp.healthcheck_id

        #valid change environment
        if sp.environment and sp.environment.id != env.id:
            del_smp = sp.serverpoolmember_set.exclude(id__in=id_pool_member)
            vip = sp.vipporttopool_set.count()
            if vip > 0:
                raise exceptions.UpdateEnvironmentVIPException()

            if len(del_smp) > 0:
                raise exceptions.UpdateEnvironmentServerPoolMemberException()

        sp.default_port = default_port
        sp.healthcheck = hc
        sp.lb_method = balancing
        sp.identifier = identifier
        sp.environment = env
        sp.default_limit = maxcom
    else:
        sp = ServerPool(identifier=identifier, default_port=default_port, healthcheck=hc,
                        environment=env, pool_created=False, lb_method=balancing, default_limit=maxcom)
    sp.save(user)

    return sp, old_healthcheck_id


def prepare_to_save_reals(ip_list_full, ports_reals, nome_equips, priorities, weight, id_pool_member, id_equips):

    list_server_pool_member = list()

    if id_pool_member:

        invalid_ports_real = [i for i in ports_reals if int(i) > 65535 or int(i) < 1]
        invalid_priority = [i for i in priorities if int(i) > 4294967295 or int(i) < 0]

        if invalid_priority:
            raise exceptions.InvalidRealPoolException('O valor da Prioridade deve estar entre 0 e 4294967295.')

        if invalid_ports_real:
            raise exceptions.InvalidRealPoolException('O número da porta deve estar entre 1 e 65535.')

        if len(id_equips) != len(id_pool_member):
            raise exceptions.InvalidRealPoolException('Quantidade de portas e equipamento difere.')

        for i in range(0, len(ip_list_full)):
            for j in range(0, len(ip_list_full)):
                if i == j:
                    pass
                elif ports_reals[i] == ports_reals[j] and ip_list_full[i].get('id', '') == ip_list_full[j].get('id', ''):
                    raise exceptions.InvalidRealPoolException('Ips com portas iguais.')

        for i in range(0, len(id_pool_member)):
            list_server_pool_member.append({'id': ip_list_full[i].get('id', '') if ip_list_full[i] else '',
                                            'ip': ip_list_full[i].get('ip', '') if ip_list_full[i] else '',
                                            'port_real': ports_reals[i],
                                            'nome_equips': nome_equips[i],
                                            'priority': priorities[i],
                                            'weight': weight[i],
                                            'id_pool_member': id_pool_member[i],
                                          })
    return list_server_pool_member


def save_server_pool_member(user, sp, list_server_pool_member):

    list_pool_member = list()
    # Remove empty values from list
    id_pool_member_noempty = [x['id_pool_member'] for x in list_server_pool_member if x['id_pool_member'] != '']

    #exclue server pool member
    del_smp = sp.serverpoolmember_set.exclude(id__in=id_pool_member_noempty)
    if del_smp:
        for obj in del_smp:

            #execute script remove real
            command = settings.POOL_REAL_REMOVE % (obj.server_pool_id, obj.ip_id if obj.ip else obj.ipv6_id, obj.port_real)
            code, _, _ = exec_script(command)
            if code != 0:
                raise exceptions.ScriptCreatePoolException()

            obj.delete(user)

    if list_server_pool_member:
        for dic in list_server_pool_member:

            ip_object = None
            ipv6_object = None
            if len(dic['ip']) <= 15:
                ip_object = Ip.get_by_pk(dic['id'])

                if sp.environment.divisao_dc.id != ip_object.networkipv4.vlan.ambiente.divisao_dc.id \
                        or sp.environment.ambiente_logico.id != ip_object.networkipv4.vlan.ambiente.ambiente_logico.id:
                    raise exceptions.IpNotFoundByEnvironment()

            else:
                ipv6_object = Ipv6.get_by_pk(dic['id'])

                if sp.environment.divisao_dc.id != ipv6_object.networkipv6.vlan.ambiente.divisao_dc.id \
                        or sp.environment.ambiente_logico.id != ipv6_object.networkipv6.vlan.ambiente.ambiente_logico.id:
                    raise exceptions.IpNotFoundByEnvironment()

            id_pool = sp.id
            id_ip = ip_object and ip_object.id or ipv6_object and ipv6_object.id
            port_ip = dic['port_real']

            if dic['id_pool_member']:
                spm = ServerPoolMember.objects.get(id=dic['id_pool_member'])
                spm.server_pool = sp
                spm.identifier = dic['nome_equips']
                spm.ip = ip_object
                spm.ipv6 = ipv6_object
                spm.priority = dic['priority']
                spm.weight = dic['weight']
                spm.limit = sp.default_limit
                spm.port_real = dic['port_real']

                #execute script remove real
                command = settings.POOL_REAL_REMOVE % (id_pool, id_ip, port_ip)
                code, _, _ = exec_script(command)
                if code != 0:
                    raise exceptions.ScriptCreatePoolException()

            else:
                spm = ServerPoolMember(server_pool=sp, identifier=dic['nome_equips'], ip=ip_object, ipv6=ipv6_object,
                                       priority=dic['priority'], weight=dic['weight'], limit=sp.default_limit,
                                       port_real=dic['port_real'])

            if sp.healthcheck_id:
                spm.healthcheck = sp.healthcheck

            spm.save(user)

            #execute script create real
            command = settings.POOL_REAL_CREATE % (id_pool, id_ip, port_ip)
            code, _, _ = exec_script(command)
            if code != 0:
                raise exceptions.ScriptCreatePoolException()

            list_pool_member.append(spm)

    return list_pool_member


def exec_script_check_poolmember_by_pool(pool_id):

    #execute script check status real
    command = settings.POOL_REAL_CHECK_BY_POOL % (pool_id)
    status_code, stdout, stderr = exec_script(command)

    if status_code != 0:
        raise exceptions.ScriptCheckStatusPoolMemberException()

    return stdout


def manager_pools(request):
    """
    Manager Status Pool Members Enable/Disabled By Pool

    :param request: HttpRequest

    """

    try:
        pool_id = request.DATA.get("server_pool_id")
        pool_members = request.DATA.get("server_pool_members", [])

        # List to validate pool member status
        valid_status = [0, 1, False, True]

        pool_members_id = [member.get('id') for member in pool_members]

        if not is_valid_int_greater_zero_param(pool_id):
            raise exceptions.InvalidIdPoolException()

        #Validate pool members id
        is_valid_list_int_greater_zero_param(pool_members_id)

        pool_obj = ServerPool.objects.get(id=pool_id)

        related_pool_members = pool_obj.serverpoolmember_set.order_by('id')

        received_pool_members = ServerPoolMember.objects.filter(id__in=pool_members_id).order_by('id')

        relates = list(related_pool_members)
        receives = list(received_pool_members)

        if relates != receives:
            raise exceptions.InvalidIdPoolMemberException(u'Required All Pool Members By Pool')

        for member in pool_members:

            member_id = member.get("id")
            member_status = member.get("status")

            if member_status not in valid_status:
                raise exceptions.InvalidStatusPoolMemberException()

            server_pool_member = ServerPoolMember.objects.get(id=member_id)
            server_pool_member.status = member_status

            server_pool_member.save(request.user, commit=True)

        #Execute Script To Set Status
        command = settings.POOL_MANAGEMENT_MEMBERS_STATUS % pool_id
        code, _, _ = exec_script(command)
        if code != 0:
            raise exceptions.ScriptManagementPoolException()

    except (exceptions.ScriptManagementPoolException, ScriptError), exception:

        # Rollback
        for old_member in related_pool_members:
            old_member.save(request.user, commit=True)

        raise exception
