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

from __future__ import with_statement
from networkapi.admin_permission import AdminPermission
from networkapi.auth import has_perm
from networkapi.equipamento.models import TipoEquipamento, EquipamentoAmbiente
from networkapi.exception import InvalidValueError, BreakLoops
from networkapi.filterequiptype.models import FilterEquipType
from networkapi.infrastructure.xml_utils import dumps_networkapi, loads
from networkapi.ip.models import NetworkIPv4, NetworkIPv4AddressNotAvailableError, NetworkIPRangeEnvError, NetworkIPv6, \
    NetworkIPv6AddressNotAvailableError
from networkapi.log import Log
from networkapi.rest import RestResource, UserNotAuthorizedError
from networkapi.util import is_valid_int_greater_zero_param, is_valid_version_ip
from networkapi.vlan.models import VlanError, Vlan, VlanNotFoundError
from networkapi.ambiente.models import IP_VERSION, AmbienteNotFoundError
from networkapi.distributedlock import distributedlock, LOCK_VLAN
from networkapi.ambiente.models import Ambiente
from string import split
from networkapi.infrastructure.ipaddr import IPNetwork, IPv4Network, IPv6Network


class VlanValidateResource(RestResource):

    log = Log('VlanValidateResource')

    def handle_put(self, request, user, *args, **kwargs):
        '''Treat PUT requests to Validate a vlan

        URL: vlan/<id_vlan>/validate/<network>
        '''

        try:

            id_vlan = kwargs.get('id_vlan')

            network = kwargs.get('network')

            # User permission
            if not has_perm(user, AdminPermission.ACL_VLAN_VALIDATION, AdminPermission.WRITE_OPERATION):
                self.log.error(
                    u'User does not have permission to perform the operation.')
                raise UserNotAuthorizedError(None)

            # Valid Vlan ID
            if not is_valid_int_greater_zero_param(id_vlan):
                self.log.error(
                    u'The id_vlan parameter is not a valid value: %s.', id_vlan)
                raise InvalidValueError(None, 'vlan_id', id_vlan)

            # Valid Network
            if not is_valid_version_ip(network, IP_VERSION):
                self.log.error(
                    u'The network parameter is not a valid value: %s.', network)
                raise InvalidValueError(None, 'network', network)

            # Find Vlan by ID to check if it exist
            vlan = Vlan().get_by_pk(id_vlan)

            with distributedlock(LOCK_VLAN % id_vlan):

                # Set Values
                if network == IP_VERSION.IPv4[0]:
                    vlan.acl_valida = 1

                else:
                    vlan.acl_valida_v6 = 1

                vlan.save(user)

                return self.response(dumps_networkapi({}))

        except InvalidValueError, e:
            return self.response_error(269, e.param, e.value)

        except UserNotAuthorizedError:
            return self.not_authorized()

        except VlanNotFoundError, e:
            return self.response_error(116)

        except VlanError, e:
            return self.response_error(1)

    def handle_get(self, request, user, *args, **kwargs):
        '''Treat GET requests to check if a vlan need confimation to insert

        URL: vlan/confirm/
        '''

        try:
            # Get XML data
            ip_version = kwargs.get('ip_version')

            if ip_version == 'None':
                is_number = True
                number = str(kwargs.get('number'))
                id_environment = kwargs.get('id_environment')
            else:
                is_number = False
                network = kwargs.get('number')
                network = str(network.replace('net_replace', '/'))
                id_vlan = kwargs.get('id_environment')
                if ip_version == '1':
                    version = 'v6'
                else:
                    version = 'v4'

            # User permission
            if not has_perm(user, AdminPermission.VLAN_MANAGEMENT, AdminPermission.WRITE_OPERATION):
                self.log.error(
                    u'User does not have permission to perform the operation.')
                return self.not_authorized()

            if is_number:

                # Valid number
                if not is_valid_int_greater_zero_param(number):
                    self.log.error(u'Parameter number is invalid. Value: %s.', number)
                    raise InvalidValueError(None, 'number', number)

                # Valid id_environment
                if not is_valid_int_greater_zero_param(id_environment):
                    self.log.error(u'Parameter id_environment is invalid. Value: %s.', id_environment)
                    raise InvalidValueError(None, 'id_environment', id_environment)

                ambiente = Ambiente.get_by_pk(id_environment)

                equips = list()
                envs = list()
                envs_aux = list()

                for env in ambiente.equipamentoambiente_set.all():
                    equips.append(env.equipamento)

                for equip in equips:
                    for env in equip.equipamentoambiente_set.all():
                        if not env.ambiente_id in envs_aux:
                            envs.append(env.ambiente)
                            envs_aux.append(env.ambiente_id)

                # Valid number
                map = dict()
                map['needs_confirmation'] = True

                try:
                    for env in envs:
                        for vlan in env.vlan_set.all():
                            if int(vlan.num_vlan) == int(number):
                                if ambiente.filter_id == None or vlan.ambiente.filter_id == None or int(vlan.ambiente.filter_id) != int(ambiente.filter_id):
                                    map['needs_confirmation'] = False
                                else:
                                    raise BreakLoops()
                except BreakLoops, e:
                    map['needs_confirmation'] = True

            else:
                # Valid id_vlan
                if not is_valid_int_greater_zero_param(id_vlan):
                    self.log.error(u'Parameter id_vlan is invalid. Value: %s.', id_vlan)
                    raise InvalidValueError(None, 'id_vlan', id_vlan)

                # Valid network
                try:
                    network_ip_verify = IPNetwork(network)
                except ValueError, e:
                    raise InvalidValueError(None, 'network', network)

                # Get all vlans environments from equipments of the current
                vlan = Vlan()
                vlan = vlan.get_by_pk(id_vlan)

                # environment
                ambiente = vlan.ambiente

                error = False

                # Inicio - Validação adicional pesente em NetworkAddResource

                expl = split(network_ip_verify.network.exploded, "." if version == IP_VERSION.IPv4[0] else ":")
                expl.append(str(network_ip_verify.prefixlen))

                if version == IP_VERSION.IPv4[0]:

                    try:
                        # Find all networks related to environment
                        nets = NetworkIPv4.objects.select_related().filter(
                            vlan__ambiente__id=vlan.ambiente.id)

                        # Cast to API class
                        networks = set([IPv4Network('%d.%d.%d.%d/%d' % (net_ip.oct1, net_ip.oct2, net_ip.oct3,
                                                                        net_ip.oct4, net_ip.block))
                                        for net_ip in nets])

                        # If network selected not in use
                        if network_ip_verify in networks:
                            raise NetworkIPv4AddressNotAvailableError(
                                None, u'Unavailable address to create a NetworkIPv4.')

                        # TODO: NÃO RESCEBO AMBIENTE VIP NESTA VALIDAÇÃO (Remover?)
                        '''
                        if env_vip is not None:

                            # Find all networks related to environment vip
                            nets = NetworkIPv4.objects.select_related().filter(
                                ambient_vip__id=env_vip.id)

                            # Cast to API class
                            networks = set([IPv4Network('%d.%d.%d.%d/%d' % (net_ip.oct1, net_ip.oct2, net_ip.oct3,
                                                                            net_ip.oct4, net_ip.block))
                                            for net_ip in nets])

                            # If there is already a network with the same  range ip as
                            # related the environment  vip
                            if net in networks:
                                raise NetworkIpAddressNotAvailableError(
                                    None, u'Unavailable address to create a NetworkIPv4.')
                        '''

                        # Filter case 1 - Adding new network with same ip range to another network on other environment
                        # Get environments with networks with the same ip range
                        nets = NetworkIPv4.objects.filter(oct1=expl[0], oct2=expl[1], oct3=expl[2], oct4=expl[3],
                                                          block=expl[4])
                        env_ids = list()
                        for net_ip in nets:
                            env_ids.append(net_ip.vlan.ambiente.id)

                        # If other network with same ip range exists
                        if len(env_ids) > 0:

                            # Get equipments related to this network's environment
                            env_equips = EquipamentoAmbiente.objects.filter(
                                ambiente=vlan.ambiente.id)

                            # Verify equipments related with all other environments
                            # that contains networks with same ip range
                            for env_id in env_ids:
                                # Equipments related to other environments
                                other_env_equips = EquipamentoAmbiente.objects.filter(
                                    ambiente=env_id)
                                # Adjust to equipments
                                equip_list = list()
                                for equip_env in other_env_equips:
                                    equip_list.append(equip_env.equipamento.id)

                                for env_equip in env_equips:
                                    if env_equip.equipamento.id in equip_list:

                                        # Filter testing
                                        if other_env_equips[0].ambiente.filter is None or vlan.ambiente.filter is None:
                                            raise NetworkIPRangeEnvError(
                                                None, u'Um dos equipamentos associados com o ambiente desta rede também está associado com outro ambiente que tem uma rede com essa mesma faixa, adicione filtros nos ambientes se necessário.')
                                        else:
                                            # Test both environment's filters
                                            tp_equip_list_one = list()
                                            for fet in FilterEquipType.objects.filter(filter=vlan.ambiente.filter.id):
                                                tp_equip_list_one.append(fet.equiptype)

                                            tp_equip_list_two = list()
                                            for fet in FilterEquipType.objects.filter(filter=other_env_equips[0].ambiente.filter.id):
                                                tp_equip_list_two.append(fet.equiptype)

                                            if env_equip.equipamento.tipo_equipamento not in tp_equip_list_one or env_equip.equipamento.tipo_equipamento not in tp_equip_list_two:
                                                raise NetworkIPRangeEnvError(
                                                    None, u'Um dos equipamentos associados com o ambiente desta rede também está associado com outro ambiente que tem uma rede com essa mesma faixa, adicione filtros nos ambientes se necessário.')
                    except NetworkIPv4AddressNotAvailableError, e:
                        self.log.debug(e.message)
                        error = True
                    except NetworkIPRangeEnvError, e:
                        self.log.debug(e.message)
                        error = True
                else:

                    try:
                        # Find all networks ralated to environment
                        nets = NetworkIPv6.objects.select_related().filter(vlan__ambiente__id=vlan.ambiente.id)

                        # Cast to API class
                        networks = set([IPv6Network('%s:%s:%s:%s:%s:%s:%s:%s/%d' % (net_ip.block1, net_ip.block2,
                                                                                    net_ip.block3, net_ip.block4,
                                                                                    net_ip.block5, net_ip.block6,
                                                                                    net_ip.block7, net_ip.block8,
                                                                                    net_ip.block)) for net_ip in nets])

                        # If network selected not in use
                        if network_ip_verify in networks:
                            raise NetworkIPv6AddressNotAvailableError(
                                None, u'Unavailable address to create a NetworkIPv6.')

                        # TODO: NÃO RESCEBO AMBIENTE VIP NESTA VALIDAÇÃO (Remover?)
                        '''
                        if env_vip is not None:

                            # Find all networks related to environment vip
                            nets = NetworkIPv6.objects.select_related().filter(
                                ambient_vip__id=env_vip.id)

                            # Cast to API class
                            networks = set([IPv6Network('%s:%s:%s:%s:%s:%s:%s:%s/%d' % (net_ip.block1, net_ip.block2,
                                                                                        net_ip.block3, net_ip.block4,
                                                                                        net_ip.block5, net_ip.block6,
                                                                                        net_ip.block7, net_ip.block8,
                                                                                        net_ip.block))
                                            for net_ip in nets])

                            # If there is already a network with the same  range ip as
                            # related the environment  vip
                            if net in networks:
                                raise NetworkIpAddressNotAvailableError(
                                    None, u'Unavailable address to create a NetworkIPv6.')
                        '''

                        # Filter case 1 - Adding new network with same ip range to another network on other environment
                        # Get environments with networks with the same ip range
                        nets = NetworkIPv6.objects.filter(block1=expl[0], block2=expl[1], block3=expl[2],
                                                          block4=expl[3], block5=expl[4], block6=expl[5],
                                                          block7=expl[6], block8=expl[7], block=expl[8])
                        env_ids = list()
                        for net_ip in nets:
                            env_ids.append(net_ip.vlan.ambiente.id)

                        # If other network with same ip range exists
                        if len(env_ids) > 0:

                            # Get equipments related to this network's environment
                            env_equips = EquipamentoAmbiente.objects.filter(
                                ambiente=vlan.ambiente.id)

                            # Verify equipments related with all other environments
                            # that contains networks with same ip range
                            for env_id in env_ids:
                                # Equipments related to other environments
                                other_env_equips = EquipamentoAmbiente.objects.filter(
                                    ambiente=env_id)
                                # Adjust to equipments
                                equip_list = list()
                                for equip_env in other_env_equips:
                                    equip_list.append(equip_env.equipamento.id)

                                for env_equip in env_equips:
                                    if env_equip.equipamento.id in equip_list:

                                        # Filter testing
                                        if other_env_equips[0].ambiente.filter is None or vlan.ambiente.filter is None:
                                            raise NetworkIPRangeEnvError(
                                                None, u'Um dos equipamentos associados com o ambiente desta rede também está associado com outro ambiente que tem uma rede com essa mesma faixa, adicione filtros nos ambientes se necessário.')
                                        else:
                                            # Test both environment's filters
                                            tp_equip_list_one = list()
                                            for fet in FilterEquipType.objects.filter(filter=vlan.ambiente.filter.id):
                                                tp_equip_list_one.append(fet.equiptype)

                                            tp_equip_list_two = list()
                                            for fet in FilterEquipType.objects.filter(filter=other_env_equips[0].ambiente.filter.id):
                                                tp_equip_list_two.append(fet.equiptype)

                                            if env_equip.equipamento.tipo_equipamento not in tp_equip_list_one or env_equip.equipamento.tipo_equipamento not in tp_equip_list_two:
                                                raise NetworkIPRangeEnvError(
                                                    None, u'Um dos equipamentos associados com o ambiente desta rede também está associado com outro ambiente que tem uma rede com essa mesma faixa, adicione filtros nos ambientes se necessário.')
                    except NetworkIPv6AddressNotAvailableError, e:
                        self.log.debug(e.message)
                        error = True
                    except NetworkIPRangeEnvError, e:
                        self.log.debug(e.message)
                        error = True
                # Fim - Validação adicional pesente em NetworkAddResource

                # Return map variable
                map = dict()
                map['needs_confirmation'] = False

                if not error:

                    equipment_types = TipoEquipamento.objects.filter(filterequiptype__filter=ambiente.filter)

                    equips = list()
                    envs = list()
                    #Get all equipments from the environment being tested
                    #that are not supposed to be filtered
                    #(not the same type of the equipment type of a filter of the environment)
                    for env in vlan.ambiente.equipamentoambiente_set.all().exclude(
                            equipamento__tipo_equipamento__in=equipment_types):
                        equips.append(env.equipamento)

                    envs_aux = list()
                    #Get all environment that the equipments above are included
                    for equip in equips:
                        for env in equip.equipamentoambiente_set.all():
                            if not env.ambiente_id in envs_aux:
                                envs.append(env.ambiente)
                                envs_aux.append(env.ambiente_id)

                    try:
                        #Check in all vlans from all environments above
                        #if there is a network that is sub or super network of the current
                        #network being tested
                        for env in envs:
                            for vlan_obj in env.vlan_set.all():
                                is_subnet = verify_subnet(vlan_obj, network_ip_verify, version)
                                if is_subnet:
                                    raise BreakLoops()
                    except BreakLoops, e:
                        map['needs_confirmation'] = True

                else:
                    map['needs_confirmation'] = True

            # Return XML
            return self.response(dumps_networkapi(map))

        except InvalidValueError, e:
            self.log.error(e)
            return self.response_error(269, e.param, e.value)
        except AmbienteNotFoundError:
            self.log.error(e)
            return self.response_error(112)
        except Exception, e:
            self.log.error(e)
            return self.response_error(1)


def verify_subnet(vlan, network, version):

    from networkapi.infrastructure.ipaddr import IPNetwork

    if version == IP_VERSION.IPv4[0]:
        vlan_net = vlan.networkipv4_set.all()
    else:
        vlan_net = vlan.networkipv6_set.all()

    # One vlan may have many networks, iterate over it
    for net in vlan_net:
        if version == IP_VERSION.IPv4[0]:
            ip = "%s.%s.%s.%s/%s" % (net.oct1,
                                     net.oct2, net.oct3, net.oct4, net.block)
        else:
            ip = "%s:%s:%s:%s:%s:%s:%s:%s/%d" % (net.block1, net.block2, net.block3,
                                                 net.block4, net.block5, net.block6, net.block7, net.block8, net.block)

        ip_net = IPNetwork(ip)
        # If some network, inside this vlan, is subnet of network search param
        if ip_net in network or network in ip_net:
            # This vlan must be in vlans founded, don't need to continue
            # checking
            return True

    # If don't found any subnet return False
    return False
