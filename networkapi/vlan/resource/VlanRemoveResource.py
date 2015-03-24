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
from networkapi.grupo.models import GrupoError
from networkapi.infrastructure.xml_utils import dumps_networkapi, XMLError
from networkapi.log import Log
from networkapi.queue_tools import queue_keys
from networkapi.queue_tools.queue_manager import QueueManager
from networkapi.rest import RestResource
from networkapi.util import is_valid_int_greater_zero_param
from networkapi.vlan.models import Vlan, VlanError, VlanNotFoundError, \
    VlanInactiveError, VlanNetworkError
from networkapi.exception import InvalidValueError
from networkapi.infrastructure.script_utils import exec_script, ScriptError
from networkapi import settings, error_message_utils
from networkapi.distributedlock import distributedlock, LOCK_VLAN
from networkapi.equipamento.models import Equipamento
from networkapi.error_message_utils import error_messages


class VlanRemoveResource(RestResource):

    log = Log('VlanRemoveResource')

    def handle_delete(self, request, user, *args, **kwargs):
        """Handles DELETE requests to remove VLAN by ID.

        URLs: /vlan/<id_vlan>/remove/
        """

        self.log.info('Remove VLAN by ID')
        CODE_MESSAGE_VLAN_ERROR = 369

        try:

            # Commons Validations

            # User permission
            if not has_perm(user, AdminPermission.VLAN_MANAGEMENT, AdminPermission.WRITE_OPERATION):
                self.log.error(
                    u'User does not have permission to perform the operation.')
                return self.not_authorized()

            # Business Validations

            # Load URL param
            vlan_id = kwargs.get('id_vlan')

            # Valid VLAN ID
            if not is_valid_int_greater_zero_param(vlan_id):
                self.log.error(
                    u'Parameter id_vlan is invalid. Value: %s.', vlan_id)
                raise InvalidValueError(None, 'id_vlan', vlan_id)

            # Existing VLAN ID
            vlan = Vlan().get_by_pk(vlan_id)

            # Check permission group equipments
            equips_from_ipv4 = Equipamento.objects.filter(
                ipequipamento__ip__networkipv4__vlan=vlan_id, equipamentoambiente__is_router=1)
            equips_from_ipv6 = Equipamento.objects.filter(
                ipv6equipament__ip__networkipv6__vlan=vlan_id, equipamentoambiente__is_router=1)
            for equip in equips_from_ipv4:
                # User permission
                if not has_perm(user, AdminPermission.EQUIPMENT_MANAGEMENT, AdminPermission.WRITE_OPERATION, None, equip.id, AdminPermission.EQUIP_WRITE_OPERATION):
                    self.log.error(
                        u'User does not have permission to perform the operation.')
                    return self.not_authorized()
            for equip in equips_from_ipv6:
                # User permission
                if not has_perm(user, AdminPermission.EQUIPMENT_MANAGEMENT, AdminPermission.WRITE_OPERATION, None, equip.id, AdminPermission.EQUIP_WRITE_OPERATION):
                    self.log.error(
                        u'User does not have permission to perform the operation.')
                    return self.not_authorized()

            networks_ipv4_ids = []
            networks_ipv6_ids = []

            with distributedlock(LOCK_VLAN % vlan_id):

                # Business Rules

                if vlan.ativada:
                    network_errors = []

                    for net4 in vlan.networkipv4_set.all():

                        network_to_queue = dict(id=net4.id, ip=net4.ip_formated)
                        networks_ipv4_ids.append(network_to_queue)

                        if net4.active:
                            try:
                                command = settings.NETWORKIPV4_REMOVE % int(net4.id)

                                code, stdout, stderr = exec_script(command)
                                if code == 0:
                                    net4.deactivate(user, True)
                                else:
                                    network_errors.append(str(net4.id))
                            except Exception, e:
                                network_errors.append(str(net4.id))
                                pass

                    for net6 in vlan.networkipv6_set.all():

                        network_to_queue = dict(id=net6.id, ip=net6.ip_formated)
                        networks_ipv6_ids.append(network_to_queue)

                        if net6.active:
                            try:
                                command = settings.NETWORKIPV6_REMOVE % int(net6.id)
                                code, stdout, stderr = exec_script(command)
                                if code == 0:
                                    net6.deactivate(user, True)
                                else:
                                    network_errors.append(str(net6.id))
                            except Exception, e:
                                network_errors.append(str(net6.id))
                                pass

                    if network_errors:
                        raise VlanNetworkError(
                            None, message=', '.join(network_errors))

                else:
                    raise VlanInactiveError(
                        None, 'Cant remove vlan because its inactive.')

                # Execute script
                vlan_id = vlan.id
                environment_id = vlan.ambiente.id

                # navlan -i <ID_REQUISICAO> --remove
                command = settings.VLAN_REMOVE % vlan_id
                code, stdout, stderr = exec_script(command)

                # Return XML
                if code == 0:
                    success_map = dict()
                    success_map['codigo'] = '%04d' % code
                    success_map['descricao'] = {
                        'stdout': stdout, 'stderr': stderr}

                    map = dict()
                    map['sucesso'] = success_map
                    vlan.remove(user)

                    # Send to Queue
                    queue_manager = QueueManager()

                    obj_to_queue = dict(
                        id_vlan=vlan_id,
                        id_environemnt=environment_id,
                        networks_ipv4=networks_ipv4_ids,
                        networks_ipv6=networks_ipv6_ids,
                        description=queue_keys.VLAN_REMOVE
                    )

                    queue_manager.append(obj_to_queue)
                    queue_manager.send()

                    return self.response(dumps_networkapi(map))
                else:
                    return self.response_error(2, stdout + stderr)

        except InvalidValueError, e:
            return self.response_error(269, e.param, e.value)
        except XMLError, x:
            self.log.error(u'Error reading the XML request.')
            return self.response_error(3, x)
        except VlanNotFoundError, e:
            return self.response_error(116)
        except ScriptError, s:
            return self.response_error(2, s)
        except GrupoError:
            return self.response_error(1)
        except VlanInactiveError, e:
            return self.response_error(368)
        except VlanNetworkError, e:
            return self.response_error(CODE_MESSAGE_VLAN_ERROR, e.message)
        except VlanError, e:
            return self.response_error(1)
