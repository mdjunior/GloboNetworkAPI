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


from networkapi.rest import RestResource
from networkapi.auth import has_perm
from networkapi.admin_permission import AdminPermission
from networkapi.infrastructure.xml_utils import XMLError, dumps_networkapi
from networkapi.log import Log
from networkapi.grupo.models import GrupoError
from networkapi.equipamento.models import EquipamentoAccessNotFoundError, EquipamentoError
from networkapi.exception import InvalidValueError
from networkapi.util import is_valid_int_greater_zero_param
from django.forms.models import model_to_dict
from networkapi.equipamento.models import EquipamentoAcesso


class EquipAccessGetResource(RestResource):

    log = Log('EquipAccessGetResource')

    def handle_get(self, request, user, *args, **kwargs):
        """Handles GET requests to list all equip access by access identifier.

        URLs: equipamentoacesso/id/<id_acesso>/
        """

        try:

            # Commons Validations

            # User permission
            if not has_perm(user, AdminPermission.EQUIPMENT_MANAGEMENT, AdminPermission.READ_OPERATION):
                self.log.error(
                    u'User does not have permission to perform the operation.')
                return self.not_authorized()

            # Business Validations

            # Valid id access
            id_access = kwargs.get('id_acesso')

            if not is_valid_int_greater_zero_param(id_access):
                self.log.error(
                    u'Parameter id_acesso is invalid. Value: %s.', id_access)
                raise InvalidValueError(None, 'id_acesso', id_access)

            # Business Rules

            access = EquipamentoAcesso.get_by_pk(id_access)

            equip_access_map = dict()
            equip_access_map['equipamento_acesso'] = model_to_dict(access)

            # Return XML
            return self.response(dumps_networkapi(equip_access_map))

        except InvalidValueError, e:
            return self.response_error(269, e.param, e.value)
        except EquipamentoAccessNotFoundError, e:
            return self.response_error(303)
        except (EquipamentoError, GrupoError):
            return self.response_error(1)
        except XMLError, x:
            self.log.error(u'Error reading the XML request.')
            return self.response_error(3, x)
