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

from rest_framework import serializers
from networkapi.ambiente.models import Ambiente
from networkapi.infrastructure.script_utils import exec_script
from networkapi.ip.models import Ip, Ipv6, NetworkIPv4, NetworkIPv6
from networkapi.requisicaovips.models import ServerPool, ServerPoolMember, VipPortToPool
from networkapi.healthcheckexpect.models import Healthcheck
from networkapi.equipamento.models import Equipamento
from networkapi.api_pools.models import OpcaoPoolAmbiente, OpcaoPool
from networkapi.settings import POOL_REAL_CHECK
from networkapi.vlan.models import Vlan


class NetworkIpv4Serializer(serializers.ModelSerializer):

    ip_formated = serializers.Field()

    class Meta:
        model = NetworkIPv4
        fields = (
            'id',
            'ip_formated',
        )


class NetworkIpv6Serializer(serializers.ModelSerializer):

    ip_formated = serializers.Field()

    class Meta:
        model = NetworkIPv6
        fields = (
            'id',
            'ip_formated',
        )


class VlanSerializer(serializers.ModelSerializer):

    id_vlan = serializers.Field(source='id')

    id_environment = serializers.RelatedField(
        source='ambiente.id'
    )

    networks_ipv4 = NetworkIpv4Serializer(many=True, source="networkipv4_set.select_related")
    networks_ipv6 = NetworkIpv6Serializer(many=True, source="networkipv6_set.select_related")

    class Meta:
        model = Vlan
        fields = (
            'id_vlan',
            'num_vlan',
            'id_environment',
            'networks_ipv4',
            'networks_ipv6',
        )