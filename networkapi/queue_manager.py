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

import json

import pika
from django.conf import settings

from networkapi.log import Log

log = Log(__name__)


class QueueManager(object):

    OPERATION_SAVE = "insert"
    OPERATION_UPDATE = "update"
    OPERATION_DELETE = "delete"

    def __init__(self):
        self.queue = list()
        self.api_routing_key = getattr(settings, 'api_routing', None) or "networkapi_routing"
        self.api_exchange = getattr(settings, 'api_exchange', None) or "networkapi_exchange"
        self.connection_parameters = getattr(settings, 'connection_parameters', None) or pika.ConnectionParameters()

    def append(self, id, description, operation):

        obj_to_queue = dict(id=id, description=description, operation=operation)
        self.queue.append(obj_to_queue)

    def send(self):

        connection = pika.BlockingConnection(self.connection_parameters)
        channel = connection.channel()
        channel.exchange_declare(exchange=self.api_exchange, type='topic')

        for message in self.queue:

            serialized_message = json.dumps(message, ensure_ascii=False)

            channel.basic_publish(
                exchange=self.api_exchange,
                routing_key=self.api_routing_key,
                body=serialized_message
            )

        connection.close()