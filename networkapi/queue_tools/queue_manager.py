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
import types

import logging

import pika

from django.conf import settings


LOGGER = logging.getLogger(__name__)


class QueueManager(object):
    """
        Object to manager objects sent to queue
    """

    def __init__(self):
        """
            Create a new instance QueueManager and initialize
            with parameters of routing, exchange and connection
            from settings or set default settings.

        """
        self._queue = []
        self._api_routing_key = getattr(settings, 'QUEUE_ROUTING', None) or "networkapi_routing"
        self._api_exchange = getattr(settings, 'QUEUE_EXCHANGE', None) or "networkapi_exchange"
        self._url_parameters = getattr(settings, 'QUEUE_BROKER_URL', None) or "amqp://guest:guest@localhost:5672/%2F"

    def append(self, dict_obj):
        """
            Appended in list object a dictionary that represents
            the body of the message that will be sent to queue.

            :param dict_obj: Dict object

        """

        try:

            if not isinstance(dict_obj, types.DictType):
                raise ValueError(u"QueueManagerError - The type must be a instance of Dict")

            self._queue.append(dict_obj)

        except Exception, e:
            LOGGER.error(u"QueueManagerError - Error on appending objects to queue.")
            LOGGER.error(e)

    def send(self):

        """
            Open a new connection defining a channel,
            then serializes message by message posting
            them to your consumers in TOPIC standard
            and closes the connection.
        """

        try:

            conn_parameters = pika.URLParameters(self._url_parameters)
            connection = pika.BlockingConnection(conn_parameters)
            channel = connection.channel()
            channel.exchange_declare(exchange=self._api_exchange, type='topic')

            for message in self._queue:

                serialized_message = json.dumps(message, ensure_ascii=False)

                channel.basic_publish(
                    exchange=self._api_exchange,
                    routing_key=self._api_routing_key,
                    body=serialized_message
                )

            connection.close()

        except Exception, e:
            LOGGER.error(u"QueueManagerError - Error on sending objects from queue.")
            LOGGER.error(e)