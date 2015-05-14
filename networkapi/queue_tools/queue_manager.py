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


from django.conf import settings
from stompest.config import StompConfig
from stompest.sync import Stomp


LOGGER = logging.getLogger(__name__)


class QueueManager(object):
    """
        Object to manager objects sent to queue
    """

    def __init__(self):
        """
            Create a new instance QueueManager and initialize
            with parameters of destination and broker uri
            from settings or set default settings.

        """
        self._queue = []
        self._queue_destination = getattr(settings, 'QUEUE_DESTINATION', None) or "/topic/networkapi_queue"
        self._broker_uri = getattr(settings, 'QUEUE_BROKER_URI', None) or "tcp://localhost:61613"

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
            Create a new stomp configuration client, connect and
            then serializes message by message posting
            them to your consumers in TOPIC standard
            and disconnect.
        """

        try:

            configuration = StompConfig(uri=self._broker_uri)
            client = Stomp(configuration)
            client.connect()

            for message in self._queue:
                serialized_message = json.dumps(message, ensure_ascii=False)
                client.send(self._queue_destination, serialized_message)

            client.disconnect()

        except Exception, e:
            LOGGER.error(u"QueueManagerError - Error on sending objects from queue.")
            LOGGER.error(e)
