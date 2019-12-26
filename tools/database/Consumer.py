#!/usr/bin/python3
# coding: utf-8
# author: 9ian1i   https://github.com/Qianlitp

"""
    消费者
"""
import traceback
import logging
import pika
import simplejson

from settings.database_config import MqConfig
from models.Log import Log

logging.getLogger("pika").setLevel(logging.ERROR)


class Consumer(object):
    def __init__(self):
        self.auth = pika.PlainCredentials(MqConfig.user, MqConfig.password)
        self.connection = None
        self.channel = None
        self.handle_func = None

    def check_connection(self) -> bool:
        """
            检查连接
        """
        try:
            pika.BlockingConnection(pika.ConnectionParameters(
                host=MqConfig.host,
                port=MqConfig.port,
                credentials=self.auth,
                heartbeat=600
            ))
            return True
        except Exception as e:
            return False

    def connect(self):
        """
            主进程的消费队列连接
        """
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(
            host=MqConfig.host,
            port=MqConfig.port,
            credentials=self.auth,
            heartbeat=0
        ))
        self.channel = self.connection.channel()
        self.channel.basic_qos(prefetch_count=1)
        self.channel.exchange_declare(exchange=MqConfig.exchange, exchange_type=MqConfig.exchange_type, durable=True)
        self.channel.queue_declare(queue=MqConfig.main_queue, durable=True)
        self.channel.queue_bind(exchange=MqConfig.exchange, queue=MqConfig.main_queue)
        self.channel.basic_consume(queue=MqConfig.main_queue, on_message_callback=self.callback, auto_ack=True)

    def run(self, handle_func):
        self.connect()
        self.handle_func = handle_func
        self.channel.start_consuming()

    def callback(self, ch, method, properties, body):
        # print(ch)
        # print(method)
        # print(properties)
        try:
            assert isinstance(body, bytes)
            message = simplejson.loads(body.decode("utf-8"))

            self.handle_func(message)

        except Exception as e:
            traceback.print_exc()


if __name__ == '__main__':
    Consumer().check_connection()
