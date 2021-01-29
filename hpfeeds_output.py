#!/usr/bin/env python3
# encoding: utf-8
import logging
import argparse
import fileinput
import json
import hpfeeds
import os
import configparser

LOG_FORMAT = '%(asctime)s - %(levelname)s - %(name)s[%(lineno)s][%(filename)s] - %(message)s'

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(LOG_FORMAT))
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(handler)

def parse_config(config_file):
    sshauthlogger_config = configparser.ConfigParser()

    try:
        sshauthlogger_config.read(config_file)
    except AttributeError as e:
        print(e)
        logging.error("Can't find config file: %s", config_file)

    return sshauthlogger_config

class HpfeedsOutput:
    """
    jsonlog output
    """

    def __init__(self, config):
        self.config = config
        self.log_get = False
        self.channel = "ssh-auth-logger.events"
        self.server = config.get('hpfeeds', 'server')
        self.port = config.getint('hpfeeds', 'port')
        self.ident = config.get('hpfeeds', 'ident')
        self.secret = config.get('hpfeeds', 'secret')
        self.tags = config.get('hpfeeds', 'tags')
        self.reported_ip = config.get('hpfeeds', 'reported_ip')
        self.client = hpfeeds.new(self.server, self.port, self.ident, self.secret)

    def write(self, data):
        self.client.publish(self.channel, json.dumps(data).encode('utf-8'))

def main():

    parser = argparse.ArgumentParser(
        description='Parse ssh-auth-logger logs and export them to an hpfeeds3 destination',
        epilog='http://xkcd.com/353/')
    parser.add_argument('-d', '--debug', action="store_true", dest='debug',
                        default=False,
                        help='Get debug messages about processing')
    parser.add_argument('-c', '--config', dest='configfile',
                        default='/opt/ssh-auth-logger.cfg',
                        help='Config file to read; defaults to /opt/ssh-auth-logger.cfg')
    options = parser.parse_args()

    if options.debug:
        logger.setLevel(logging.DEBUG)

    conf = parse_config(options.configfile)
    logger.debug('Retrieved config from env: {}'.format(conf.items()))
    hpf = HpfeedsOutput(conf)

    logger.info('Starting input loop for hpfeeds_output!')
    for line in fileinput.input(files='-'):
        logger.debug('Awaiting input line')
        message = json.loads(line.rstrip())
        logger.debug('Got message of: {}'.format(json.dumps(message)))
        if hpf.reported_ip and hpf.reported_ip != 'UNSET_REPORTED_IP':
            message['dst'] = hpf.reported_ip
        hpf.write(message)
        logger.info('Processed input line.')



if __name__ == '__main__':
    main()
