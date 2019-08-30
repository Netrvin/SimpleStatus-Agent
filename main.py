#!/usr/bin/python
# -*- coding: utf-8 -*-

# v1.0.0 https://github.com/Netrvin/SimpleStatus-Agent

import time
import json
import sys
import os
import socket
import requests

config = json.loads(open(sys.path[0] + '/config.json', 'r').read())
items = json.loads(open(sys.path[0] + '/items.json', 'r').read())


def check_self(data):
    data['status'] = 'online'
    data['message'] = ''
    return data


def check_icmp(data):
    try:
        result = os.system('ping '+data['data']['addr']+' -c 4')
        data['message'] = ''
        data['status'] = ('online' if (result == 0) else 'offline')
        return data
    except:
        data['status'] = 'error'
        data['message'] = 'Cannot ping.'


def check_tcp_port(addr, port, retry=3):
    try:
        cs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        address = (str(addr), int(port))
        cs.settimeout(3)
        status = cs.connect_ex(address)
    except:
        if retry != 0:
            return check_tcp_port(addr, port, retry-1)
        return {'status': False, 'message': 'Failed to connect.'}
    else:
        if status != 0:
            if retry != 0:
                return check_tcp_port(addr, port, retry-1)
            return {'status': False, 'message': 'Failed to connect.'}
        else:
            return {'status': True, 'message': ''}


def check_tcp(data):
    result = check_tcp_port(data['data']['addr'], data['data']['port'])
    data['message'] = result['message']
    data['status'] = ('online' if (result['status']) else 'offline')
    return data


def check_http_code(url, retry=3):
    try:
        code = requests.get(url).status_code
    except:
        if retry != 0:
            return check_http_code(url, retry-1)
        return {'code': 0, 'message': 'Failed to connect.'}
    else:
        return {'code': code, 'message': 'Code: ' + str(code)}


def check_http(data):
    result = check_http_code(data['data']['url'])
    data['message'] = result['message']
    data['status'] = ('online' if (result['code'] ==
                                   data['data']['code']) else 'offline')
    return data


def check_process_running(name):
    try:
        process = len(os.popen('ps aux | grep "' + name +
                               '" | grep -v grep').readlines())
        if process >= 1:
            return 2
        else:
            return 1
    except:
        return 0


def check_process(data):
    result = check_process_running(data['data']['name'])
    data['message'] = ''
    if result == 2:
        data['status'] = 'online'
    elif result == 1:
        data['status'] = 'offline'
    else:
        data['status'] = 'error'
        data['message'] = 'Cannot check process.'
    return data


def check_service(data):
    try:
        result = os.system('/usr/sbin/service ' + data['data']['name'] + ' status')
        data['message'] = ''
        data['status'] = ('online' if (result == 0) else 'offline')
        return data
    except:
        data['status'] = 'error'
        data['message'] = 'Cannot check service.'


def post_data(url, data, retry=3):
    try:
        print(requests.post(url=url, data=data, headers={
              'Content-Type': 'application/x-www-form-urlencoded'}).content)
    except:
        if retry != 0:
            post_data(url, data, retry - 1)


def upload_data(data):
    url = config['ServerURL']
    token = config['Token']
    agent_id = config['AgentID']
    complete_data = dict({})
    complete_data['token'] = token
    complete_data['agent_id'] = agent_id
    complete_data['data'] = json.dumps(data)
    post_data(url, complete_data)


report_data = dict({})

for i, item in items.items():
    if item['type'] == 'self':
        report_data[i] = check_self(item)
    elif item['type'] == 'icmp':
        report_data[i] = check_icmp(item)
    elif item['type'] == 'tcp':
        report_data[i] = check_tcp(item)
    elif item['type'] == 'http':
        report_data[i] = check_http(item)
    elif item['type'] == 'process':
        report_data[i] = check_process(item)
    elif item['type'] == 'service':
        report_data[i] = check_service(item)

upload_data(report_data)
