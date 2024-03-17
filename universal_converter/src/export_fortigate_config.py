#!/usr/bin/python3
#
# asa_convert_config (convert Cisco ASA configuration to NGFW UserGate).
#
# Copyright @ 2021-2022 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <ran1024@yandex.ru>
# License: GPLv3
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License along
# with this program; if not, contact the site <https://www.gnu.org/licenses/>.
#
#--------------------------------------------------------------------------------------------------- 
# Модуль переноса конфигурации с устройств Fortigate на NGFW UserGate.
# Версия 0.2
#

import os, sys, json
import ipaddress
import copy
import common_func as func
from datetime import datetime as dt
from PyQt6.QtCore import QThread, pyqtSignal
from services import zone_services, character_map, character_map_for_name, character_map_file_name, character_map_userlogin, ug_services, ip_proto


trans_table = str.maketrans(character_map)
trans_filename = str.maketrans(character_map_file_name)
trans_name = str.maketrans(character_map_for_name)

class ConvertFortigateConfig(QThread):
    """Преобразуем файл конфигурации Fortigate в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_fg_path, current_ug_path):
        super().__init__()
        self.current_fg_path = current_fg_path
        self.current_ug_path = current_ug_path
        self.error = 0
        self.services = {}
        self.ip_lists = set()
        self.url_lists = set()

    def run(self):
        convert_config_file(self, self.current_fg_path)

        json_file = os.path.join(self.current_fg_path, 'config.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            self.error = 1
        else:
            convert_vpn_interfaces(self, self.current_ug_path, data['config system interface'])
            convert_dns_servers(self, self.current_ug_path, data)
            convert_notification_profile(self, self.current_ug_path, data['config system email-server'])
            convert_services(self, self.current_ug_path, data)
            convert_service_groups(self, self.current_ug_path, data['config firewall service group'])
            convert_ntp_settings(self, self.current_ug_path, data['config system ntp'])
            convert_ip_lists(self, self.current_ug_path, data)
            convert_url_lists(self, self.current_ug_path, data)
            convert_auth_servers(self, self.current_ug_path, data)
            convert_user_groups(self, self.current_ug_path, data)
            convert_local_users(self, self.current_ug_path, data)
            convert_web_portal_resources(self, self.current_ug_path, data['config vpn ssl web user-bookmark'])
            convert_time_sets(self, self.current_ug_path, data)
            convert_dnat_rule(self, self.current_ug_path, data['config firewall vip'])
            convert_loadbalancing_rule(self, self.current_ug_path, data['config firewall vip'])

        if self.error:
            self.stepChanged.emit('iORANGE|Конвертация конфигурации Fortigate в формат UserGate NGFW прошла с ошибками.')
        else:
            self.stepChanged.emit('iGREEN|Конвертация конфигурации Fortigate в формат UserGate NGFW прошла успешно.')


def convert_config_file(parent, path):
    """Преобразуем файл конфигурации Fortigate в формат json."""
    parent.stepChanged.emit('BLUE|Конвертация файла конфигурации Fortigate в формат json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit('RED|    Не найден каталог с конфигурацией Fortigate.')
        parent.error = 1
        return
    error = 0
    data = {}
    config_file = 'fortigate.cfg'
    bad_cert_block = {'config firewall ssh local-key',
                      'config firewall ssh local-ca',
                      'config vpn certificate ca',
                      'config vpn certificate local',
                      'config web-proxy explicit'}
    fg_config_file = os.path.join(path, config_file)
    try:
        with open(fg_config_file, "r") as fh:
            line = fh.readline()
            while line:
                x = line.translate(trans_table).split(' ')
                if x[0].startswith('config'):
                    key = ' '.join(x).replace('"', '')
                    config_block = []
                    line = fh.readline()
                    x = line.translate(trans_table).split(' ')
                    while x[0] != 'end':
                        for i, y in enumerate(x):
                            x[i] = y.replace('"', '')
                        config_block.append(x)
                        line = fh.readline()
                        x = line.translate(trans_table).split(' ')
                        if len(x) == 2 and x[1] == 'end':
                            break
                    if key not in bad_cert_block:
                        block = make_conf_block(parent, config_block)
                        data[key] = block
                line = fh.readline()
    except FileNotFoundError:
        parent.stepChanged.emit(f'RED|    Не найден файл "{config_file}" в каталоге "{path}" с конфигурацией Fortigate.')
        parent.error = 1
        return

    json_file = os.path.join(path, 'config.json')
    with open(json_file, 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    if parent.error:
        error = 1
    out_message = f'BLACK|    Конфигурация Fortigate в формате json выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Fortigate в формат json.' if error else out_message)

def make_edit_block(parent, data):
    """Конвертируем блок edit"""
#    print('\n--- make_edit_block ---')
#    for x in data:
#        print(x)
    edit_block = {}
    while data:
        item = data.pop(0)[4:]
        match item[0]:
            case 'set':
                edit_block[item[1]] = ' '.join(item[2:])
            case 'config':
                conf_block = []
                conf_key = ' '.join(item[1:])
                item = data.pop(0)[4:]
#                    while item[0] != 'end':
                while len(item) > 4:
                    conf_block.append(item)
                    item = data.pop(0)[4:]
                result = make_conf_block(parent, conf_block)
#                    print('result - ', result)
                edit_block[conf_key] = result
    return edit_block

def make_conf_block(parent, data):
    """Конвертируем блок config"""
#    print('\n--- make_config_block ---')
#    for x in data:
#        print(x)
    block = {}
    name = {}
    while data:
        item = data.pop(0)[4:]
#        print('\nitem conf_block -', item)
        match item[0]:
            case 'set':
                block[item[1]] = ' '.join(item[2:])
            case 'edit':
                edit_block = []
                edit_key = ' '.join(item[1:])
                if edit_key in name:
                    name[edit_key] += 1
                    edit_key += str(name[edit_key])
                else:
                    name[edit_key] = 0
                item = data.pop(0)[4:]
                try:
                    while item[0] != 'next':
                        edit_block.append(item)
                        item = data.pop(0)[4:]
                except IndexError:
                    parent.stepChanged.emit(f'RED|    Не корректная структура блока "{edit_key}". Исправьте формат блока и повторите попытку.')
                    parent.error = 1
                    break
                result = make_edit_block(parent, edit_block)
#                print('result edit - ', result)
                block[edit_key] = result
            case 'config':
#                print('Зашли в config:')
                conf_block = []
                conf_key = ' '.join(item[1:])
                item = data.pop(0)[4:]
#                while item[0] != 'end':
                while len(item) > 4:
                    conf_block.append(item)
                    item = data.pop(0)[4:]
#                print('conf_block -', conf_block)
                result = make_conf_block(parent, conf_block)
#                print('result config - ', result)
                block[conf_key] = result
    return block


def convert_vpn_interfaces(parent, path, interfaces):
    """Конвертируем интерфейсы VLAN."""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'Interfaces')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    ifaces = []
    for ifname, ifblock in interfaces.items():
        if 'vlanid' in ifblock:
            ip, mask = ifblock['ip'].split(' ')
            iface = {
                "name": ifname,
                "kind": "vlan",
                "enabled": False,
                "description": "",
                "zone_id": 0,
                "master": False,
                "netflow_profile": "undefined",
                "lldp_profile": "undefined",
                "ipv4": [pack_ip_address(ip, mask)],
                "ifalias": ifblock.get('alias', ''),
                "flow_control": False,
                "mode": "static",
                "mtu": 1500,
                "tap": False,
                "dhcp_relay": {
                    "enabled": False,
                    "host_ipv4": "",
                    "servers": []
                },
                "vlan_id": int(ifblock.get('vlanid', 0)),
                "link": ifblock.get('interface', '')
            }
            ifaces.append(iface)

    json_file = os.path.join(current_path, 'config_interfaces.json')
    with open(json_file, 'w') as fh:
        json.dump(ifaces, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.' if not ifaces else out_message)


def convert_dns_servers(parent, path, data):
    """Заполняем список системных DNS"""
    parent.stepChanged.emit('BLUE|Конвертация настроек DNS.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'DNS')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    dns_servers = []
    for key, value in data['config system dns'].items():
        if key in {'primary', 'secondary'}:
            dns_servers.append({'dns': value, 'is_bad': False})
        
    json_file = os.path.join(current_path, 'config_dns_servers.json')
    with open(json_file, 'w') as fh:
        json.dump(dns_servers, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет серверов DNS для экспорта.' if not dns_servers else out_message)

    """Создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS"""
    if 'config user domain-controller' in data:
        dns_rules = []
        for key, value in data['config user domain-controller'].items():
            dns_rules.append({
                "name": key,
                "description": "Портировано с Fortigate",
                "enabled": True,
                "domains": [f'*.{value["domain-name"]}'],
                "dns_servers": [value["ip-address"]],
            })

        json_file = os.path.join(current_path, 'config_dns_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(dns_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Правила DNS в DNS-прокси выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил DNS для экспорта.')


def convert_notification_profile(parent, path, email_info):
    """Конвертируем почтовый адрес и профиль оповещения"""
    parent.stepChanged.emit('BLUE|Конвертация почтового адреса и профиля оповещения.')
    section_path = os.path.join(path, 'Libraries')

    if 'server' in email_info:
        current_path = os.path.join(section_path, 'NotificationProfiles')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        notification = [{
            'type': 'smtp',
            'name': 'System email-server',
            'description': 'Перенесено с Fortigate',
            'host': email_info['server'],
            'port': 25,
            'security': 'none',
            'authentication': False,
            'login': 'mailserveruser'
        }]

        json_file = os.path.join(current_path, 'config_notification_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(notification, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Профиль оповещения SMTP выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет профиля оповещения для экспорта.')

    if 'reply-to' in email_info:
        current_path = os.path.join(section_path, 'Emails')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        emails = [{
            'name': 'System email-server',
            'description': 'Перенесено с Fortigate',
            'type': 'emailgroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': [{'value': email_info['reply-to']}]
        }]

        json_file = os.path.join(current_path, 'config_email_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(emails, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Почтовый адрес выгружен в группу почтовых адресов "System email-server" в файле "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет почтового адреса для экспорта.')


def convert_any_service(proto, name):
    """Конвертируем objects не имеющие портов в список сервисов"""
    service = {
        'name': name,
        'description': f'{name} packet',
        'protocols': [
            {
                'proto': proto,
                'port': '',
                'app_proto': '',
                'source_port': '',
                'alg': ''
            }
        ]
    }
    return service


def convert_services(parent, path, data):
    """Конвертируем сетевые сервисы."""
    parent.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    services = {}

    for key, value in data['config system session-helper'].items():
        protocol = {
            'proto': ip_proto[value['protocol']],
            'port': value['port'],
            'app_proto': '',
            'source_port': '',
            'alg': ''
        }
        if value['name'] in services:
            services[value['name']]['protocols'].append(protocol)
        else:
            services[value['name']] = {
                'name': ug_services.get(value['name'], value['name']),
                'description': '',
                'protocols': [protocol]
            }

    services_proto = {'110': 'pop3', '995': 'pop3s', '25': 'smtp', '465': 'smtps'}

    for key, value in data['config firewall service custom'].items():
        protocols = []
        if 'tcp-portrange' in value:
            for port in value['tcp-portrange'].replace(':', ' ').strip().split():
                if port[:2] == '0-':
                    port = f'1-{port[2:]}'
                protocols.append(
                    {
                        'proto': services_proto.get(port, 'tcp'),
                        'port': port if port != '0' else '',
                        'app_proto': services_proto.get(port, ''),
                        'source_port': '',
                        'alg': ''
                    }
                )
        if 'udp-portrange' in value:
            for port in value['udp-portrange'].strip().split():
                if port[:2] == '0-':
                    port = f'1-{port[2:]}'
                protocols.append(
                    {
                        'proto': 'udp',
                        'port': port if port != '0' else '',
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }
                )

        service_name = key.strip().translate(trans_name)
        if service_name in services:
            services[service_name]['protocols'].extend(protocols)
        else:
            if service_name == 'ALL':
                continue
            if service_name == 'ALL_TCP':
                services[service_name] = convert_any_service('tcp', 'ALL_TCP')
            elif service_name == 'ALL_UDP':
                services[service_name] = convert_any_service('udp', 'ALL_UDP')
            else:
                if 'protocol' in value and value['protocol'] == 'ICMP':
                    services[service_name] = convert_any_service('icmp', service_name)
                elif 'protocol' in value and value['protocol'] == 'ICMP6':
                    services[service_name] = convert_any_service('ipv6-icmp', service_name)
                elif 'protocol-number' in value:
                    try:
                        proto = ip_proto[value['protocol-number']]
                    except KeyError as err:
                        parent.stepChanged.emit(f'bRED|    Протокол "{service_name}" номер протокола: {err} не поддерживается UG NGFW.')
                    else:
                        services[service_name] = convert_any_service(proto, ug_services.get(service_name, service_name))
                else:
                    services[service_name] = {
                        'name': ug_services.get(service_name, service_name),
                        'description': value.get('category', ''),
                        'protocols': protocols
                    }

    json_file = os.path.join(current_path, 'config_services_list.json')
    with open(json_file, 'w') as fh:
        json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
    parent.services = services

    out_message = f'BLACK|    Сервисы выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет сетевых сервисов для экспорта.' if not services else out_message)


def convert_service_groups(parent, path, services):
    """Конвертируем группы сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация групп сервисов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'ServicesGroups')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    services_groups = []
    for key, value in services.items():
        srv_group = {
            'name': key.strip().translate(trans_name),
            'description': '',
            'type': 'servicegroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': []
        }
        for item in value['member'].strip().split():
            service = copy.deepcopy(parent.services[item])
            for x in service['protocols']:
                x.pop('source_port', None)
                x.pop('app_proto', None)
                x.pop('alg', None)
            srv_group['content'].append(service)

        services_groups.append(srv_group)

    json_file = os.path.join(current_path, 'config_services_groups_list.json')
    with open(json_file, "w") as fh:
        json.dump(services_groups, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Группы сервисов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.' if not services_groups else out_message)


def convert_ntp_settings(parent, path, ntp_info):
    """Конвертируем настройки NTP"""
    parent.stepChanged.emit('BLUE|Конвертация настроек NTP.')
    section_path = os.path.join(path, 'UserGate')
    current_path = os.path.join(section_path, 'GeneralSettings')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    if ntp_info:
        ntp_server = {
            'ntp_servers': [],
            'ntp_enabled': True,
            'ntp_synced': True if ntp_info['ntpsync'] == 'enable' else False
        }

        for i, value in ntp_info['ntpserver'].items():
            ntp_server['ntp_servers'].append(value['server'])
            if int(i) == 2:
                break
        if ntp_server['ntp_servers']:
            json_file = os.path.join(current_path, 'config_ntp.json')
            with open(json_file, 'w') as fh:
                json.dump(ntp_server, fh, indent=4, ensure_ascii=False)
        else:
            ntp_info = []

    out_message = f'BLACK|    Настройки NTP выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.' if not ntp_info else out_message)


def convert_ip_lists(parent, path, data):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    ip_list = {
        'name': '',
        'description': '',
        'type': 'network',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {'threat_level': 3},
        'content': []
    }
    data['ngfw_ip_lists'] = {}

    for list_name, value in data['config firewall address'].items():
        if 'subnet' in value:
            ip_list['name'] = list_name.strip().translate(trans_name)
            ip_list['description'] = value.get('comment', '')
            ip, mask = value['subnet'].split()
            subnet = ipaddress.ip_network(f'{ip}/{mask}')
            ip_list['content'] = [{'value': f'{ip}/{subnet.prefixlen}'}]
        elif 'type' in value and value['type'] == 'iprange':
            ip_list['name'] = list_name.strip().translate(trans_name)
            ip_list['description'] = value.get('comment', '')
            ip_list['content'] = [{'value': f'{value["start-ip"]}-{value["end-ip"]}'}]
        else:
            continue

        data['ngfw_ip_lists'][ip_list['name']] = {
            'uuid': value['uuid'],
            'fqdn': ip_list['content']
        }

        json_file = os.path.join(current_path, f'{list_name.strip().translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

    for list_name, value in data['config firewall multicast-address'].items():
        ip_list['name'] = 'Multicast - ' + list_name.strip().translate(trans_name)
        if value["start-ip"] == value["end-ip"]:
            ip_list['content'] = [{'value': value["start-ip"]}]
        else:
            ip_list['content'] = [{'value': f'{value["start-ip"]}-{value["end-ip"]}'}]

        data['ngfw_ip_lists'][ip_list['name']] = {
            'uuid': '',
            'fqdn': ip_list['content']
        }

        json_file = os.path.join(current_path, f'{ip_list["name"].strip().translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список ip-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

    for list_name, value in data['config firewall addrgrp'].items():
        ip_list['content'] = []
        members = value['member'].split()
        for item in members:
            if item in data['ngfw_ip_lists']:
                ip_list['content'].append({'list': item})
            else:
                try:
                    ipaddress.ip_address(item)   # проверяем что это IP-адрес или получаем ValueError
                    ip_list['content'].append({'value': item})
                except ValueError:
                    pass

        if ip_list['content']:
            ip_list['name'] = list_name.strip().translate(trans_name)
            ip_list['description'] = value.get('comment', '')

            data['ngfw_ip_lists'][ip_list['name']] = {
                'uuid': value['uuid'],
                'fqdn': ip_list['content']
            }

            json_file = os.path.join(current_path, f'{list_name.strip().translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список ip-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".'
    parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.' if not ip_list['name'] else out_message)


def convert_url_lists(parent, path, data):
    """Конвертируем списки URL"""
    parent.stepChanged.emit('BLUE|Конвертация списков URL.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'URLLists')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    url_list = {
        'name': '',
        'description': '',
        'type': 'url',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {'list_compile_type': 'case_insensitive'},
        'content': []
    }
    data['ngfw_urls_lists'] = {}

    for key, value in data['config wanopt content-delivery-network-rule'].items():
        _, pattern = key.split(':')
        if pattern == '//':
            list_name = 'All URLs (default)'
        else:
            list_name = pattern.replace('/', '')

        if 'host-domain-name-suffix' not in value and list_name != 'All URLs (default)':
            parent.stepChanged.emit(f'rNOTE|       Запись "{key}" не конвертирована так как не имеет host-domain-name-suffix.')
            continue

        suffixes = work_with_rules(value['rules']) if 'rules' in value else []

        url_list['content'] = []
        for domain_name in value.get('host-domain-name-suffix', '').split(' '):
            if suffixes:
                url_list['content'].extend([{'value': f'{domain_name}/{x}' if domain_name else x} for x in suffixes])
            else:
                url_list['content'].extend([{'value': domain_name}])
        if url_list['content']:
            url_list['name'] = list_name.strip().translate(trans_name)
            url_list['description'] = value.get('comment', '')

        json_file = os.path.join(current_path, f'{list_name.strip().translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

    for list_name, value in data['config firewall address'].items():
        if 'type' in value and value['type'] == 'fqdn':
            url_list['name'] = list_name.strip().translate(trans_name)
            url_list['description'] = value.get('comment', '')
            url_list['content'] = [{'value': value['fqdn']}]

            data['ngfw_urls_lists'][url_list['name']] = {
                'uuid': value['uuid'],
                'fqdn': url_list['content']
            }

            json_file = os.path.join(current_path, f'{list_name.strip().translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

    for list_name, value in data['config firewall addrgrp'].items():
        url_list['content'] = []
        members = value['member'].split()
        for item in members:
            if item in data['ngfw_urls_lists']:
                url_list['content'].extend(data['ngfw_urls_lists'][item]['fqdn'])
        if url_list['content']:
            url_list['name'] = list_name.strip().translate(trans_name)
            url_list['description'] = value.get('comment', '')

            data['ngfw_urls_lists'][url_list['name']] = {
                'uuid': value['uuid'],
                'fqdn': url_list['content']
            }

            json_file = os.path.join(current_path, f'{list_name.strip().translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

    for list_name, value in data['config firewall wildcard-fqdn custom'].items():
        if list_name in data['ngfw_urls_lists']:
            list_name = f'{list_name} - wildcard-fqdn'
        url_list['name'] = list_name.strip().translate(trans_name)
        url_list['description'] = value.get('comment', '')
        url_list['content'] = [{'value': value['wildcard-fqdn']}]

        data['ngfw_urls_lists'][url_list['name']] = {
            'uuid': value['uuid'],
            'fqdn': url_list['content']
        }

        json_file = os.path.join(current_path, f'{list_name.strip().translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(url_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|       Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Списки URL выгружены в каталог "{current_path}".'
    parent.stepChanged.emit('GRAY|    Нет списков URL для экспорта.' if not url_list['name'] else out_message)


def work_with_rules(rules):
    """
    Для функции convert_url_lists().
    Преобразование структуры 'config wanopt content-delivery-network-rule'.
    """
    patterns = set()
    for _, rule in rules.items():
        for _, entries in rule['match-entries'].items():
            value = entries['pattern']
            patterns.add(value[1:] if value.startswith('/') else value)
    return patterns


def convert_auth_servers(parent, path, data):
    """Конвертируем серверов авторизации"""
    parent.stepChanged.emit('BLUE|Конвертация серверов аутентификации.')
    section_path = os.path.join(path, 'UsersAndDevices')
    current_path = os.path.join(section_path, 'AuthServers')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return
    success = False

    if 'config user ldap' in data:
        ldap_servers = []
        for key, value in data['config user ldap'].items():
            if value['dn']:
                tmp_dn1 = [x.split('=') for x in value['dn'].split(',')]
                tmp_dn2 = [b for a, b in tmp_dn1 if a == 'dc']
                dn = '.'.join(tmp_dn2)
            ldap_servers.append({
                "name": f'{key.strip().translate(trans_name)} - AD Auth server',
                "description": "LDAP-коннектор импортирован с Fortigate.",
                "enabled": False,
                "ssl": False,
                "address": value['server'],
                "bind_dn": value['username'].replace('\\', '', 1),
                "password": "",
                "domains": [dn],
                "roots": [value['dn']] if value['dn'] else [],
                "keytab_exists": False
            })
        json_file = os.path.join(current_path, 'config_ldap_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации LDAP выгружены в файл "{json_file}".')
        success = True

    if 'config user radius' in data:
        radius_servers = []
        for key, value in data['config user radius'].items():
            radius_servers.append({
                "name": f'{key.strip().translate(trans_name)} - Radius Auth server',
                "description": "Radius auth server импортирован с Fortigate.",
                "enabled": False,
                "addresses": [
                    {'host': value['server'], 'port': 1812}
                ]
            })
        json_file = os.path.join(current_path, 'config_radius_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации RADIUS выгружены в файл "{json_file}".')
        success = True

    out_message = f'GREEN|    Настройки серверов аутентификации конвертированы.'
    parent.stepChanged.emit('GRAY|    Нет серверов аутентификации для экспорта.' if not success else out_message)


def convert_user_groups(parent, path, data):
    """Конвертируем локальные группы пользователей"""
    parent.stepChanged.emit('BLUE|Конвертация локальных групп пользователей.')
    section_path = os.path.join(path, 'UsersAndDevices')
    current_path = os.path.join(section_path, 'Groups')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    users = {x for x in data['config user local']}

    groups = []
    for key, value in data['config user group'].items():
        groups.append({
            "name": key,
            "description": "",
            "is_ldap": False,
            "is_transient": False,
            "users": [x for x in value['member'].split() if x in users] if 'member' in value else []
        })

    json_file = os.path.join(current_path, 'config_groups.json')
    with open(json_file, 'w') as fh:
        json.dump(groups, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список локальных групп пользователей выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет локальных групп пользователей для экспорта.' if not groups else out_message)


def convert_local_users(parent, path, data):
    """Конвертируем локальных пользователей"""
    parent.stepChanged.emit('BLUE|Конвертация локальных пользователей.')
    section_path = os.path.join(path, 'UsersAndDevices')
    current_path = os.path.join(section_path, 'Users')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    users = {}
    trans_userlogin = str.maketrans(character_map_userlogin)
    for key, value in data['config user local'].items():
        if value['type'] == 'password':
            users[key] = {
                "name": key,
                "enabled": False if value.get('status', None) == 'disable' else True,
                "auth_login": key.strip().translate(trans_userlogin),
                "is_ldap": False,
                "static_ip_addresses": [],
                "ldap_dn": "",
                "emails": [value['email-to']] if value.get('email-to', None) else [],
                "phones": [],
                "first_name": "",
                "last_name": "",
                "groups": [],
            }

    for key, value in data['config user group'].items():
        users_in_group = [x for x in value['member'].split() if x in users] if 'member' in value else []
        for user in users_in_group:
            users[user]['groups'].append(key)

    json_file = os.path.join(current_path, 'config_users.json')
    with open(json_file, 'w') as fh:
        json.dump([x for x in users.values()], fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет локальных пользователей для экспорта.' if not users else out_message)


def convert_web_portal_resources(parent, path, data):
    """Конвертируем ресурсы веб-портала"""
    parent.stepChanged.emit('BLUE|Конвертация ресурсов веб-портала.')
    section_path = os.path.join(path, 'GlobalPortal')
    current_path = os.path.join(section_path, 'WebPortal')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    resources = []
    for key, value in data.items():
        user_group = key.split('#')[1]
        for key1, value1 in value.items():
            for key2, value2 in value1.items():
                url = None
                icon = 'default.svg'
                if 'apptype' in value2 and value2['apptype'] in {'rdp', 'ftp'}:
                    if value2['apptype'] == 'rdp':
                        url = f'rdp://{value2["host"]}'
                        icon = 'rdp.svg'
                    elif value2['apptype'] == 'ftp':
                        url = f'ftp://{value2["folder"]}'
                elif 'url' in value2:
                    url = value2['url']
                    value2['apptype'] = 'http'
                if url:
                    resources.append({
                        'name': f'Resource {value2["apptype"]}-{key2}',
                        'description': 'Перенесено с Fortigate',
                        'enabled': True,
                        'url': url,
                        'additional_urls': [],
                        'users': [['group', user_group]] if user_group else [],
                        'icon': icon,
                        'mapping_url': '',
                        'mapping_url_ssl_profile_id': 0,
                        'mapping_url_certificate_id': 0,
                        'position_layer': 'local',
                        'rdp_check_session_alive': True if value2['apptype'] == 'rdp' else False,
                        'transparent_auth': True if value2['apptype'] == 'rdp' else False
                    })

    json_file = os.path.join(current_path, 'config_web_portal.json')
    with open(json_file, 'w') as fh:
        json.dump(resources, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список ресурсов веб-портала выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет ресурсов веб-портала для экспорта.' if not resources else out_message)


def convert_time_sets(parent, path, data):
    """Конвертируем time set (календари)"""
    parent.stepChanged.emit('BLUE|Конвертация календарей.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'TimeSets')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    week = {
        "monday": 1,
        "tuesday": 2,
        "wednesday": 3,
        "thursday": 4,
        "friday": 5,
        "saturday": 6,
        "sunday": 7
    }
    timerestrictiongroup = []
    for key, value in data['config firewall schedule onetime'].items():
        if value:
            time_from, fixed_date_from = value['start'].split()
            time_to, fixed_date_to = value['end'].split()
            timerestrictiongroup.append({
                "name": key.strip().translate(trans_name),
                "description": "Портировано с Fortigate",
                "type": "timerestrictiongroup",
                "url": "",
                "list_type_update": "static",
                "schedule": "disabled",
                "attributes": {},
                "content": [
                    {
                        'name': key.strip().translate(trans_name),
                        'type': 'range',
                        'time_to': time_to,
                        'time_from': time_from,
                        'fixed_date_to': f'{fixed_date_to.replace("/", "-")}T00:00:00',
                        'fixed_date_from': f'{fixed_date_from.replace("/", "-")}T00:00:00'
                    }
                ]
            })

    for key, value in data['config firewall schedule recurring'].items():
        if value:
            schedule = {
                "name": key.strip().translate(trans_name),
                "description": "Портировано с Fortigate",
                "type": "timerestrictiongroup",
                "url": "",
                "list_type_update": "static",
                "schedule": "disabled",
                "attributes": {},
                "content": [
                    {
                        'name': key.strip().translate(trans_name),
                        'type': 'weekly',
                        'days': [week[day] for day in value['day'].split()]
                    }
                ]
            }
            if 'start' in value:
                schedule['content'][0]['time_from'] = value['start']
                schedule['content'][0]['time_to'] = value['end']
            timerestrictiongroup.append(schedule)

    json_file = os.path.join(current_path, 'config_calendars.json')
    with open(json_file, 'w') as fh:
        json.dump(timerestrictiongroup, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список календарей выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет календарей для экспорта.' if not timerestrictiongroup else out_message)


def convert_dnat_rule(parent, path, data):
    """Конвертируем object 'config firewall vip' в правила DNAT или Port-форвардинга"""
    parent.stepChanged.emit('BLUE|Конвертация правил DNAT/Порт-форвардинга.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'NATandRouting')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    rules = []
    ips_for_rules = set()
    for key, value in data.items():
        if value and 'type' not in value:
            if 'mappedip' in value:
                services = []
                port_mappings = []
                if value['extip'] in ips_for_rules:
                    list_id = value['extip']
                else:
                    ips_for_rules.add(value['extip'])
                    list_id = create_ip_list(parent, path, value['extip'], key)
                create_ip_list(parent, path, value['mappedip'], key)
                if 'service' in value:
                    services = [['service' if x in parent.services else 'list_id', x] for x in value['service'].split()]
                elif 'mappedport' in value:
                    port_mappings = [{
                        'proto': value['protocol'] if 'protocol' in value else 'tcp',
                        'src_port': int(value['extport']),
                        'dst_port': int(value['mappedport'])
                    }]
                rule = {
                    'name': f'Rule {key.strip().translate(trans_name)}',
                    'description': value['comment'] if 'comment' in value else 'Портировано с Fortigate',
                    'action': 'port-mapping' if port_mappings else 'dnat',
                    'position': 'last',
                    'zone_in': ['Untrusted'],
                    'zone_out': [],
                    'source_ip': [],
                    'dest_ip': [['list_id', list_id]],
                    'service': services,
                    'target_ip': value['mappedip'],
                    'gateway': '',
                    'enabled': False,
                    'log': False,
                    'log_session_start': False,
                    'target_snat': True,
                    'snat_target_ip': value['extip'],
                    'zone_in_nagate': False,
                    'zone_out_nagate': False,
                    'source_ip_nagate': False,
                    'dest_ip_nagate': False,
                    'port_mappings': port_mappings,
                    'direction': "input",
                    'users': [],
                    'scenario_rule_id': False
                }
                rules.append(rule)
                parent.stepChanged.emit(f'BLACK|    Создано правило {rule["action"]} "{rule["name"]}".')

    json_file = os.path.join(current_path, 'config_nat_rules.json')
    with open(json_file, 'w') as fh:
        json.dump(rules, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Павила DNAT/Порт-форвардинга выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет правил DNAT/Порт-форвардинга для экспорта.' if not rules else out_message)


def convert_loadbalancing_rule(parent, path, data):
    """Конвертируем object 'config firewall vip' в правила балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Конвертация правил балансировки нагрузки.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'LoadBalancing')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    rules = []
    ssl_certificate = False
    for key, value in data.items():
        if value and value.get('type', None) == 'server-load-balance':
            if 'ssl-certificate' in value:
                ssl_certificate = True
            hosts = []
            for server in value['realservers'].values():
                hosts.append({
                    'ip_address': server['ip'],
                    'port': int(server['port']),
                    'weight': 50,
                    'mode': 'masq',
                    'snat': True
                })
            rule = {
                'name': f'Rule {key.strip().translate(trans_name)}',
                'description': value['comment'] if 'comment' in value else 'Портировано с Fortigate',
                'enabled': False,
                'protocol': 'tcp' if value['server-type'] in {'http', 'https'} else value['server-type'],
                'scheduler': 'wrr',
                'ip_address': value['extip'],
                'port': int(value['extport']),
                'hosts': hosts,
                'fallback': False,
                'monitoring': {
                    'kind': 'ping',
                    'service': 'tcp',
                    'request': '',
                    'response': '',
                    'interval': 60,
                    'timeout': 60,
                    'failurecount': 10
                },
                'src_zones': ['Untrusted'],
                'src_zones_nagate': False,
                'src_ips': [],
                'src_ips_nagate': False
            }
            rules.append(rule)
            parent.stepChanged.emit(f'BLACK|    Создано правило балансировки нагрузки "{rule["name"]}".')

    json_file = os.path.join(current_path, 'config_loadbalancing_tcpudp.json')
    with open(json_file, 'w') as fh:
        json.dump(rules, fh, indent=4, ensure_ascii=False)

    if ssl_certificate:
        parent.stepChanged.emit(f'LBLUE|    В правилах Fortigate использовались сертификаты, после импорта конфигурации удалите соответсвующие правила балансировки нагрузки и')
        parent.stepChanged.emit(f'LBLUE|    создайте правила reverse-прокси, предварительно загрузив необходимые сертификаты.')
    out_message = f'GREEN|    Павила балансировки нагрузки выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет правил балансировки нагрузки для экспорта.' if not rules else out_message)


def convert_ace(parent, path, data):
    """Конвертируем object 'config firewall policy' в правила МЭ"""
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'Firewall')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

#data['ngfw_urls_lists'][url_list['name']]
#data['ngfw_ip_lists'][ip_list['name']]
#ip_list['name'] = list_name.strip().translate(trans_name)

    rules = {}
    for key, value in data.items():
        rules[key] = {
            'name': f'Rule - {value["name"] if value.get("name", None) else key}',
            'description': 'Портировано с Fortigate',
            'action': value['action'] if value.get('action', None) else 'drop',
            'position': 'last',
            'scenario_rule_id': False,     # При импорте заменяется на UID или "0". 
            'src_zones': [],
            'dst_zones': [],
            'src_ips': [],
            'dst_ips': [],
            'services': [],
            'apps': [],
            'users': [],
            'enabled': False,
            'limit': True,
            'limit_value': '3/h',
            'limit_burst': 5,
            'log': False,
            'log_session_start': True,
            'src_zones_negate': False,
            'dst_zones_negate': False,
            'src_ips_negate': False,
            'dst_ips_negate': False,
            'services_negate': False,
            'apps_negate': False,
            'fragmented': 'ignore',
            'time_restrictions': [],
            'send_host_icmp': '',
        }
        rules.append(rule)
        parent.stepChanged.emit(f'BLACK|    Создано правило МЭ "{rule["name"]}".')

    json_file = os.path.join(current_path, 'config_firewall_rules.json')
    with open(json_file, 'w') as fh:
        json.dump([v for _, v in sorted(rules.items())], fh, indent=4, ensure_ascii=False)

    if rules:
        parent.stepChanged.emit(f'LBLUE|    После импорта правил МЭ, необходимо в каждом правиле указать зону источника и зону назначения.')
        parent.stepChanged.emit(f'LBLUE|    Создайте необходимое количество зоны и присвойте зону каждому интерфейсу.')
        parent.stepChanged.emit(f'GREEN|    Павила межсетевого экрана выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


#    subnet = ipaddress.ip_network(f'{ip}/{mask}')
#    tmp_dict['content'].append({'value': f'{ip}/{subnet.prefixlen}'})

    # default_vrf = {
        # "name": "default",
        # "descriprion": "",
        # "interfaces": [],
        # "routes": [],
        # "ospf": {},
        # "bgp": {},
        # "rip": {},
        # "pimsm": {}
    # }

def convert_route(array):
    """Конвертируем шлюзы и статические маршруты в VRF по умолчанию"""
    [iface, network, mask, next_hop, *other] = array[1:]
    iface = iface.translate(trans_name)
    if network == '0':
        network = '0.0.0.0'
    if mask == '0':
        mask = '0.0.0.0'
    if network == mask == '0.0.0.0':
        gateway = {
            "name": f"{iface} (backup)" if gateways and gateways[0]['name'] == iface else iface,
            "enabled": True,
            "description": "",
            "ipv4": next_hop,
            "vrf": "default",
            "weight": int(other[0]),
            "multigate": False,
            "default": False if gateways else True,
            "iface": "undefined",
            "is_automatic": False,
            "active": True
        }
        gateways.append(gateway)
    else:
        network_dest = pack_ip_address(network, mask)
        route = {
            "name": f"Route for {network_dest}",
            "description": "",
            "enabled": False,
            "dest": network_dest,
            "gateway": next_hop,
            "ifname": "undefined",
            "kind": "unicast",
            "metric": int(other[0])
        }
        default_vrf['routes'].append(route)


def get_service_number(service):
    """Получить цифровое значение сервиса из его имени"""
    if service.isdigit():
        return service
    elif service in service_ports:
        return service_ports.get(service, service)


#def convert_webtype_ace(acs_name, rule_block, remark):
#    """
#    Конвертируем ACE webtype в правило КФ. Не активные ACE пропускаются.
#    """
#    if 'inactive' in rule_block:
#        return
#
#    nonlocal cfrule_number
#    cfrule_number += 1
#    deq = deque(rule_block)
#    action = deq.popleft()
#    rule = {
#        "name": f"Rule {cfrule_number} ({acs_name})",
#        "description": ", ".join(remark),
#        "position": "last",
#        "action": "drop" if action == 'deny' else "accept",
#        "public_name": "",
#        "enabled": True,
#        "enable_custom_redirect": False,
#        "blockpage_template_id": -1,
#        "users": [],
#        "url_categories": [],
#        "src_zones": [],
#        "dst_zones": [],
#        "src_ips": [],
#        "dst_ips": [],
#        "morph_categories": [],
#        "urls": [],
#        "referers": [],
#        "referer_categories": [],
#        "user_agents": [],
#        "time_restrictions": [],
#        "content_types": [],
#        "http_methods": [],
#        "src_zones_negate": False,
#        "dst_zones_negate": False,
#        "src_ips_negate": False,
#        "dst_ips_negate": False,
#        "url_categories_negate": False,
#        "urls_negate": False,
#        "content_types_negate": False,
#        "user_agents_negate": False,
#        "custom_redirect": "",
#        "enable_kav_check": False,
#        "enable_md5_check": False,
#        "rule_log": False,
#        "scenario_rule_id": False,
#        "users_negate": False
#    }
#
#----------------------------------------------------------------------------------------
def aaa():
    with open(f"data_ca/{file_name}.txt", "r") as fh:
        line = fh.readline()
        while line:
            if line[:1] in {':', '!'}:
                line = fh.readline()
                continue
            tmp_block = []
            x = line.translate(trans_table).rsplit(' ')
            match x[0]:
                case 'domain-name':
                    convert_modules(x)
                    line = fh.readline()
                case 'dns':
                    match x[1]:
                        case 'domain-lookup':
                            convert_zone_access(x)
                            line = fh.readline()
                        case 'forwarder':
                            convert_dns_servers(x)
                            line = fh.readline()
                        case 'server-group':
                            line, tmp_block = make_block_of_line(fh)
                            convert_dns_rules(x[2], tmp_block)
                case 'interface':
                    line, tmp_block = make_block_of_line(fh)
                    convert_interface(tmp_block)
                case 'route':
                    convert_route(x)
                    line = fh.readline()
                case 'telnet' | 'ssh'| 'http':
                    convert_zone_access(x)
                    line = fh.readline()
                case 'aaa-server':
                    line, tmp_block = make_block_of_line(fh)
                    convert_auth_servers(x, tmp_block)
                case 'time-range':
                    line, tmp_block = make_block_of_line(fh)
                    convert_time_sets(x[1], tmp_block)
                case 'clock':
                    convert_settings_ui(x)
                    line = fh.readline()
                case 'ntp':
                    convert_ntp_settings(x)
                    line = fh.readline()
                case 'dhcp':
                    convert_dhcp_settings(x)
                    line = fh.readline()
                case 'username':
                    convert_local_users(x[1], x[2])
                    line = fh.readline()
                case 'user-identity':
                    convert_user_identity_domains(x[1:])
                    line = fh.readline()
                case 'object':
                    match x[1]:
                        case 'service':
                            line, tmp_block = make_block_of_line(fh)
                            convert_service_object(x[2], tmp_block)
                        case 'network':
                            line, tmp_block = make_block_of_line(fh)
                            convert_network_object(x[2], tmp_block)
                case 'object-group':
                    match x[1]:
                        case 'network':
                            line, tmp_block = make_block_of_line(fh)
                            convert_network_object_group(x[2], tmp_block)
                        case 'service':
                            line, tmp_block = make_block_of_line(fh)
                            convert_service_object_group(x[2:], tmp_block)
                        case 'protocol':
                            line, tmp_block = make_block_of_line(fh)
                            convert_protocol_object_group(x[2], tmp_block)
                        case 'user':
                            line, tmp_block = make_block_of_line(fh)
                            convert_user_groups_object_group(x[2], tmp_block)
                        case 'icmp-type':
                            line, tmp_block = make_block_of_line(fh)
                            convert_icmp_object_group(x[2])
                        case _:
                            line = fh.readline()
                case 'access-group':
                    convert_access_group(x[1:])
                    line = fh.readline()
                case _:
                    line = fh.readline()

    if not os.path.isdir('data/UserGate/GeneralSettings'):
        os.makedirs('data/UserGate/GeneralSettings')
    with open('data/UserGate/GeneralSettings/config_ntp.json', 'w') as fh:
        json.dump(ntp, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/Zones'):
        os.makedirs('data/Network/Zones')
    with open('data/Network/Zones/config_zones.json', 'w') as fh:
        json.dump([x for x in zones.values()], fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/DNS'):
        os.makedirs('data/Network/DNS')
    with open('data/Network/DNS/config_dns_servers.json', 'w') as fh:
        json.dump(system_dns, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/DNS'):
        os.makedirs('data/Network/DNS')
    with open('data/Network/DNS/config_dns_rules.json', 'w') as fh:
        json.dump(dns_rules, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/Interfaces'):
        os.makedirs('data/Network/Interfaces')
    with open('data/Network/Interfaces/config_interfaces.json', 'w') as fh:
        json.dump(interfaces, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/Gateways'):
        os.makedirs('data/Network/Gateways')
    with open('data/Network/Gateways/config_gateways.json', 'w') as fh:
        json.dump(gateways, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/VRF'):
        os.makedirs('data/Network/VRF')
    with open('data/Network/VRF/config_routers.json', 'w') as fh:
        json.dump([default_vrf], fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Network/DHCP'):
        os.makedirs('data/Network/DHCP')
    with open('data/Network/DHCP/config_dhcp_subnets.json', 'w') as fh:
        for x in dhcp.values():
            x.pop('cc', None)
        json.dump([x for x in dhcp.values()], fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/UsersAndDevices/AuthServers'):
        os.makedirs('data/UsersAndDevices/AuthServers')
    tacacs_servers = []
    radius_servers = []
    ldap_servers = []
    for key, auth_server in auth_servers.items():
        if auth_server['description'] == 'tacacs':
            tacacs_servers.append(auth_server)
        if auth_server['description'] == 'radius':
            radius_servers.append(auth_server)
        if auth_server['description'] == 'ldap':
            ldap_servers.append(auth_server)
    with open('data/UsersAndDevices/AuthServers/config_tacacs_servers.json', 'w') as fh:
        json.dump(tacacs_servers, fh, indent=4, ensure_ascii=False)
    with open('data/UsersAndDevices/AuthServers/config_radius_servers.json', 'w') as fh:
        json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
    with open('data/UsersAndDevices/AuthServers/config_ldap_servers.json', 'w') as fh:
        json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Libraries/Services'):
        os.makedirs('data/Libraries/Services')
    with open('data/Libraries/Services/config_services.json', 'w') as fh:
        json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
    
    if not os.path.isdir('data/Libraries/URLLists'):
        os.makedirs('data/Libraries/URLLists')
    for list_name, value in url_dict.items():
        with open(f'data/Libraries/URLLists/{list_name}.json', 'w') as fh:
            json.dump(value, fh, indent=4, ensure_ascii=False)
    
############################################# Служебные функции ###################################################
def pack_ip_address(ip, mask):
    if ip == '0':
        ip = '0.0.0.0'
    if mask == '0':
        mask = '128.0.0.0'
    ip_address = ipaddress.ip_interface(f'{ip}/{mask}')
    return f'{ip}/{ip_address.network.prefixlen}'

def get_ips(parent, rule_ips, rule_name):
    """
    Получить UID-ы списков IP-адресов и URL-листов.
    Если списки не найдены, то они создаются или пропускаются, если невозможно создать."""
    new_rule_ips = []
    for ips in rule_ips.split():
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', utm.list_ip[ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', utm.list_url[ips[1]]])
        except KeyError as err:
            print(f'\t\033[33mНе найден адрес источника/назначения {err} для правила "{rule_name}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
    return new_rule_ips

def get_guids_users_and_groups(utm, item):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if item['users']:
        users = []
        for x in item['users']:
            if x[0] == 'user' and x[1]:
                i = x[1].partition("\\")
                if i[2]:
                    err, result = utm.get_ldap_user_guid(i[0], i[2])
                    if err != 0:
                        print(f"\033[31m{result}\033[0m")
                    elif not result:
                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт.\033[0m')
                    else:
                        x[1] = result
                        users.append(x)
                else:
                    try:
                        x[1] = utm.list_users[x[1]]
                    except KeyError:
                        print(f'\t\033[31mНе найден пользователь "{x[1]}" для правила "{item["name"]}".\n\tИмпортируйте локальных пользователей и повторите импорт правил.\033[0m')
                    else:
                        users.append(x)

            elif x[0] == 'group' and x[1]:
                i = x[1].partition("\\")
                if i[2]:
                    err, result = utm.get_ldap_group_guid(i[0], i[2])
                    if err != 0:
                        print(f"\033[31m{result}\033[0m")
                    elif not result:
                        print(f'\t\033[31mНет LDAP-коннектора для домена "{i[0]}"!\n\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                    else:
                        x[1] = result
                        users.append(x)
                else:
                    try:
                        x[1] = utm.list_groups[x[1]]
                    except KeyError:
                        print(f'\t\033[31mНе найдена группа "{x[1]}" для правила "{item["name"]}".\n\tИмпортируйте локальные группы и повторите импорт правил.\033[0m')
                    else:
                        users.append(x)
            elif x[0] == 'special' and x[1]:
                users.append(x)
        item['users'] = users

def set_time_restrictions(utm, item):
    if item['time_restrictions']:
        try:
            item['time_restrictions'] = [utm.list_calendar[x] for x in item['time_restrictions']]
        except KeyError as err:
            print(f'\t\033[33mНе найден календарь {err} для правила "{item["name"]}".\n\tЗагрузите календари в библиотеку и повторите попытку.\033[0m')
            item['time_restrictions'] = []

def get_services(utm, rule_services, rule_name):
    new_service_list = []
    for service in rule_services:
        try:
            new_service_list.append(['service', utm.services[service[1]]])
        except KeyError as err:
            print(f'\t\033[33mНе найден сервис "{service[1]}" для правила "{rule_name}".\033[0m')
    return new_service_list

def set_urls_and_categories(utm, item):
    if item['urls']:
        try:
            item['urls'] = [utm.list_url[x] for x in item['urls']]
        except KeyError as err:
            print(f'\t\033[33mНе найден URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
            item['urls'] = []

def create_ip_list(parent, path, ip, rule_name):
    """Создаём IP-лист для правила. Возвращаем имя ip-листа."""
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return ip

    ip_list = {
        'name': ip,
        'description': f'IP-лист создан для правил dnat/port-forwarding',
        'type': 'network',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {'threat_level': 3},
        'content': [{'value': ip}]
    }

    json_file = os.path.join(current_path, f'{ip_list["name"]}.json')
    with open(json_file, 'w') as fh:
        json.dump(ip_list, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'NOTE|    Создан список IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')

    return ip_list['name']


def main():
    convert_file()

if __name__ == '__main__':
    main()
