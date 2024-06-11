#!/usr/bin/python3
#
# export_cisco_fpr_config.py (convert configuration from Cisco FPR to NGFW UserGate).
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
# Модуль предназначен для выгрузки конфигурации MikroTik Router в формат json NGFW UserGate.
# Версия 1.2
#

import os, sys, json, re
import ipaddress, copy
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from services import network_proto, service_ports, trans_table, trans_name, trans_filename


revers_service_ports = {v: k for k, v in service_ports.items()}
#pattern = re.compile('\d{1, 3}\.\d{1, 3}\.\d{1, 3}\.\d{1, 3}')
pattern = re.compile(r"[-\w]+='[-:!,/\.\w ]+'|[-\w]+=[-:!,/\.\w]+|rule='.+'")
pattern_rf = re.compile(r"[\w]+=[-\w]+|\(.+\)|(?:accept|reject)")


class ConvertMikrotikConfig(QThread):
    """Преобразуем файл конфигурации MikroTik в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_fpr_path, current_ug_path):
        super().__init__()
        self.current_fpr_path = current_fpr_path
        self.current_ug_path = current_ug_path
        self.error = 0
        self.ifaces = []
#    data = {
#        'ip_lists': {},
#        'services': {
#            'Any ICMP': {
#                'name': 'Any ICMP',
#                'description': 'Any ICMP packet',
#                'protocols': [
#                    {
#                        'proto': 'icmp',
#                        'port': '',
#                        'source_port': '',
#                    }
#                ],
#                'group': False
#            }
#        },
#        'zones': [],
#        'fw_rules': {},
#        'routes': []
#    }

    def run(self):
        self.stepChanged.emit(f'GREEN|                                                            Конвертация конфигурации MikroTik в формат UserGate NGFW.')
        self.stepChanged.emit(f'ORANGE|====================================================================================================================')
#        convert_config_file(self, self.current_fpr_path)
        
        json_file = os.path.join(self.current_fpr_path, 'config.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            self.error = 1
        else:
#            convert_settings_ui(self, self.current_ug_path, data)
#            convert_ntp_settings(self, self.current_ug_path, data)
            convert_ipip_interface(self, self.current_ug_path, data)
#            convert_zones(self, self.current_ug_path, data['zones'])
#            convert_static_routes(self, self.current_ug_path, data['routes'])
#            convert_vlan_interfaces(self, self.current_ug_path, data['ifaces'])
#            convert_ip_lists(self, self.current_ug_path, data['ip_lists'])
#            convert_service_groups(self, self.current_ug_path, data['services'])
#            convert_services_list(self, self.current_ug_path, data['services'])
#            convert_firewall_rules(self, self.current_ug_path, data['fw_rules'], data['services'])

            self.save_interfaces()

        if self.error:
            self.stepChanged.emit('iORANGE|Конвертация конфигурации MikroTik в формат UserGate NGFW прошла с ошибками.')
        else:
            self.stepChanged.emit('iGREEN|Конвертация конфигурации MikroTik в формат UserGate NGFW прошла успешно.')

    def save_interfaces(self):
        """Сохраняем интерфейсы IPIP и VLAN"""
        if self.ifaces:
            self.stepChanged.emit('BLUE|Выгружаем конфигурацию интерфейсов.')
            section_path = os.path.join(self.current_ug_path, 'Network')
            current_path = os.path.join(section_path, 'Interfaces')
            err, msg = func.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    Error: Произошла ошибка выгрузки интерфейсов.')
                self.stepChanged.emit('RED|    {msg}.')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, "w") as fh:
                json.dump(self.ifaces, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Конфигурация интерфейсов выгружена в файл "{json_file}".')


def parse_string(conf_data):
    new_struct = []
    for item in conf_data:
        item_dict = {}
        result = pattern.findall(item[4:])
        for x in result:
            key, value = x.split('=')
            item_dict[key] = value
        new_struct.append(item_dict)
    return new_struct


def parse_routing_filter_rule(conf_data):
    """Парсинг routing filter rule"""
    new_struct = []
    for item in conf_data:
        item_dict = {}
        result = pattern_rf.findall(item[4:])
        for x in result:
            if 'in' in x or '&' in x:
                continue
            if x.startswith('('):
                x = x[1:-1].replace('=', '', 1)
            elif x in ('accept', 'reject'):
                x = f'rule={x}'
            key, value = x.split('=') 
            item_dict[key] = value
        new_struct.append(item_dict)
    return new_struct

def convert_config_file(parent, path):
    """Преобразуем файл конфигурации MikroTik в json."""
    parent.stepChanged.emit('BLUE|Преобразование файла конфигурации MikroTik в json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit('RED|    Не найден каталог с конфигурацией MikroTik.')
        parent.error = 1
        return
    error = 0
    data = {}
    config_file = 'mikrotik.cfg'
    config_file_path = os.path.join(path, config_file)

    try:
        with open(config_file_path, "r") as fh:
            line = fh.readline()
            while line:
                line = line.translate(trans_table).rstrip().replace('"', "'")
                if line.startswith('#'):
                    line = fh.readline()
                    continue
                if line.startswith('/'):
                    key = line[1:]
                    data[key] = []
                    line = fh.readline().translate(trans_table).rstrip().replace('"', "'")
                    while line[0] != '/':
                        config_block = line
                        if line[-1] == chr(92):
                            config_block = line[:-1]
                            line = fh.readline().translate(trans_table).rstrip().replace('"', "'")
                            while line[0] not in {'a', 's', '/'}:
                                config_block += line[:-1].lstrip() if line[-1] == chr(92) else line.lstrip()
                                line = fh.readline().translate(trans_table).rstrip().replace('"', "'")
                        else:
                            line = fh.readline().translate(trans_table).rstrip().replace('"', "'")
                        data[key].append(config_block)
                        if not line:
                            break

    except FileNotFoundError:
        parent.stepChanged.emit(f'RED|    Не найден файл "{config_file_path}" с конфигурацией MikroTic.')
        parent.error = 1
        return

    data.pop('tool traffic-monitor', None)
    data.pop('tool netwatch', None)
    data.pop('system script', None)
    data.pop('system routerboard settings', None)

    for key, value in data.items():
        if key not in {'ip service', 'routing filter rule'}:
            data[key] = parse_string(value)

    if 'routing filter rule' in data:
        data['routing filter rule'] = parse_routing_filter_rule(data['routing filter rule'])
        
    ifaces = {}
    for item in data['ip address']:
        ifaces[item['interface']] = item['address']
    data['ip address'] = ifaces

    json_file = os.path.join(path, 'config.json')
    with open(json_file, "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Конфигурация MikroTik в формате json выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации MikroTik в формат json.' if error else out_message)


def convert_settings_ui(parent, path, data):
    """Конвертируем часовой пояс"""
    if 'system clock' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация часового пояса.')
    settings = {'ui_timezone': None}
    for item in data['system clock']:
        if 'time-zone-name' in item and item['time-zone-name']:
            settings['ui_timezone'] = item['time-zone-name']

    if settings['ui_timezone']:
        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        json_file = os.path.join(current_path, 'config_settings_ui.json')
        with open(json_file, 'w') as fh:
            json.dump(settings, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройка часового пояса выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет часового пояса для экспорта.')


def convert_ntp_settings(parent, path, data):
    """Конвертируем настройки для NTP"""
    if 'system ntp client servers' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация настроек NTP.')
    ntp = {
        "ntp_servers": [],
        "ntp_enabled": True,
        "ntp_synced": True
    }
    for item in data['system ntp client servers']:
        if 'address' in item and item['address']:
            if len(ntp['ntp_servers']) < 2:
                ntp['ntp_servers'].append(item['address'])

    if ntp['ntp_servers']:
        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        json_file = os.path.join(current_path, 'config_ntp.json')
        with open(json_file, 'w') as fh:
            json.dump(ntp, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройка NTP выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет настроек NTP для экспорта.')


def convert_ipip_interface(parent, path, data):
    """Конвертируем интерфейс IP-IP"""
    if 'interface ipip' not in data:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Конвертация интервейсов IP-IP.')
    for item in data['interface ipip']:
        try:
            iface = {
                'name': 'gre',
                'kind': 'tunnel',
                'enabled': False,
                'description': '',
                'zone_id': 0,
                'master': False,
                'netflow_profile': 'undefined',
                'lldp_profile': 'undefined',
                'ipv4': [],
                'ifalias': '',
                'flow_control': False,
                'tunnel': {
                    'local_ipv4': item['local-address'],
                    'mode': 'ipip',
                    'remote_ipv4': item['remote-address'],
                    'vni': 0
                },
                'mode': 'static',
                'mtu': item['mtu'] if item['mtu'] else 1500,
                'tap': False
            }
            iface['ipv4'].append(data['ip address'][item['name']])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Интервейс IP-IP {item["name"]} не конвертирован [{err}].')
            error = 1
            parent.error = 1
        else:
            parent.ifaces.append(iface)
            parent.stepChanged.emit(f'BLACK|    Интервейс IP-IP {item["name"]} конвертирован.')
    if error:
        parent.stepChanged.emit('ORANGE|    Прошла ошибка при экспорте интервейсов IP-IP.')
    else:
        parent.stepChanged.emit('GREEN|    Интервейсы IP-IP конвертированы.')


def convert_vlan_interfaces(parent, path, ifaces_list):
    """Конвертируем интерфейсы VLAN"""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')

    for iface in ifaces_list:
        iface['enabled'] = False
        iface['master'] = False
        iface['netflow_profile'] = 'undefined'
        iface['lldp_profile'] = 'undefined'
        iface['ifalias'] = ''
        iface['flow_control'] = False
        iface['mode'] = 'static'
        iface['mtu'] = 1500
        iface['tap'] = False
        iface['link'] = ''

    json_file = os.path.join(current_path, 'config_interfaces.json')
    with open(json_file, "w") as fh:
        json.dump(ifaces_list, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.' if not ifaces_list else out_message)


#####################################################################################################
def add_ip_list(ip, mask='255.255.255.255', obj='host'):
    ip_list = {
        'name': '',
        'description': '',
        'type': 'network',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {
            'threat_level': 3
        },
        'content': []
    }
    if obj == 'subnet':
        subnet = ipaddress.ip_network(f'{ip}/{mask}')
        ip_list['name'] = f'subnet {ip}/{subnet.prefixlen}'
        ip_list['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
    elif obj == 'host':
        ip_list['name'] = f'host {ip}'
        ip_list['content'].append({'value': f'{ip}'})

    data['ip_lists'][ip_list['name']] = ip_list
    return ip_list['name']

def convert_local_pool(x):
    ip_list = {
        'name': f'{x[3]}',
        'description': '',
        'type': 'network',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {
            'threat_level': 3
        },
        'content': [{'value': x[4]}]
    }
    data['ip_lists'][x[3]] = ip_list

def convert_network_object(name, fh):
    ip_list = {
        'name': name,
        'description': '',
        'type': 'network',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {
            'threat_level': 3
        },
        'content': []
    }
    line = fh.readline()
    y = line.translate(trans_table).strip().split(' ')
    if y[0] == 'subnet':
        subnet = ipaddress.ip_network(f'{y[1]}/{y[2]}')
        ip_list['content'].append({'value': f'{y[1]}/{subnet.prefixlen}'})
        data['ip_lists'][name] = ip_list
    elif y[0] == 'host':
        ip_list['content'].append({'value': f'{y[1]}'})
        data['ip_lists'][name] = ip_list
    elif y[0] == 'range':
        ip_list['content'].append({'value': f'{y[1]}-{y[2]}'})
        data['ip_lists'][name] = ip_list
    return line

def convert_network_object_group(name, fh):
    ip_list = {
        'name': name,
        'description': '',
        'type': 'network',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {
            'threat_level': 3
        },
        'content': []
    }
    line = fh.readline()
    y = line.translate(trans_table).rstrip().split(' ')
    while y[0] == '':
        if y[1] == 'network-object':
            if y[2] == 'object':
#                    ip_list['content'].extend(data['ip_lists'][y[3]]['content'])
                ip_list['content'].append({'list': y[3]})
            elif y[2] == 'host':
                ip_list['content'].append({'value': f'{y[3]}'})
            else:
                try:
                    subnet = ipaddress.ip_network(f'{y[2]}/{y[3]}')
                    ip_list['content'].append({'value': f'{y[2]}/{subnet.prefixlen}'})
                except IndexError:
                    parent.stepChanged.emit(f"RED|    Error: строка '{' '.join(y)}' не может быть обработана.")
                    error = 1
        elif y[1] == 'group-object':
#                ip_list['content'].extend(data['ip_lists'][y[2]]['content'])
            ip_list['content'].append({'list': y[2]})
        elif y[1] == 'description':
            ip_list['description'] = ' '.join(y[2:])
        line = fh.readline()
        y = line.translate(trans_table).rstrip().split(' ')
    data['ip_lists'][name] = ip_list
    return line        

def convert_service_object(name, fh):
    service = {
        'name': name,
        'description': '',
        'protocols': [],
        'group': False
    }
    port = ''
    source_port = ''
    line = fh.readline()
    y = line.translate(trans_table).strip().split(' ')
        
    try:
        i = y.index('source')
        source_port = y[i+2] if y[i+1] == 'eq' else f'{y[i+2]}-{y[i+3]}'
    except ValueError:
        pass
    try:
        i = y.index('destination')
        port = y[i+2] if y[i+1] == 'eq' else f'{y[i+2]}-{y[i+3]}'
    except ValueError:
        pass

    service['protocols'].append(
        {
            'proto': y[1],
            'port': port,
            'source_port': source_port,
         }
    )
    data['services'][name] = service
    return line

def convert_service_object_group(line, fh):
    x = line.translate(trans_table).split(' ')
    service = {
        'name': x[2],
        'description': '',
        'protocols': [],
        'group': False
    }
    port = ''
    source_port = ''

    line = fh.readline()
    y = line.translate(trans_table).rstrip().split(' ')

    try:
        proto_array = x[3].split('-')
        while y[0] == '':
            if y[1] == 'port-object':
                for indx, port in enumerate(y[3:]):
                    if not port.isdigit():
                        try:
                            y[indx+3] = service_ports[port]
                        except KeyError as err:
                            parent.stepChanged.emit(f'RED|    Error: не найден порт {err} в сервисе "{" ".join(x)}"')
                            error = 1
                            break
#                                while True:
#                                    port_number = input(f'\t\033[36mВведите номер порта для сервиса {err}:\033[0m')
#                                    if not port_number.isdigit() or (int(port_number) > 65535) or (int(port_number) < 1):
#                                        print('\t\033[31mНеверно, номер порта должен быть цифрой между 1 и 65535.\033[0m')
#                                    else:
#                                        y[indx+3] = port_number
#                                        break
                for proto in proto_array:
                    if y[3] == "0":
                        port_for_proto = ''
                    else:
                        port_for_proto = f'{y[3]}-{y[4]}' if y[2] == 'range' else y[3]
                    service['protocols'].append(
                            {
                                'proto': proto,
                                'port': port_for_proto,
                                'source_port': '',
                             }
                    )
            elif y[1] == 'group-object':
                try:
#                        service['protocols'].extend(data['services'][y[2]]['protocols'])
                    service['protocols'].append({'name': y[2]})
                    service['group'] = True
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: не найден group-object {err} в сервисе "{" ".join(x)}" - "{y}"')
                    error = 1
            elif y[1] == 'description':
                service['description'] = ' '.join(y[2:])
            line = fh.readline()
            y = line.translate(trans_table).rstrip().split(' ')
    except IndexError:
        while y[0] == '':
            if y[1] == 'service-object':
                port = ''
                source_port = ''
                proto_array = y[2].split('-')
                try:
                    i = y.index('source')
                    source_port = y[i+2] if y[i+1] == 'eq' else f'{y[i+2]}-{y[i+3]}'
                except ValueError:
                    pass
                try:
                    i = y.index('destination')
                    port = y[i+2] if y[i+1] == 'eq' else f'{y[i+2]}-{y[i+3]}'
                except ValueError:
                    pass
                for proto in proto_array:
                    service['protocols'].append(
                        {
                            'proto': proto,
                            'port': port,
                            'source_port': source_port,
                         }
                    )
            elif y[1] == 'group-object':
                try:
#                        service['protocols'].extend(data['services'][y[2]]['protocols'])
                    service['protocols'].append({'name': y[2]})
                    service['group'] = True
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: не найден group-object {err} в сервисе "{" ".join(x)}" - {y}')
                    error = 1
            elif y[1] == 'description':
                service['description'] = ' '.join(y[2:])

            line = fh.readline()
            y = line.translate(trans_table).rstrip().split(' ')


    data['services'][x[2]] = service
    return line

def convert_icmp_object_group(name, fh):
    service = {
        'name': 'Any ICMP',
        'description': 'Any ICMP packet',
        'protocols': [
            {
                'proto': 'icmp',
                'port': '',
                'source_port': '',
            }
        ],
        'group': False
    }
    line = fh.readline()
    y = line.split(' ')
    while y[0] == '':
        line = fh.readline()
        y = line.split(' ')
    data['services'][name] = service
    return line

def convert_access_list(rule_id, rule_name, fh):
    fw_rule = {
        'name': rule_name.translate(trans_name).strip("-").strip(),
        'description': "",
        'action': '',
        'src_zones': set(),
        'dst_zones': set(),
        'src_ips': set(),
        'dst_ips': set(),
        'services': set(),
        'enabled': False,
    }

    line = fh.readline()
    x = line.translate(trans_table).rstrip().split(' ')
    while x[0] == 'access-list' and x[1] == 'CSM_FW_ACL_' and x[2] == 'advanced':
        service_name = ''
        service = {
            'name': '',
            'description': '',
            'protocols': [
                {
                    'proto': '',
                    'port': '',
                    'source_port': '',
                }
            ],
            'group': False
        }
        if not rule_id == int(x[x.index('rule-id') + 1]):
            parent.stepChanged.emit(f'RED|    Error: "{line}" не обработано!')
            error = 1
            break
        fw_rule['action'] = 'drop' if x[3] == 'deny' else 'accept'
        if x[4] == 'icmp':
            fw_rule['services'].add('Any ICMP')
        elif x[4] == 'ipinip':
            service_name = f'service-IPinIP'
            service['name'] = service_name
            service['protocols'][0]['proto'] = 'ipip'
        elif x[4] == 'gre':
            service_name = f'service-gre'
            service['name'] = service_name
            service['protocols'][0]['proto'] = 'gre'
        elif x[4] == '41':
            line = fh.readline()
            x = line.translate(trans_table).rstrip().split(' ')
            continue
        if x[4] == 'object-group' and x[5] in data['services']:
            fw_rule['services'].add(x[5])
            x.pop(5)
#                print('----------------------------------------------------------------------')
        if x[5] == 'ifc':
            fw_rule['src_zones'].add(x[6].replace('_', ' '))
            y = x[7:]
        else:
            y = x[5:]

#            print(f"\n{x[2:]}")
#            print(f"{x[4]}", y)

        for i in range(len(y)):
            if y[i] in ('host', 'object', 'object-group', 'any'):
                if y[i] == 'any':
                    continue
                if i == 0:
                    list_name = add_ip_list(y[1]) if y[0] == 'host' else y[1]
                    fw_rule['src_ips'].add(('list_id', list_name))
                elif i == 2:
                    list_name = add_ip_list(y[3]) if y[2] == 'host' else y[3]
                    fw_rule['dst_ips'].add(('list_id', list_name))
                else:
                    if y[i+1] in data['services']:
                        fw_rule['services'].add(y[i+1])
                    else:
                        list_name = add_ip_list(y[i+1]) if y[i] == 'host' else y[i+1]
                        fw_rule['dst_ips'].add(('list_id', list_name))
            elif y[i] == 'ifc':
                fw_rule['dst_zones'].add(y[i+1].replace('_', ' '))
            elif y[i] == 'eq':
                if service_name:
                    service_name = f'{service_name} extended'
                    service['name'] = service_name
                    service['protocols'][0]['source_port'] = service['protocols'][0]['port']
                    service['protocols'][0]['port'] = service_ports.get(y[i+1], y[i+1])
                else:
                    service_name = f'service-{x[4]}-{revers_service_ports.get(y[i+1], y[i+1])}'
                    service['name'] = service_name
                    service['protocols'][0]['proto'] = x[4]
                    service['protocols'][0]['port'] = service_ports.get(y[i+1], y[i+1])
                    
            elif y[i] == 'range':
                if service_name:
                    service_name = f'{service_name} extended'
                    service['name'] = service_name
                    service['protocols'][0]['source_port'] = service['protocols'][0]['port']
                    service['protocols'][0]['port'] = f'{service_ports.get(y[i+1], y[i+1])}-{service_ports.get(y[i+2], y[i+2])}'
                else:
                    service_name = f'service-{x[4]} {service_ports.get(y[i+1], y[i+1])}-{service_ports.get(y[i+2], y[i+2])}'
                    service['name'] = service_name
                    service['protocols'][0]['proto'] = x[4]
                    service['protocols'][0]['port'] = f'{service_ports.get(y[i+1], y[i+1])}-{service_ports.get(y[i+2], y[i+2])}'
            elif pattern.match(y[i]) and pattern.match(y[i+1]):
                if i == 0:
                    fw_rule['src_ips'].add(('list_id', add_ip_list(y[0], mask=y[1], obj='subnet')))
                elif i == 2:
                    fw_rule['dst_ips'].add(('list_id', add_ip_list(y[2], mask=y[3], obj='subnet')))
                elif i == 4:
                    fw_rule['dst_ips'].add(('list_id', add_ip_list(y[4], mask=y[5], obj='subnet')))
        if service_name:
            fw_rule['services'].add(service_name)
            if service_name not in data['services']:
                data['services'][service_name] = service

        line = fh.readline()
        x = line.translate(trans_table).rstrip().split(' ')

    fw_rule['src_zones'] = list(fw_rule['src_zones'])
    fw_rule['dst_zones'] = list(fw_rule['dst_zones'])
    fw_rule['src_ips'] = list(fw_rule['src_ips'])
    fw_rule['dst_ips'] = list(fw_rule['dst_ips'])
    fw_rule['services'] = list(fw_rule['services'])

    data['fw_rules'][rule_id] = fw_rule
    return line

def convert_routes_list(route_line):
    """Выгрузить список маршрутов"""
    route = {
        'enabled': True,
        'name': '',
        'description': '',
        'dest': '',
        'gateway': '',
        'ifname': 'undefined',
        'kind': 'unicast',
        'metric': 0
    }

    try:
        ip_address = ipaddress.ip_interface(f'{route_line[2]}/{route_line[3]}')
        route['dest'] = f'{route_line[2]}/{ip_address.network.prefixlen}'
        route['name'] = f'{route_line[1]} - {route["dest"]}'
        route['gateway'] = route_line[4]
        if len(route_line) == 6:
            route['metric'] = int(route_line[5])
    except IndexError as err:
        parent.stepChanged.emit(f'RED|    Error: {err}. Маршрут "{" ".join(route_line)}" не конвертирован.')
        error = 1
    else:
        data['routes'].append(route)

#------------------------------------------- Конвертация -----------------------------------------------
def convert_zones(parent, path, zone_names):
    """Конвертируем зоны."""
    parent.stepChanged.emit('BLUE|Конвертация Зон.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'Zones')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    zones = []
    for item in zone_names:
        zone = {
            'name': item,
            'description': '',
            'dos_profiles': [
                {
                    'enabled': True,
                    'kind': 'syn',
                    'alert_threshold': 3000,
                    'drop_threshold': 6000,
                    'aggregate': False,
                    'excluded_ips': []
                },
                {
                    'enabled': True,
                    'kind': 'udp',
                    'alert_threshold': 3000,
                    'drop_threshold': 6000,
                    'aggregate': False,
                    'excluded_ips': []
                },
                {
                    'enabled': True,
                    'kind': 'icmp',
                    'alert_threshold': 100,
                    'drop_threshold': 200,
                    'aggregate': False,
                    'excluded_ips': []
                }
            ],
            'services_access': [
                {
                'enabled': True,
                'service_id': 'Ping',
                'allowed_ips': []
                },
                {
                'enabled': True,
                'service_id': 'SMTP(S)-прокси',
                'allowed_ips': []
                },
                {
                'enabled': True,
                'service_id': 'POP(S)-прокси',
                'allowed_ips': []
                }
            ],
            'readonly': False,
            'enable_antispoof': False,
            'antispoof_invert': False,
            'networks': [],
            'sessions_limit_enabled': False,
            'sessions_limit_threshold': 0,
            'sessions_limit_exclusions': []
        }
        zones.append(zone)
        parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" конвертирована.')

    json_file = os.path.join(current_path, 'config_zones.json')
    with open(json_file, "w") as fh:
        json.dump(zones, fh, indent=4, ensure_ascii=False)

    if zones:
        parent.stepChanged.emit(f'GREEN|    Конфигурация Зон выгружена в файл "{json_file}".')
        parent.stepChanged.emit('LBLUE|    Необходимо настроить каждую зону. Включить нужный сервис в контроле доступа, поменять по необходимости параметры защиты от DoS и настроить защиту от спуфинга.')
    else:
        parent.stepChanged.emit('GRAY|    Нет зон для экспорта.')


def convert_static_routes(parent, path, static_routes):
    """Конвертируем статические маршруты"""
    parent.stepChanged.emit('BLUE|Конвертация статических маршрутов.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'VRF')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    if static_routes:
        vrf_info = [{
            'name': 'default',
            'description': 'default',
            'interfaces': [],
            'routes': static_routes,
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {},
        }]
    else:
        vrf_info = []

    json_file = os.path.join(current_path, 'config_vrf.json')
    with open(json_file, "w") as fh:
        json.dump(vrf_info, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Статические маршруты добавлены в виртуальный маршрутизатор по умолчанию в файле "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.' if not vrf_info else out_message)


def convert_ip_lists(parent, path, list_ips):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    for key, value in list_ips.items():
        json_file = os.path.join(current_path, f'{key.translate(trans_filename)}.json')
        with open(json_file, "w") as fh:
            json.dump(value, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{key}" выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".'
    parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.' if not list_ips else out_message)


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
        if value['group']:
            srv_group = {
                'name': value['name'],
                'description': value['description'],
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            for item in value['protocols']:
                service = copy.deepcopy(services[item['name']])
                service.pop('group')
                for x in service['protocols']:
                    x.pop('source_port', None)
                srv_group['content'].append(service)

            services_groups.append(srv_group)

    json_file = os.path.join(current_path, 'config_services_groups_list.json')
    with open(json_file, "w") as fh:
        json.dump(services_groups, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Группы сервисов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.' if not services_groups else out_message)


def convert_services_list(parent, path, services):
    """Конвертируем список сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация списка сервисов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    services_list = []
    for key, value in services.items():
        if value['group']:
            continue
        service = copy.deepcopy(value)
        service.pop('group', None)
        for item in service['protocols']:
            match item['port']:
                case '110':
                    item['proto'] = 'pop3'
                    item['app_proto'] = 'pop3'
                case '995':
                    item['proto'] = 'pop3s'
                    item['app_proto'] = 'pop3s'
                case '25':
                    item['proto'] = 'smtp'
                    item['app_proto'] = 'smtp'
                case '465':
                    item['proto'] = 'smtps'
                    item['app_proto'] = 'smtps'
                case _:
                    item['app_proto'] = ''
            item['alg'] =  ''
        services_list.append(service)

    json_file = os.path.join(current_path, 'config_services_list.json')
    with open(json_file, "w") as fh:
        json.dump(services_list, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Список сервисов выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет сервисов для экспорта.' if not services_list else out_message)


def convert_firewall_rules(parent, path, fw_rules, services_list):
    """Конвертируем правила межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'Firewall')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    firewall_rules = []
    for key, value in fw_rules.items():
        value['services'] = [['list_id', x] if services_list[x]['group'] else ['service', x] for x in value['services']]
        value['scenario_rule_id'] = False
        value['users'] = []
        value['limit'] = False
        value['limit_value'] = '3/h'
        value['limit_burst'] = '5'
        value['log'] = False
        value['log_session_start'] = False
        value['src_zones_nagate'] = False
        value['dst_zones_nagate'] = False
        value['src_ips_nagate'] = False
        value['dst_ips_nagate'] = False
        value['services_nagate'] = False
        value['fragmented'] = 'ignore'
        value['time_restrictions'] = []
        value['send_host_icmp'] = ''
        value['position_layer'] = 'local'
        value['ips_profile'] = False
        value['l7_profile'] = False
        value['hip_profile'] = []

        firewall_rules.append(value)

    json_file = os.path.join(current_path, 'config_firewall_rules.json')
    with open(json_file, "w") as fh:
        json.dump(firewall_rules, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Список правил межсетевого экрана выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.' if not firewall_rules else out_message)


def main():
    pass

if __name__ == '__main__':
    main()
