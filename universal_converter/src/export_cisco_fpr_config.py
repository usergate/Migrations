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
# Модуль предназначен для выгрузки конфигурации Cisco FPR в формат json NGFW UserGate.
# Версия 1.6 21.10.2024
#

import os, sys, json, re
import copy, time
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from services import network_proto, service_ports, trans_table, trans_filename, trans_name, MONTHS


revers_service_ports = {v: k for k, v in service_ports.items()}
pattern = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


class ConvertCiscoFPRConfig(QThread):
    """Преобразуем файл конфигурации Cisco FPR в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_fpr_path, current_ug_path):
        super().__init__()
        self.current_fpr_path = current_fpr_path
        self.current_ug_path = current_ug_path
        self.vendor = 'Cisco FPR'
        self.error = 0

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации Cisco FPR в формат UserGate NGFW.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        convert_config_file(self, self.current_fpr_path)
#        return
        
        json_file = os.path.join(self.current_fpr_path, 'cisco_fpr.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            self.error = 1
        else:
            convert_zones(self, self.current_ug_path, data)
            convert_dns_servers(self, self.current_ug_path, data['dns']['system_dns'])
            convert_dns_rules(self, self.current_ug_path, data['dns']['dns_rules'])
            convert_gateways(self, self.current_ug_path, data['gateways'])
            convert_static_routes(self, self.current_ug_path, data['routes'])
            convert_vlan_interfaces(self, self.current_ug_path, data)
            convert_ip_lists(self, self.current_ug_path, data['ip_lists'])
            convert_url_lists(self, self.current_ug_path, data['url_lists'])
            convert_service_groups(self, self.current_ug_path, data['services'])
            convert_services_list(self, self.current_ug_path, data['services'])
            convert_time_sets(self, self.current_ug_path, data)
            convert_firewall_rules(self, self.current_ug_path, data)

        if self.error:
            self.stepChanged.emit('iORANGE|Конвертация конфигурации Cisco FPR в формат UserGate NGFW прошла с ошибками.')
        else:
            self.stepChanged.emit('iGREEN|Конвертация конфигурации Cisco FPR в формат UserGate NGFW прошла успешно.')

def convert_config_file(parent, path):
    """Преобразуем файл конфигурации Cisco FPR в json."""
    parent.stepChanged.emit('BLUE|Преобразование файла конфигурации Cisco FPR в json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit('RED|    Не найден каталог с конфигурацией Cisco FPR.')
        parent.error = 1
        return
    error = 0
    config_file = 'cisco_fpr.cfg'
    fpr_config_file = os.path.join(path, config_file)

    data = {
        'ip_lists': {},
        'url_lists': {},
        'services': {
            'Any ICMP': {
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
        },
        'zones': [],
        'dns': {
            'domain-lookup': [],
            'dns_rules': [],
            'system_dns': [],
            'dns_static': []
        },
        'dhcp_relay': {},
        'ifaces': [],
        'fw_rules': {},
        'gateways': [],
        'routes': [],
        'time-range': {}
    }

    def add_ip_list(ip, mask='255.255.255.255', obj='host'):
        ip_list = {
            'name': '',
            'description': 'Портировано с Cisco FPR.',
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
            subnet = func.pack_ip_address(ip, mask)
            ip_list['name'] = f'subnet {subnet}'
            ip_list['content'].append({'value': subnet})
        elif obj == 'host':
            ip_list['name'] = f'host {ip}'
            ip_list['content'].append({'value': f'{ip}'})

        data['ip_lists'][ip_list['name']] = ip_list
        return ip_list['name']

    def convert_local_pool(x):
        ip_list = {
            'name': f'{x[3]}',
            'description': 'Портировано с Cisco FPR.',
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

    def convert_interface(ifname, line, fh):
        iface = {
            'name': ifname,
            'kind': '',
            'description': 'Портировано с Cisco FPR.',
            'zone_id': '',
            'ipv4': [],
            'dhcp_relay': {
                'enabled': False,
                'host_ipv4': '',
                'servers': []
            },
            'vlan_id': 0,
        }
        while not line.startswith('!'):
            y = line.translate(trans_table).strip().split(' ')
            if y[0] == 'vlan':
                iface['kind'] = 'vlan'
                iface['vlan_id'] = int(y[1])
            elif y[0] == 'nameif':
                iface['zone_id'] = y[1].replace('_', ' ')
            elif y[0] == 'ip' and y[1] == 'address':
                iface['ipv4'].append(func.pack_ip_address(y[2], y[3]))
            elif y[0] == 'description':
                iface['description'] = f"{iface['description']}\n{y[1]}"
            line = fh.readline()
        if iface['kind'] == 'vlan':
            data['ifaces'].append(iface)
        return line

    def convert_network_object(name, fh):
        ip_list = {
            'name': name,
            'description': 'Портировано с Cisco FPR.',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        line = fh.readline()
        y = line.translate(trans_table).strip().split(' ')
        if y[0] == 'subnet':
            ip_list['content'].append({'value': func.pack_ip_address(y[1], y[2])})
            data['ip_lists'][name] = ip_list
        elif y[0] == 'host':
            ip_list['content'].append({'value': f'{y[1]}'})
            data['ip_lists'][name] = ip_list
        elif y[0] == 'range':
            ip_list['content'].append({'value': f'{y[1]}-{y[2]}'})
            data['ip_lists'][name] = ip_list
        elif y[0] == 'fqdn':
            ip_list['type'] = 'url'
            ip_list['attributes'] = {'list_compile_type': 'case_insensitive'}
            if len(y) == 5:
                ip_list['content'].append({'value': f'{y[2]}'})
            else:
                ip_list['content'].append({'value': f'{y[1]}'})
            data['url_lists'][name] = ip_list
        return line

    def convert_network_object_group(name, fh):
        ip_list = {
            'name': name,
            'description': 'Портировано с Cisco FPR.',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        url_list = {
            'name': name,
            'description': 'Портировано с Cisco FPR.',
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': []
        }
        line = fh.readline()
        y = line.translate(trans_table).rstrip().split(' ')
        while y[0] == '':
            match y[1]:
                case 'network-object':
                    if y[2] == 'object':
                        if y[3] in data['url_lists']:
                            url_list['content'].extend(data['url_lists'][y[3]]['content'])
                        else:
                            ip_list['content'].append({'list': y[3]})
                    elif y[2] == 'host':
                        ip_list['content'].append({'value': f'{y[3]}'})
                    else:
                        try:
                            error, ip = func.pack_ip_addr(y[2], y[3])
                            if error:
                                parent.stepChanged.emit(f"RED|    Error: строка '{' '.join(y)}' не может быть обработана [{ip}].")
                                error = 1
                            else:
                                ip_list['content'].append({'value': ip})
                        except IndexError as err:
                            parent.stepChanged.emit(f"RED|    Error: строка '{' '.join(y)}' не может быть обработана [{err}].")
                            error = 1
                case 'group-object':
                    if y[2] in data['url_lists']:
                        url_list['content'].extend(data['url_lists'][y[2]]['content'])
                    if y[2] in data['ip_lists']:
                        ip_list['content'].append({'list': y[2]})
                case 'description':
                    ip_list['description'] = f"{ip_list['description']}\n{' '.join(y[2:])}"
                    url_list['description'] = f"{url_list['description']}\n{' '.join(y[2:])}"
            line = fh.readline()
            y = line.translate(trans_table).rstrip().split(' ')
        if ip_list['content']:
            data['ip_lists'][name] = ip_list
        if url_list['content']:
            data['url_lists'][name] = url_list
        return line        

    def convert_service_object(name, fh):
        service = {
            'name': name,
            'description': 'Портировано с Cisco FPR.',
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
            'description': 'Портировано с Cisco FPR.',
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
                    service['description'] = f"{service['description']}\n{' '.join(y[2:])}"
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
                    service['description'] = f"{service['description']}\n{' '.join(y[2:])}"

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
            'name': func.get_restricted_name(rule_name),
            'description': 'Портировано с Cisco FPR.',
            'action': '',
            'src_zones': set(),
            'dst_zones': set(),
            'src_ips': set(),
            'dst_ips': set(),
            'services': set(),
            'enabled': True,
            'time_restrictions': []
        }

        line = fh.readline()
        x = line.translate(trans_table).rstrip().split(' ')
        while x[0] == 'access-list' and x[1] == 'CSM_FW_ACL_' and x[2] == 'advanced':
            service_name = ''
            service = {
                'name': '',
                'description': 'Портировано с Cisco FPR.',
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

            for i in range(len(y)):
                if y[i] in ('host', 'object', 'object-group', 'any'):
                    if y[i] == 'any':
                        continue
                    if i == 0:
                        list_name = add_ip_list(y[1]) if y[0] == 'host' else y[1]
                        fw_rule['src_ips'].add(list_name)
                    elif i == 2:
                        list_name = add_ip_list(y[3]) if y[2] == 'host' else y[3]
                        fw_rule['dst_ips'].add(list_name)
                    else:
                        if y[i+1] in data['services']:
                            fw_rule['services'].add(y[i+1])
                        else:
                            list_name = add_ip_list(y[i+1]) if y[i] == 'host' else y[i+1]
                            fw_rule['dst_ips'].add(list_name)
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
                        fw_rule['src_ips'].add(add_ip_list(y[0], mask=y[1], obj='subnet'))
                    elif i == 2:
                        fw_rule['dst_ips'].add(add_ip_list(y[2], mask=y[3], obj='subnet'))
                    elif i == 4:
                        fw_rule['dst_ips'].add(add_ip_list(y[4], mask=y[5], obj='subnet'))
                elif y[i] == 'time-range':
                    fw_rule['time_restrictions'].append(y[i+1])
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

    def add_remark_to_fw_rules(rule_id, remark):
        """Ремарки занести в описание правила fw"""
        if data['fw_rules'][rule_id]['description']:
            data['fw_rules'][rule_id]['description'] += f"\n{remark}"
        else:
            data['fw_rules'][rule_id]['description'] += f"{remark}"

    def convert_routes_list(route_line):
        """Выгрузить список маршрутов"""
        route = {
            'enabled': True,
            'name': '',
            'description': 'Портировано с Cisco FPR.',
            'dest': '',
            'gateway': '',
            'ifname': 'undefined',
            'kind': 'unicast',
            'metric': 0
        }
        gateway = {
            'name': '',
            'enabled': True,
            'description': 'Портировано с Cisco FPR.',
            'ipv4': '',
            'vrf': 'default',
            'weight': 1,
            'multigate': False,
            'default': False,
            'iface': 'undefined',
            'is_automatic': False
        }
        try:
            error, interface = func.pack_ip_addr(route_line[2], route_line[3])
            if error:
                parent.stepChanged.emit(f'RED|    Error: {interface}. Маршрут "{" ".join(route_line)}" не конвертирован.')
                error = 1
            else:
                if interface == '0.0.0.0/0':
                    gateway['name'] = route_line[1]
                    gateway['ipv4'] = route_line[4]
                    if len(route_line) >= 6:
                        gateway['weight'] = int(route_line[5])
                    data['gateways'].append(gateway)
                else:
                    route['dest'] = interface
                    route['name'] = f'{route_line[1]} - {route["dest"]}'
                    route['gateway'] = route_line[4]
                    if len(route_line) == 6:
                        route['metric'] = int(route_line[5])
                    data['routes'].append(route)
        except IndexError as err:
            parent.stepChanged.emit(f'RED|    Error: {err}. Маршрут "{" ".join(route_line)}" не конвертирован.')
            error = 1

    with open(fpr_config_file, "r") as fh:
        line = fh.readline()
        while line:
            if line.startswith(':'):
                line = fh.readline()
                continue
            x = line.translate(trans_table).rsplit(' ')
            match x[0]:
                case 'dns':
                    match x[1:]:
                        case ['domain-lookup', zone_name]:
                            data['dns']['domain-lookup'].append(zone_name)
                        case ['server-group', servergroup_name]:
                            line, tmp_block = get_block(fh)
                            create_dns_rules(data, servergroup_name, tmp_block)
                            continue
                        case 'forwarder':
                            pass
                case 'interface':
                    line = convert_interface(x[1], line, fh)
                case 'ip':
                     if x[1] == 'local' and x[2] == 'pool':
                        convert_local_pool(x)
                case 'object':
                    if x[1] == 'network':
                        line = convert_network_object(x[2], fh)
                    if x[1] == 'service':
                        line = convert_service_object(x[2], fh)
                case 'object-group':
                    if x[1] == 'network':
                        line = convert_network_object_group(x[2], fh)
                        continue
                    if x[1] == 'service':
                        line = convert_service_object_group(line, fh)
                        continue
                    if x[1] == 'icmp-type':
                        line = convert_icmp_object_group(x[2], fh)
                        continue
                case 'access-list':
                     if x[1] == 'CSM_FW_ACL_' and x[2] == 'remark' and x[5] in ('RULE:', 'L7', 'L4'):
                        line = convert_access_list(int(x[4][:-1]), ' '.join(x[6:]), fh)
                        continue
                case 'mtu':
                    if x[1].lower() != 'management':
                        data['zones'].append(x[1].replace('_', ' ').translate(trans_name))
                case 'dhcprelay':
                    if x[1] == 'server':
                        zone_name = x[3].replace('_', ' ')
                        if zone_name in data['dhcp_relay']:
                            data['dhcp_relay'][zone_name].append(x[2])
                        else:
                            data['dhcp_relay'][zone_name] = [x[2]]
                case 'route':
                    convert_routes_list(x)
                case 'time-range':
                    line, tmp_block = get_block(fh)
                    data['time-range'][x[1].translate(trans_name)] = tmp_block
                    continue
            line = fh.readline()

    with open(fpr_config_file, "r") as fh:
        line = fh.readline()
        while line:
            if line.startswith(':'):
                line = fh.readline()
                continue
            x = line.translate(trans_table).rsplit(' ')
            if x[0] == 'access-list' and x[1] == 'CSM_FW_ACL_' and x[2] == 'remark':
                add_remark_to_fw_rules(int(x[4][:-1]), ' '.join(x[5:]))
            line = fh.readline()

    json_file = os.path.join(path, 'cisco_fpr.json')
    with open(json_file, "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'BLACK|    Конфигурация Cisco FPR в формате json выгружена в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Cisco FPR в формат json.' if error else out_message)


def get_block(fh):
    """Читаем файл и создаём блок записей для раздела конфигурации"""
    block = []
    line = fh.readline()
    while line.startswith(' '):
        block.append(line.translate(trans_table).strip().split(' '))
        line = fh.readline()
    return line, block


def create_dns_rules(data, rule_name, data_block):
    """
    Если в data_block нет domain-name, создаём системные DNS-сервера.
    Если есть, создаём правило DNS прокси "Сеть/DNS/DNS-прокси/Правила DNS".
    """
    dns_rule = {
        'name': rule_name,
        'domains': [],
        'dns_servers': []
    }
    for item in data_block:
        match item[0]:
            case 'name-server':
                dns_rule['dns_servers'].append(item[1])
            case 'domain-name':
                dns_rule['domains'].append(f'*.{item[1]}')
    if dns_rule['domains']:
        data['dns']['dns_rules'].append(dns_rule)
    else:
        for x in dns_rule['dns_servers']:
            data['dns']['system_dns'].append(x)

#------------------------------------------- Конвертация -----------------------------------------------
def convert_zones(parent, path, data):
    """Конвертируем зоны."""
    parent.stepChanged.emit('BLUE|Конвертация Зон.')

    zones = []
    for item in data['zones']:
        zone = {
            'name': item,
            'description': 'Портировано с Cisco FPR.',
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
                },
                {
                'enabled': False,
                'service_id': 'DNS',
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
        if data['dns']['domain-lookup']:
            for zone_name in data['dns']['domain-lookup']:
                if item == zone_name:
                    for service in zone['services_access']:
                        if service['service_id'] == 'DNS':
                            service['enabled'] = True
                            break

        zones.append(zone)
        parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" конвертирована.')

    if zones:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Zones')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_zones.json')
        with open(json_file, "w") as fh:
            json.dump(zones, fh, indent=4, ensure_ascii=False)

        parent.stepChanged.emit(f'GREEN|    Конфигурация Зон выгружена в файл "{json_file}".')
        parent.stepChanged.emit('LBLUE|    Необходимо настроить каждую зону. Включить нужный сервис в контроле доступа, поменять по необходимости параметры защиты от DoS и настроить защиту от спуфинга.')
    else:
        parent.stepChanged.emit('GRAY|    Нет зон для экспорта.')


def convert_dns_servers(parent, path, system_dns):
    """Заполняем список системных DNS"""
    parent.stepChanged.emit('BLUE|Конвертация системных DNS-серверов.')
    if system_dns:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        dns_servers = []
        for ip in system_dns:
            dns_servers.append({
                'dns': ip,
                'is_bad': False
            })

        json_file = os.path.join(current_path, 'config_dns_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Системные DNS-сервера выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет системных DNS-серверов для экспорта.')


def convert_dns_rules(parent, path, dns_rules):
    """Создаём правило DNS прокси Сеть/DNS/DNS-прокси/Правила DNS"""
    parent.stepChanged.emit('BLUE|Конвертация правил DNS в DNS-прокси.')
    if dns_rules:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        rules = []
        for item in dns_rules:
            rules.append({
                'name': item['name'],
                'description': 'Перенесено с Cisco FPR',
                'enabled': True,
                'position': 'last',
                'domains': item['domains'],
                'dns_servers': item['dns_servers']
            })

        json_file = os.path.join(current_path, 'config_dns_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Правила DNS выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет правил DNS для экспорта.')


def convert_gateways(parent, path, gateways):
    """Выгружаем шлюзы в файл json"""
    parent.stepChanged.emit('BLUE|Конвертация шлюзов.')

    if gateways:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Gateways')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_gateways.json')
        with open(json_file, "w") as fh:
            json.dump(gateways, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список шлюзов выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')


def convert_static_routes(parent, path, static_routes):
    """Конвертируем статические маршруты"""
    parent.stepChanged.emit('BLUE|Конвертация статических маршрутов.')

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

        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'VRF')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_vrf.json')
        with open(json_file, "w") as fh:
            json.dump(vrf_info, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Статические маршруты добавлены в виртуальный маршрутизатор по умолчанию в файле "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


def convert_vlan_interfaces(parent, path, data):
    """Конвертируем интерфейсы VLAN"""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')

    if data['ifaces']:
        for iface in data['ifaces']:
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

            if iface['zone_id'] in data['dhcp_relay']:
                iface['dhcp_relay']['enabled'] = True
                iface['dhcp_relay']['servers'] = data['dhcp_relay'][iface['zone_id']]

        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Interfaces')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_interfaces.json')
        with open(json_file, "w") as fh:
            json.dump(data['ifaces'], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Интерфейсы VLAN выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')


def convert_ip_lists(parent, path, list_ips):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')

    if list_ips:
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
            time.sleep(0.1)

        parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


def convert_url_lists(parent, path, list_urls):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков URL.')

    if list_urls:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'URLLists')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        for key, value in list_urls.items():
            json_file = os.path.join(current_path, f'{key.translate(trans_filename)}.json')
            with open(json_file, "w") as fh:
                json.dump(value, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список URL "{key}" выгружен в файл "{json_file}".')
            time.sleep(0.1)

        parent.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


def convert_service_groups(parent, path, services):
    """Конвертируем группы сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация групп сервисов.')

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
            parent.stepChanged.emit(f'BLACK|    Создана группа сервисов "{srv_group["name"]}".')
            time.sleep(0.1)

    if services_groups:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'ServicesGroups')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_groups_list.json')
        with open(json_file, "w") as fh:
            json.dump(services_groups, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Группы сервисов выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')


def convert_services_list(parent, path, services):
    """Конвертируем список сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация списка сервисов.')

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

    if services_list:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'Services')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, "w") as fh:
            json.dump(services_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список сервисов выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет сервисов для экспорта.')


def convert_time_sets(parent, path, data):
    """Конвертируем time set (календари)"""
    parent.stepChanged.emit('BLUE|Конвертация календарей.')
    if not data['time-range']:
        parent.stepChanged.emit(f'GRAY|    Нет календарей для экспорта.')
        return

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'TimeSets')
    err, msg = func.create_dir(current_path)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {msg}.')
        return

    week = {
        'Monday': 1,
        'Tuesday': 2,
        'Wednesday': 3,
        'Thursday': 4,
        'Friday': 5,
        'Saturday': 6,
        'Sunday': 7
    }
    time_rules = []

    for rule_name, content in data['time-range'].items():
        rule = {
            'name': rule_name,
            'description': 'Перенесено с Cisco FPR',
            'type': 'timerestrictiongroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': []
        }
        i = 0
        for item in content:
            i += 1
            time_set = {
                'name': f'{rule_name} {i}',
                'type': 'span' if item[0] == 'absolute' else 'weekly'
            }
            match item:
                case ['absolute', 'start' | 'end', time, day, month, year]:
                    if item[1] == 'start':
                        time_set['time_from'] = time
                        time_set['fixed_date_from'] = f'{year}-{MONTHS[month]}-{day}T00:00:00'
                    elif item[1] == 'end':
                        time_set['time_to'] = time
                        time_set['fixed_date_to'] = f'{year}-{MONTHS[month]}-{day}T00:00:00'
                case ['absolute', 'start', start_time, start_day, start_month, start_year, 'end', end_time, end_day, end_month, end_year]:
                    time_set['time_from'] = start_time
                    time_set['fixed_date_from'] = f'{start_year}-{MONTHS[start_month]}-{start_day}T00:00:00'
                    time_set['time_to'] = end_time
                    time_set['fixed_date_to'] = f'{end_year}-{MONTHS[end_month]}-{end_day}T00:00:00'
                case ['absolute', 'end', end_time, end_day, end_month, end_year, 'start', start_time, start_day, start_month, start_year]:
                    time_set['time_from'] = start_time
                    time_set['fixed_date_from'] = f'{start_year}-{MONTHS[start_month]}-{start_day}T00:00:00'
                    time_set['time_to'] = end_time
                    time_set['fixed_date_to'] = f'{end_year}-{MONTHS[end_month]}-{end_day}T00:00:00'
                case ['periodic', *other]:
                    if other[0] in ('weekend', 'weekdays', 'daily'):
                        time_set['time_from'] = other[1] if other[1] != 'to' else '00:00'
                        time_set['time_to'] = other[len(other)-1]
                        if other[0] == 'daily':
                            time_set['type'] = 'daily'
                        else:
                            time_set['days'] = [6, 7] if other[0] == 'weekend' else [1, 2, 3, 4, 5]
                    else:
                        start, end = other[:other.index('to')], other[other.index('to')+1:]
                        days = set()
                        for x in start:
                            if week.get(x, None):
                                days.add(week[x])
                            else:
                                time_set['time_from'] = x
                        for x in end:
                            if week.get(x, None):
                                days = {y for y in range(min(days), week[x]+1)}
                            else:
                                time_set['time_to'] = x
                        if not time_set.get('time_from', None):
                            time_set['time_from'] = "00:00"
                        if not time_set.get('time_to', None):
                            time_set['time_to'] = "23:59"
                        if days:
                            time_set['days'] = sorted(list(days))
                        else:
                            time_set['type'] = 'daily'
            rule['content'].append(time_set)
        time_rules.append(rule)

    if time_rules:
        json_file = os.path.join(current_path, 'config_calendars.json')
        with open(json_file, 'w') as fh:
            json.dump(time_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет календарей для экспорта.')


def convert_firewall_rules(parent, path, data):
    """Конвертируем правила межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'Firewall')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    services_list = data['services']
    firewall_rules = []
    for key, value in data['fw_rules'].items():
        value['src_ips'] = get_ips(data, value['src_ips'])
        value['dst_ips'] = get_ips(data, value['dst_ips'])
        value['services'] = [['list_id', x] if services_list[x]['group'] else ['service', x] for x in value['services']]
        value['scenario_rule_id'] = False
        value['users'] = []
        value['limit'] = False
        value['limit_value'] = '3/h'
        value['limit_burst'] = 5
        value['log'] = False
        value['log_session_start'] = False
        value['src_zones_nagate'] = False
        value['dst_zones_nagate'] = False
        value['src_ips_nagate'] = False
        value['dst_ips_nagate'] = False
        value['services_nagate'] = False
        value['fragmented'] = 'ignore'
        value['send_host_icmp'] = ''
        value['position_layer'] = 'local'
        value['ips_profile'] = False
        value['l7_profile'] = False
        value['hip_profiles'] = []

        firewall_rules.append(value)
        parent.stepChanged.emit(f'BLACK|    Создано правило межсетевого экрана "{value["name"]}".')
        time.sleep(0.1)

    json_file = os.path.join(current_path, 'config_firewall_rules.json')
    with open(json_file, "w") as fh:
        json.dump(firewall_rules, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список правил межсетевого экрана выгружен в файл "{json_file}".'
    parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.' if not firewall_rules else out_message)


def get_ips(data, rule_ips):
    """Получаем список IP-адресов и URL-листов"""
    new_rule_ips = []
    if rule_ips:
        for item in rule_ips:
            if item in data['ip_lists']:
                new_rule_ips.append(['list_id', item])
            if item in data['url_lists']:
                new_rule_ips.append(['urllist_id', item])
    return new_rule_ips


def main():
    pass

if __name__ == '__main__':
    main()
