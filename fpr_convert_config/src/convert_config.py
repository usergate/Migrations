#!/usr/bin/python3
#
# asa_convert_config (convert Cisco FPR NGFW configuration to NGFW UserGate).
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
# Программа предназначена для переноса конфигурации с устройств Cisco FPR-2130 на NGFW UserGate версии 6.
# Версия 1.4
#

import os, sys, json, re
import stdiomask
import ipaddress
from pprint import pprint
from services import character_map, network_proto, service_ports
from utm import UTM

revers_service_ports = {v: k for k, v in service_ports.items()}
pattern = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')

def convert_file(file_name):
    """Преобразуем файл конфигурации Cisco FPR-2130 в json."""
    print('\033[32mПреобразование файла конфигурации Cisco FPR в json.\033[0m')

    trans_table = str.maketrans(character_map)
    data = {
        'ip_lists': {},
        'services': {},
        'ifaces': [],
        'zones': [],
        'fw_rules': {},
        'routes': []
    }

    def add_ip_list(ip, mask='255.255.255.255', obj='host'):
        ip_list = {
            'name': '',
            'description': '',
            'type': 'network',
            'url': '',
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
            'attributes': {
                'threat_level': 3
            },
            'content': [{'value': x[4]}]
        }
        data['ip_lists'][x[3]] = ip_list

    def convert_interface(ifname, line, fh):
        iface = {
            'name': ifname,
            'zone_id': '',
            'master': False,
            'netflow_profile': 'undefined',
            'tap': False,
            'enabled': False,
            'kind': '',
            'mtu': 1500,
            'running': False,
            'dhcp_relay': {
                'enabled': False,
                'host_ipv4': '',
                'servers': []
            },
            'mode': 'static',
        }
        while not line.startswith('!'):
            y = line.translate(trans_table).strip().split(' ')
            if y[0] == 'vlan':
                iface['kind'] = 'vlan'
                iface['vlan_id'] = int(y[1])
            elif y[0] == 'nameif':
                iface['zone_id'] = y[1]
            elif y[0] == 'ip' and y[1] == 'address':
                ip_address = ipaddress.ip_interface(f'{y[2]}/{y[3]}')
                iface['ipv4'] = [f'{y[2]}/{ip_address.network.prefixlen}']
            elif y[0] == 'description':
                iface['description'] = y[1]
            line = fh.readline()
        if iface['kind'] == 'vlan':
            data['ifaces'].append(iface)
        return line

    def convert_dhcprelay(server_ip, zone_name):
        for iface in data['ifaces']:
            if iface['zone_id'] == zone_name:
                iface['dhcp_relay']['enabled'] = True
                iface['dhcp_relay']['servers'].append(server_ip)

    def convert_network_object(name, fh):
        ip_list = {
            'name': name,
            'description': '',
            'type': 'network',
            'url': '',
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
                    ip_list['content'].extend(data['ip_lists'][y[3]]['content'])
                elif y[2] == 'host':
                    ip_list['content'].append({'value': f'{y[3]}'})
                else:
                    try:
                        subnet = ipaddress.ip_network(f'{y[2]}/{y[3]}')
                        ip_list['content'].append({'value': f'{y[2]}/{subnet.prefixlen}'})
                    except IndexError:
                        print(f"\tОшибка: строка '{' '.join(y)}' не может быть обработана!")
            elif y[1] == 'group-object':
                ip_list['content'].extend(data['ip_lists'][y[2]]['content'])
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
            'protocols': []
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
            'protocols': []
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
                                print(f"\tОшибка: не найден порт {err} в сервисе '{' '.join(x)}'")
                                while True:
                                    port_number = input(f'\t\033[36mВведите номер порта для сервиса {err}:\033[0m')
                                    if not port_number.isdigit() or (int(port_number) > 65535) or (int(port_number) < 1):
                                        print('\t\033[31mНеверно, номер порта должен быть цифрой между 1 и 65535.\033[0m')
                                    else:
                                        y[indx+3] = port_number
                                        break
                    for proto in proto_array:
                        service['protocols'].append(
                                {
                                    'proto': proto,
                                    'port': f'{y[3]}-{y[4]}' if y[2] == 'range' else y[3],
                                    'source_port': '',
                                 }
                            )
                elif y[1] == 'group-object':
                    try:
                        service['protocols'].extend(data['services'][y[2]]['protocols'])
                    except KeyError as err:
                        print(f"\t\033[31mОшибка: не найден group-object {err} в сервисе '{' '.join(x)}'\033[0m")
                        print(y)
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
                        service['protocols'].extend(data['services'][y[2]]['protocols'])
                    except KeyError as err:
                        print(f"\t\033[31mОшибка: не найден group-object {err} в сервисе '{' '.join(x)}'\033[0m")
                        print(y)
                elif y[1] == 'description':
                    service['description'] = ' '.join(y[2:])

                line = fh.readline()
                y = line.translate(trans_table).rstrip().split(' ')


        data['services'][x[2]] = service
        return line

    def convert_icmp_object_group(name, fh):
        service = {
            'name': 'Any ICMP',
            'description': '',
            'protocols': [
                {
                    'proto': 'icmp',
                    'port': '',
                    'source_port': '',
                }
            ]
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
            'name': rule_name,
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
                ]
            }
            if not rule_id == int(x[x.index('rule-id') + 1]):
                print(f'\t\033[31mОшибка: "{line}" не обработано!\033[0m')
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
                fw_rule['src_zones'].add(x[6])
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
                    fw_rule['dst_zones'].add(y[i+1])
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

#            pprint(fw_rule, sort_dicts=False)

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
            print(f'\t\033[33mОшибка: {err}. Маршрут "{" ".join(route_line)}" не конвертирован.\033[0m')
        else:
            data['routes'].append(route)

    def add_remark_to_fw_rules(rule_id, remark):
        """Ремарки занести в описание правила fw"""
        data['fw_rules'][rule_id]['description'] += f"{remark} -- "

    if os.path.isdir('data_ca'):
        with open(f"data_ca/{file_name}.txt", "r") as fh:
            line = fh.readline()
            while line:
                if line.startswith(':'):
                    line = fh.readline()
                    continue
                x = line.translate(trans_table).rsplit(' ')
                if x[0] == 'interface':
                    line = convert_interface(x[1], line, fh)
                elif x[0] == 'ip' and x[1] == 'local' and x[2] == 'pool':
                    convert_local_pool(x)
                elif x[0] == 'object':
                    if x[1] == 'network':
                        line = convert_network_object(x[2], fh)
                    if x[1] == 'service':
                        line = convert_service_object(x[2], fh)
                elif x[0] == 'object-group':
                    if x[1] == 'network':
                        line = convert_network_object_group(x[2], fh)
                        continue
                    if x[1] == 'service':
                        line = convert_service_object_group(line, fh)
                        continue
                    if x[1] == 'icmp-type':
                        line = convert_icmp_object_group(x[2], fh)
                        continue
                elif x[0] == 'access-list' and x[1] == 'CSM_FW_ACL_' and x[2] == 'remark' and x[5] in ('RULE:', 'L7', 'L4'):
                    line = convert_access_list(int(x[4][:-1]), ' '.join(x[6:]), fh)
                    continue
                elif x[0] == 'mtu':
                    if x[1].lower() != 'management':
                        data['zones'].append(x[1])
                elif x[0] == 'dhcprelay':
                    if x[1] == 'server':
                        convert_dhcprelay(x[2], x[3])
                elif x[0] == 'route':
                    convert_routes_list(x)
                line = fh.readline()
                
        with open(f"data_ca/{file_name}.txt", "r") as fh:
            line = fh.readline()
            while line:
                if line.startswith(':'):
                    line = fh.readline()
                    continue
                x = line.translate(trans_table).rsplit(' ')
                if x[0] == 'access-list' and x[1] == 'CSM_FW_ACL_' and x[2] == 'remark':
                    add_remark_to_fw_rules(int(x[4][:-1]), ' '.join(x[5:]))
                line = fh.readline()

            
    else:
        print(f'Не найден каталог с конфигурацией Cisco FPR.')
        return

    with open(f"data_ca/{file_name}.json", "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)
    print('\033[32mПреобразование завершено.\033[0m')

######################################## Импорт ####################################################
def import_list_ips(utm, list_ips):
    """Импортировать списки IP адресов"""
    print('\033[32mИмпорт списков IP-адресов раздела "Библиотеки":\033[0m')

    if not list_ips:
        print("\tНет списков IP-адресов для импорта.")
        return

    utm_list_ips = utm.get_nlists_list('network')

    for item in list_ips.values():
        if item['name'] in utm_list_ips:
            print(f'\tСписок "{item["name"]}" уже существует.')
            continue
        content = item.pop('content')
        err, result = utm.add_nlist(item)
        if err == 1:
            print(f'\t{result}')
        elif err == 2:
            print(f"\033[31m\t{result}\033[0m")
            continue
        else:
            utm_list_ips[item['name']] = result
            print(f'\tДобавлен список IP-адресов: "{item["name"]}".')
        if content:
            err2, result2 = utm.add_nlist_items(utm_list_ips[item['name']], content)
            if err2 != 0:
                print(f'\033[31m\t{result2}\033[0m')
            else:
                print(f'\tСодержимое списка "{item["name"]}" обновлено. Added {result2} record.')
        else:
            print(f'\tСписок "{item["name"]}" пуст.')

def import_services(utm, services):
    """Импортировать список сервисов раздела библиотеки"""
    print('\n\033[32mИмпорт списка сервисов раздела "Библиотеки":\033[0m')
    services_list = utm.get_services_list()

    for item in services.values():
        if item['name'] in services_list:
            print(f'\tСервис "{item["name"]}" уже существует.')
            continue
        protocols = []
        for val in item['protocols']:
            if val['proto'] in network_proto:
                protocols.append(val)
            elif val['proto'] in ('tcp', 'udp'):
                if val['port']:
                    if val['port'] in service_ports or val['port'].split('-')[0].isdigit():
                        val['port'] = service_ports.get(val['port'], val['port'])
                    else:
                        print(f'\t\033[33mПротокол "{val["port"]}" в сервисе "{item["name"]}" не импортирован!\033[0m')
                        continue
                if val['source_port']:
                    if val['source_port'] in service_ports or val['source_port'].split('-')[0].isdigit():
                        val['source_port'] = service_ports.get(val['source_port'], val['source_port'])
                    else:
                        print(f'\t\033[33mПротокол "{val["source_port"]}" в сервисе "{item["name"]}" не импортирован!\033[0m')
                        continue
                protocols.append(val)
        if protocols:
            item['protocols'] = protocols
            err, result = utm.add_service(item)
            if err != 0:
                print(f'\033[31m\t{result}\033[0m')
            else:
                services_list[item['name']] = result
                print(f'\tСервис "{item["name"]}" добавлен.')

def import_zones(utm, zones):
    """Импортировать зоны на UTM"""
    print('\n\033[32mИмпорт списка "Зоны" раздела "Сеть":\033[0m')
    zones_list = utm.get_zones_list()

    for item in zones:
        if item in zones_list:
            print(f'\tЗона "{item}" уже существует.')
            continue
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
                'service_id': 1,
                'allowed_ips': []
                },
                {
                'enabled': True,
                'service_id': 12,
                'allowed_ips': []
                },
                {
                'enabled': True,
                'service_id': 13,
                'allowed_ips': []
                }
            ],
            'readonly': False,
            'enable_antispoof': False,
            'antispoof_invert': False,
            'networks': [],
            'cc': False
        }
        err, result = utm.add_zone(zone)
        if err == 1:
            print(f'\t{result}')
        elif err == 2:
            print(f'\033[31m\t{result}\033[0m')
        else:
            zones_list[item] = result
            print(f'\tЗона "{item}" добавлена.')
    print('\033[36;1mВнимание:\033[0m \033[36mНеобходимо настроить каждую зону. Включить нужный сервис в контроле доступа,')
    print('поменять по необходимости параметры защиты от DoS и настроить защиту от спуфинга.\033[0m')

def import_interfaces(utm, ifaces):
    """Импортировать интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    print('\n\033[32mИмпорт VLAN в раздела "Сеть/Интерфейсы":\033[0m')

    management_port = ''
    vlan_list = []
    interfaces_list = {}
    zones_list = utm.get_zones_list()

    # Составляем список легитимных интерфейсов.
    result = utm.get_interfaces_list()
    for item in result:
        if item['kind'] == 'vlan':
            vlan_list.append(item['name'])
        for ip in item['ipv4']:
            if ip.startswith(utm.server_ip):
                management_port = item["name"]
                print(f'\tИнтерфейс "{item["name"]}" [{utm.server_ip}] используется для текущей сессии.')
                print('\tОн не будет использоваться для создания интерфейсов VLAN.\n')
        if item['kind'] not in ('bridge', 'bond', 'adapter') or item['master']:
            continue
        if item["name"] == management_port:
            continue
        interfaces_list[item['name']] = item['kind']

    for item in ifaces:
        print(f'\t\033[36mВы добавляете VLAN\033[0m "{item["name"]}" \033[36mНеобходимо выбрать интерфейс для создания VLAN.')
        print(f'\tСуществуют следующие интерфейсы:\033[0m {sorted(interfaces_list.keys())}')
        while True:
            port = input('\n\t\033[36mВведите название интерфейса: \033[0m')
            if port not in interfaces_list.keys():
                print('\033[31m\tВы ввели название не легитимного интерфейса.\033[0m')
            else:
                break
        item['link'] = port
        item['description'] = item['name']
        item['name'] = f'{port}.{item["vlan_id"]}'

        if item['kind'] == 'vlan' and item['link'] != management_port:
            if item['link'] not in interfaces_list:
                print(f'\t\033[33mСетевой адаптер "{item["link"]}" не существует - VLAN "{item["name"]}" создан не будет!\033[0m')
                continue

        if item['zone_id']:
            try:
                item['zone_id'] = zones_list[item['zone_id']]
            except KeyError as err:
                print(f'\t\033[33mЗона {err} для интерфейса "{item["name"]}" не найдена.\n\tСоздайте зону {err} и присвойте этому VLAN.\033[0m')
                item['zone_id'] = 0

        if item['name'] in vlan_list:
            print(f'\tИнтерфейс "{item["name"]}" уже существует', end= ' - ')
            item.pop('vlan_id')
            utm.update_interface(item['name'], item)
        else:
            item.pop('kind')
            err, result = utm.add_interface_vlan(item)
            if err == 2:
                print(f'\033[33m\tИнтерфейс "{item["name"]}" не добавлен!\033[0m')
                print(f"\033[31m\t{result}\033[0m")
            else:
                vlan_list.append(item['name'])
                print(f'\033[32m\tИнтерфейс "{item["name"]}" добавлен.\033[0m\n')

def import_firewall_rules(utm, fw_rules):
    """Импортировать список правил межсетевого экрана"""
    print(f'\n\033[32mИмпорт правил межсетевого экрана раздела "Политики сети":\033[0m')
    if not fw_rules:
        print("\tНет правил межсетевого экрана для импорта.")
        return

    rules_list = utm.get_firewall_rules()
    services_list = utm.get_services_list()
    zones_list = utm.get_zones_list()
    ip_list = utm.get_nlists_list('network')
#    list_users = utm.get_users_list()
#    list_groups = utm.get_groups_list()
#    l7_categories = utm.get_l7_categories()
#    applicationgroup = utm.get_nlists_list('applicationgroup')
#    l7_apps = utm.get_l7_apps()

    for item in fw_rules.values():
        if item['name'] in rules_list:
            print(f'\tПравило "{item["name"]}" уже существует.')
            continue
#        get_guids_users_and_groups(utm, item, list_users, list_groups)
        set_src_zone_and_ips(item, zones_list, ip_list)
        set_dst_zone_and_ips(item, zones_list, ip_list)
        try:
            item['services'] = [services_list[x] for x in item['services']]
        except KeyError as err:
            print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
            item['services'] = []
#        try:
#            set_apps(item['apps'], l7_categories, applicationgroup, l7_apps)
#        except KeyError as err:
#            print(f'\t\033[33mНе найдено приложение {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
#            item['apps'] = []

        item['description'] = ''
        item['scenario_rule_id'] = False
        item['apps'] = []
        item['users'] = []
        item['limit'] = True
        item['limit_value'] = '3/h'
        item['burst'] = 5
        item['log'] = False
        item['log_session_start'] = False
        item['src_zones_negate'] = False
        item['dst_zones_negate'] = False
        item['src_ips_negate'] = False
        item['dst_ips_negate'] = False
        item['services_negate'] = False
        item['apps_negate'] = False
        item['fragmented'] = 'ignore'
        item['time_restrictions'] = []
        item['active'] = True
        item['send_host_icmp'] = ''

#            print(f'\tПравило МЭ "{item["name"]}" уже существует', end= ' - ')
#            err1, result1 = utm.update_firewall_rule(rules_list[item['name']], item)
#            if err1 != 0:
#                print("\n", f"\033[31m{result1}\033[0m")
#            else:
#                print("\033[32mUpdated!\033[0;0m")

        err, result = utm.add_firewall_rule(item)
        if err != 0:
            print(f"\033[31m{result}\033[0m")
        else:
            rules_list[item["name"]] = result
            print(f'\tПравило МЭ "{item["name"]}" добавлено.')

def import_routes(utm, static_routes):
    """Импортировать список статических маршрутов"""
    print(f'\n\033[32mИмпорт списка статических маршрутов в раздел "Сеть/Виртуальные маршрутизаторы":\033[0m')
    if not static_routes:
        print("\tНет статических маршрутов для импорта.")
        return

    virt_router = {
        'name': 'default',
        'routes': static_routes,
    }

    virt_routers = {x['name']: x['id'] for x in utm.get_routers_list()}

    err, result = utm.update_routers(virt_routers['default'], virt_router)
    if err == 2:
        print(f'\033[31m{result}\033[0m')
    else:
        print(f'\tСтатические маршруты добавлены в виртуальный маршрутизатор по умолчанию.')

def set_src_zone_and_ips(item, zones, list_ip={}, list_url={}):
    if item['src_zones']:
        try:
            item['src_zones'] = [zones[x] for x in item['src_zones']]
        except KeyError as err:
            print(f'\t\033[33mИсходная зона {err} для правила "{item["name"]}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
            item['src_zones'] = []
    if item['src_ips']:
        try:
            for x in item['src_ips']:
                if x[0] == 'list_id':
                    x[1] = list_ip[x[1]]
                elif x[0] == 'urllist_id':
                    x[1] = list_url[x[1]]
        except KeyError as err:
            print(f'\t\033[33mНе найден адрес источника {err} для правила "{item["name"]}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
            item['src_ips'] = []

def set_dst_zone_and_ips(item, zones, list_ip={}, list_url={}):
    if item['dst_zones']:
        try:
            item['dst_zones'] = [zones[x] for x in item['dst_zones']]
        except KeyError as err:
            print(f'\t\033[33mЗона назначения {err} для правила "{item["name"]}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
            item['dst_zones'] = []
    if item['dst_ips']:
        try:
            for x in item['dst_ips']:
                if x[0] == 'list_id':
                    x[1] = list_ip[x[1]]
                elif x[0] == 'urllist_id':
                    x[1] = list_url[x[1]]
        except KeyError as err:
            print(f'\t\033[33mНе найден адрес назначения {err} для правила "{item["name"]}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
            item['dst_ips'] = []

#def set_apps(array_apps, l7_categories, applicationgroup, l7_apps):
#    """Определяем ID приложения по имени при импорте"""
#    for app in array_apps:
#        if app[0] == 'ro_group':
#            if app[1] == 0:
#                app[1] = "All"
#            elif app[1] == "All":
#                app[1] = 0
#            else:
#                try:
#                    app[1] = l7_categories[app[1]]
#                except KeyError as err:
#                    print(f'\t\033[33mНе найдена категория l7 №{err}.\n\tВозможно нет лицензии, и UTM не получил список категорий l7.\n\tУстановите лицензию и повторите попытку.\033[0m')
#        elif app[0] == 'group':
#            try:
#                app[1] = applicationgroup[app[1]]
#            except KeyError as err:
#                print(f'\t\033[33mНе найдена группа приложений №{err}.\n\tЗагрузите приложения и повторите попытку.\033[0m')
#        elif app[0] == 'app':
#            try:
#                app[1] = l7_apps[app[1]]
#            except KeyError as err:
#                print(f'\t\033[33mНе найдено приложение №{err}.\n\tВозможно нет лицензии, и UTM не получил список приложений l7.\n\tЗагрузите приложения или установите лицензию и повторите попытку.\033[0m')

def menu():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m              Конвертация конфигурации с Cisco FPR на NGFW UserGate             \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ca' в текущей директории на NGFW UserGate.\033[0m\n")
    print('\033[33mПеред запуском конвертации Удостоверьтесь, что:')
    print('\t1. В текущей директории создан каталог "data_ca".')
    print('\t2. Конфигурация Cisco FPR выложена в каталог "data_ca" в текущей директории.')
    print('\t3. Файл конфигурации имеет имя "config_fpr.txt". Если это не так, переименуйте его.')
    print('\t4. Вы подключились к веб-консоли администратора на зоне Management.\033[0m')
    print('\033[36m\nПереносятся настройки:')
    print('\tЗоны                  - "Сеть/Зоны"')
    print('\tИнтерфейсы VLAN       - "Сеть/Интерфейсы"')
    print('\tDHCP-relay            -  на интерфейсах VLAN')
    print('\tСтатические маршруты  - "Сеть/Виртуальные маршрутизаторы"')
    print('\tСписки IP-адресов     - "Библиотеки/IP-адреса"')
    print('\tСервисы               - "Библиотеки/Сервисы"')
    print('\tAccess-lists          - "Политики сети/Межсетевой экран"\033[0m')
    
    while True:
        mode = input('\nДля запуска процесса конвертации введите "yes", для отмены "no": ')
        if mode not in ('yes', 'no'):
            print("Вы ввели несуществующую команду.")
        elif mode == 'no':
            sys.exit()
        else:
            break

def main():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m              Конвертация конфигурации с Cisco FPR на NGFW UserGate             \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ca' в текущей директории на NGFW UserGate.\033[0m\n")
    try:
        menu()
        file_name = 'config_fpr'
        if not os.path.isfile(f'data_ca/{file_name}.txt'):
            print(f'\t\033[31mИмпорт aborted!\n\tНе найден файл "data_ca/config_fpr.txt" с конфигурацией Cisco FPR!\033[0;0m')
            sys.exit(1)

        server_ip = input("\033[36m\nВведите IP-адрес UTM:\033[0m ")
        login = input("\033[36mВведите логин администратора UTM:\033[0m ")
        password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
        print()

        try:
            convert_file(file_name)
        except json.JSONDecodeError as err:
            print(f'\n\033[31mОшибка парсинга конфигурации: {err}\033[0m')
            sys.exit(1)

#        sys.exit(0)

        try:
            with open("data_ca/config_fpr.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mИмпорт aborted!\n\tНе найден файл "data_ca/config_fpr.json" с сохранённой конфигурацией!\033[0;0m')
            sys.exit(1)
        except json.JSONDecodeError as err:
            print(f'\n\033[31mОшибка парсинга конфигурации: {err}\033[0m')
            sys.exit(1)

        try:
            utm = UTM(server_ip, login, password)
            utm.connect()
            import_zones(utm, data['zones'])
            user_input = ''
            while True:
                user_input = input('\n\033[36mБудем переносить интерфейсы VLAN? [yes или no]:\033[0m')
                if user_input not in ('yes', 'no'):
                    print('\033[31m\tНеверно, дожно быть "yes" или "no".\033[0m')
                else:
                    break
            if user_input == 'yes':
                import_interfaces(utm, data['ifaces'])
            import_routes(utm, data['routes'])
            import_list_ips(utm, data['ip_lists'])
            import_services(utm, data['services'])
            import_firewall_rules(utm, data['fw_rules'])
        except Exception as err:
            print(f'\n\033[31mОшибка: {err}\033[0m')
            utm.logout()
            sys.exit(1)
        else:
            utm.logout()
            os.remove(f'data_ca/{file_name}.json')
            print("\n\033[32mИмпорт конфигурации Cisco FPR на NGFW UserGate завершён.\033[0m\n")

    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        sys.exit()

if __name__ == '__main__':
    main()
