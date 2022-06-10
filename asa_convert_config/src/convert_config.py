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
# Программа предназначена для переноса конфигурации с устройств Cisco ASA на NGFW UserGate версии 6.
# Версия 1.0
#

import os, sys, json
import stdiomask
import ipaddress
from services import character_map, character_map_for_users, network_proto, service_ports
from utm import UTM
import colorama

def convert_file(file_name):
    """Преобразуем файл конфигурации Cisco ASA в json."""
    print('Преобразование файла конфигурации Cisco ASA в json.', end=' - ')

    trans_table = str.maketrans(character_map)
    data = {
        'modules': {
            'auth_captive': 'auth.captive',
            'logout_captive': 'logout.captive',
            'block_page_domain': 'block.captive',
            'ftpclient_captive': 'ftpclient.captive',
        },
        'ip_lists': {},
        'services': {},
        'ifaces': [],
        'zones': [],
        'users': [],
    }

    def convert_modules(x):
        data['modules']['auth_captive'] = f'auth.{x[1]}'
        data['modules']['logout_captive'] = f'logout.{x[1]}'
        data['modules']['block_page_domain'] = f'block.{x[1]}'
        data['modules']['ftpclient_captive'] = f'ftpclient.{x[1]}'

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
            'kind': '',
        }
        while not line.startswith('!'):
            y = line.translate(trans_table).strip().split(' ')
            if y[0] == 'vlan':
                iface['kind'] = 'vlan'
                iface['vlan_id'] = y[1]
            elif y[0] == 'nameif':
                iface['zone_id'] = y[1]
            elif y[0] == 'ip' and y[1] == 'address':
                ip_address = ipaddress.ip_interface(f'{y[2]}/{y[3]}')
                iface['ipv4'] = [f'{y[2]}/{ip_address.network.prefixlen}']
            line = fh.readline()
        if iface['kind'] == 'vlan':
            data['ifaces'].append(iface)
        return line

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
                    subnet = ipaddress.ip_network(f'{y[2]}/{y[3]}')
                    ip_list['content'].append({'value': f'{y[2]}/{subnet.prefixlen}'})
            elif y[1] == 'group-object':
                ip_list['content'].extend(data['ip_lists'][y[2]]['content'])
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
                    for proto in proto_array:
                        service['protocols'].append(
                            {
                                'proto': proto,
                                'port': y[3],
                                'source_port': '',
                             }
                        )
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

    if os.path.isdir('data_ca'):
        with open(f"data_ca/{file_name}.txt", "r") as fh:
            line = fh.readline()
            while line:
                if line.startswith(':'):
                    line = fh.readline()
                    continue
                x = line.translate(trans_table).rsplit(' ')
                if x[0] == 'domain-name':
                    convert_modules(x)
                elif x[0] == 'ip' and x[1] == 'local' and x[2] == 'pool':
                    convert_local_pool(x)
                elif x[0] == 'interface':
                    line = convert_interface(x[1], line, fh)
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
                elif x[0] == 'mtu':
                    if x[1].lower() != 'management':
                        data['zones'].append(x[1])
                elif x[0] == 'username':
                    data['users'].append(x[1])
                line = fh.readline()
    else:
        print(f'Не найден каталог с конфигурацией Cisco ASA.')
        return

    data['users'] = list(set(data['users']))

    with open(f"data_ca/{file_name}.json", "w") as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)
    print('\033[32mOk!\033[0m')

def convert_interfaces():
    """
    Выгружаем конфигурацию интерфейсов в файл data_ug/network/config_interfaces.json для последующей загрузки в NGFW.
    """
    print('Экспорт интерфейсов')
    if not os.path.isdir('data_ug/network'):
        os.makedirs('data_ug/network')

    config = []
    try:
        with open("data_cp/config_cp.txt", "r") as fh:
            for line in fh:
                x = line.strip('\n').split(' ')
                if x[0] in ('set', 'add'):
                    config.append(x)
    except FileNotFoundError:
        print(f'\t\033[31m\tНе найден файл "data_cp/config_cp.txt" с конфигурацией Check Point!\033[0;0m')
        sys.exit(1)

    cp_conf = {}
    vlans = []
    mgmt_iface = ''
    net_untr = ''
    for item in config:
        key = item.pop(0)
        l = len(item)
        if item[0] == 'management':
            mgmt_iface = item[2]
        elif item[0] == 'interface':
            if key == 'set':
                try:
                    cp_conf[item[1]].update({item[i]: item[i+1] if i+1 < l else '' for i in range(2,l,2)})
                except KeyError:
                    cp_conf[item[1]] = {item[i]: item[i+1] if i+1 < l else '' for i in range(2,l,2)}
            elif key  == 'add':
                if item[2] == 'vlan':
                    vlans.append(item[3])
        elif item[0] == 'static-route':
            if item[1] == 'default':
                net_untr = item[5].rpartition('.')[0]

    array = []
    for key, value in cp_conf.items():
        ifname = key.partition('.')
        name = ifname[0].replace('eth', 'port')
        if 'ipv4-address' in value:
            zone = 'Untrusted' if value['ipv4-address'].startswith(net_untr) else 'Trusted'
        else:
            zone = 0
        if ifname[2] and ifname[2] in vlans:
            tmp = {
                'id': f'{name}.{ifname[2]}',
                'zone_id': zone,
                'master': False,
                'description': value['comments'] if 'comments' in value else '',
                'netflow_profile': 'undefined',
                'tap': False,
                'name': f'{name}.{ifname[2]}',
                'enabled': False,
                'kind': 'vlan',
                'mtu': int(value['mtu']) if 'mtu' in value else 1500,
                'ipv4': [f"{value['ipv4-address']}/{value['mask-length']}"] if 'ipv4-address' in value else [],
                'vlan_id': int(ifname[2]),
                'link': name,
                'mode': 'static' if 'ipv4-address' in value else 'manual'
            }
            array.append(tmp)
        else:
            if key == 'lo':
                continue
            if key == mgmt_iface:
                name = 'port0'
                zone = 'Management'
            tmp = {
                'id': name,
                'zone_id': zone,
                'master': False,
                'description': value['comments'] if 'comments' in value else '',
                'netflow_profile': 'undefined',
                'tap': False,
                'name': name,
                'enabled': True,
                'kind': 'adapter',
                'mtu': int(value['mtu']) if 'mtu' in value else 1500,
                'ipv4': [f"{value['ipv4-address']}/{value['mask-length']}"] if 'ipv4-address' in value else [],
                'mode': 'static' if 'ipv4-address' in value else 'manual'
            }
            array.append(tmp)

    with open("data_ug/network/config_interfaces.json", "w") as fh:
        json.dump(array, fh, indent=4, ensure_ascii=False)
    print(f'\tКонфигурация интерфейсов выгружена в файл "data_ug/network/config_interfaces.json".')
            
######################################## Импорт ####################################################
def import_settings(self, modules):
    """Импортировать настройки"""
    print('Импорт настроек модулей раздела "Настройки":')

    params = {
        'auth_captive': 'Домен Auth captive-портала',
        'logout_captive': 'Домен Logout captive-портала',
        'block_page_domain': 'Домен страницы блокировки',
        'ftpclient_captive': 'FTP поверх HTTP домен',
    }

    for key, value in modules.items():
        err, result = self.set_settings_param(key, value)
        if err == 2:
            print(f'\033[31m\t{result}\033[0m')
        else:
            print(f'\t{params[key]} - \033[32mUpdated!\033[0m')

def import_list_ips(utm, list_ips):
    """Импортировать списки IP адресов"""
    print('Импорт списков IP-адресов раздела "Библиотеки":')

    if not list_ips:
        print("\tНет списков IP-адресов для импорта.")
        return

    utm_list_ips = utm.get_nlists_list('network')

    for item in list_ips.values():
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
    print('Импорт списка сервисов раздела "Библиотеки":')
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
                        print(f'\tПротокол "{val["port"]}" в сервисе "{item["name"]}" не импортирован!')
                        continue
                if val['source_port']:
                    if val['source_port'] in service_ports or val['source_port'].split('-')[0].isdigit():
                        val['source_port'] = service_ports.get(val['source_port'], val['source_port'])
                    else:
                        print(f'\tПротокол "{val["source_port"]}" в сервисе "{item["name"]}" не импортирован!')
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
    print('Импорт списка "Зоны" раздела "Сеть":')
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

def import_users(utm, users):
    """Импортировать список локальных пользователей"""
    print('Импорт списка локальных пользователей раздела "Пользователи и устройства":')
    trans_table_for_users = str.maketrans(character_map_for_users)
    users_list = utm.get_users_list()

    for item in users:
        if item in users_list:
            print(f'\tПользователь "{item}" уже существует.')
            continue
        user = {
            'groups': [],
            'name': item,
            'enabled': True,
            'auth_login': item.translate(trans_table_for_users),
            'icap_clients': [],
            'is_ldap': False,
            'static_ip_addresses': [],
            'ldap_dn': '',
            'emails': [],
            'first_name': '',
            'last_name': '',
            'phones': []
        }
        err, result = utm.add_user(user)
        if err == 1:
            print(f'\t{result}')
        elif err == 2:
            print(f'\033[31m{result}\033[0m')
        else:
            users_list[item] = result
            print(f'\tЛокальный пользователь "{item}" добавлен.')
    print('\033[36;1mВнимание:\033[0m \033[36mТире и пробел в логине заменены на символ подчёркивания. Точка, прямой и обратный слеши убраны.')
    print('Так как пароли не переносятся, необходимо задать пароль для всех пользователей или задать')
    print('статические IP/MAC/VLAN для авторизации пользователя.\033[0m')

def import_interfaces(utm, ifaces):
    """Импортировать интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    print('Импорт VLAN в раздела "Сеть/Интерфейсы":')

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
            port = input('\n\033[36mВведите название интерфейса: \033[0m')
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
        item['master'] = False
        item['netflow_profile'] = 'undefined'
        item['tap'] = False
        item['enabled'] = False
        item['mtu'] = 1500
        item['running'] = False
        item['dhcp_relay'] = {'servers': [], 'enabled': False, 'host_ipv4': ''}
        item['mode'] = 'static'

        print(item['name'], vlan_list)
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
                print(f'\tИнтерфейс "{item["name"]}" добавлен.\n')

def import_firewall_rules(number, file_rules, utm):
    """Импортировать список правил межсетевого экрана"""
    print(f'Импорт списка №{number} "Межсетевой экран" раздела "Политики сети":')
    try:
        with open(f"data_ug/network_policies/{file_rules}", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок №{number} "Межсетевой экран" не импортирован!\n\tНе найден файл "data_ug/network_policies/{file_rules}" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет правил №{number} межсетевого экрана для импорта.")
        return

    firewall_rules = utm.get_firewall_rules()
    services_list = utm.get_services_list()
    l7_categories = utm.get_l7_categories()
    applicationgroup = utm.get_nlists_list('applicationgroup')
    l7_apps = utm.get_l7_apps()
    zones = utm.get_zones_list()
    list_ip = utm.get_nlists_list('network')
    list_users = utm.get_users_list()
    list_groups = utm.get_groups_list()

    for item in data:
        get_guids_users_and_groups(utm, item, list_users, list_groups)
        set_src_zone_and_ips(item, zones, list_ip)
        set_dst_zone_and_ips(item, zones, list_ip)
        try:
            item['services'] = [services_list[x] for x in item['services']]
        except KeyError as err:
            print(f'\t\033[33mНе найден сервис {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
            item['services'] = []
        try:
            set_apps(item['apps'], l7_categories, applicationgroup, l7_apps)
        except KeyError as err:
            print(f'\t\033[33mНе найдено приложение {err} для правила "{item["name"]}".\n\tЗагрузите сервисы и повторите попытку.\033[0m')
            item['apps'] = []

        if item['name'] in firewall_rules:
            print(f'\tПравило МЭ "{item["name"]}" уже существует', end= ' - ')
            err1, result1 = utm.update_firewall_rule(firewall_rules[item['name']], item)
            if err1 != 0:
                print("\n", f"\033[31m{result1}\033[0m")
            else:
                print("\033[32mUpdated!\033[0;0m")
        else:
            err, result = utm.add_firewall_rule(item)
            if err != 0:
                print(f"\033[31m{result}\033[0m")
            else:
                firewall_rules[item["name"]] = result
                print(f'\tПравило МЭ "{item["name"]}" добавлено.')

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

def get_guids_users_and_groups(utm, item, list_users, list_groups):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if 'users' in item.keys() and item['users']:
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
                    x[1] = list_users[x[1]]
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
                    x[1] = list_groups[x[1]]
                    users.append(x)
            elif x[0] == 'special' and x[1]:
                users.append(x)
        item['users'] = users
    else:
        item['users'] = []

def set_apps(array_apps, l7_categories, applicationgroup, l7_apps):
    """Определяем ID приложения по имени при импорте"""
    for app in array_apps:
        if app[0] == 'ro_group':
            if app[1] == 0:
                app[1] = "All"
            elif app[1] == "All":
                app[1] = 0
            else:
                try:
                    app[1] = l7_categories[app[1]]
                except KeyError as err:
                    print(f'\t\033[33mНе найдена категория l7 №{err}.\n\tВозможно нет лицензии, и UTM не получил список категорий l7.\n\tУстановите лицензию и повторите попытку.\033[0m')
        elif app[0] == 'group':
            try:
                app[1] = applicationgroup[app[1]]
            except KeyError as err:
                print(f'\t\033[33mНе найдена группа приложений №{err}.\n\tЗагрузите приложения и повторите попытку.\033[0m')
        elif app[0] == 'app':
            try:
                app[1] = l7_apps[app[1]]
            except KeyError as err:
                print(f'\t\033[33mНе найдено приложение №{err}.\n\tВозможно нет лицензии, и UTM не получил список приложений l7.\n\tЗагрузите приложения или установите лицензию и повторите попытку.\033[0m')

def set_urls_and_categories(item, list_url, list_urlcategorygroup, url_category):
    if item['urls']:
        try:
            item['urls'] = [list_url[x] for x in item['urls']]
        except KeyError as err:
            print(f'\t\033[33mНе найден URL {err} для правила "{item["name"]}".\n\tЗагрузите списки URL и повторите попытку.\033[0m')
            item['urls'] = []
    if item['url_categories']:
        try:
            for x in item['url_categories']:
                if x[0] == 'list_id':
                    x[1] = list_urlcategorygroup[x[1]]
                elif x[0] == 'category_id':
                    x[1] = url_category[x[1]]
        except KeyError as err:
            print(f'\t\033[33mНе найдена группа URL-категорий {err} для правила "{item["name"]}".\n\tЗагрузите категории URL и повторите попытку.\033[0m')
            item['url_categories'] = []

def menu():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m                    Конвертация конфигурации с Cisco ASA на NGFW                   \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ca' в текущей директории на NGFW UserGate.\033[0m\n")
    print('\033[33mПеред запуском конвертации Удостоверьтесь, что:')
    print('\t1. Конфигурация Cisco ASA выложена в каталог "data_ca" в текущей директории.')
    print('\t2. Файл конфигурации имеет имя "config_asa.txt". Если это не так, переименуйте его.')
    print('\t3. Вы подключились к веб-консоли администратора на зоне Management.\033[0m')
    print('\033[36m\nПереносятся настройки:')
    print('\tМодули            - "Настойки/Модули"')
    print('\tСписки IP-адресов - "Библиотеки/IP-адреса"')
    print('\tСервисы           - "Библиотеки/Сервисы"')
    print('\tПользователи      - "Пользователи и устройства/Пользователи"')
    print('\tЗоны              - "Сеть/Зоны"')
    print('\tИнтерфейсы VLAN   - "Сеть/Интерфейсы"\033[0m')
    
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
    print("\033[1;36;43mUserGate\033[1;37;43m                     Конвертация конфигурации с Cisco ASA на NGFW                   \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ca' в текущей директории на NGFW UserGate.\033[0m\n")
    try:
        menu()
        file_name = 'config_asa'
        if not os.path.isfile(f'data_ca/{file_name}.txt'):
            print(f'\t\033[31mИмпорт aborted!\n\tНе найден файл "data_ca/config_asa.txt" с конфигурацией Cosco ASA!\033[0;0m')
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

        try:
            with open("data_ca/config_asa.json", "r") as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            print(f'\t\033[31mИмпорт aborted!\n\tНе найден файл "data_ca/config_asa.json" с сохранённой конфигурацией!\033[0;0m')
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
            import_settings(utm, data['modules'])
            import_list_ips(utm, data['ip_lists'])
            import_services(utm, data['services'])
            import_users(utm, data['users'])
        except Exception as err:
            print(f'\n\033[31mОшибка: {err}\033[0m')
            utm.logout()
            sys.exit(1)
        else:
            utm.logout()
            os.remove(f'data_ca/{file_name}.json')
            print("\n\033[32mИмпорт конфигурации Cisco ASA на NGFW UserGate завершён.\033[0m\n")

    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        sys.exit()

if __name__ == '__main__':
    colorama.init()
    main()
