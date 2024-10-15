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
# Версия 1.5 15.10.2024
#

import os, sys, json, re
import ipaddress, copy
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from services import network_proto, ug_services, service_ports, trans_table, trans_filename


revers_service_ports = {v: k for k, v in service_ports.items()}
pattern = re.compile(r"[-\w]+='[-:!,/\.\w ]+'|[-\w]+=[-:!,/\.\w]+|rule='.+'")
pattern_rf = re.compile(r"[\w]+=[-\w]+|\(.+\)|(?:accept|reject)")
pattern_ip = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


class ConvertMikrotikConfig(QThread):
    """Преобразуем файл конфигурации MikroTik в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_fpr_path, current_ug_path):
        super().__init__()
        self.current_fpr_path = current_fpr_path
        self.current_ug_path = current_ug_path
        self.error = 0
        self.vendor = 'MikroTik'
        self.ifaces = []
        self.zones = []
        self.gateways = set()
        self.ip_lists = set()
        self.url_lists = set()
        self.services = {}

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации MikroTik в формат UserGate NGFW.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        convert_config_file(self, self.current_fpr_path)
        
        json_file = os.path.join(self.current_fpr_path, 'config.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            self.error = 1
        else:
            convert_settings_ui(self, self.current_ug_path, data)
            convert_ntp_settings(self, self.current_ug_path, data)
            convert_zones(self, self.current_ug_path, data)
            convert_ipip_interface(self, self.current_ug_path, data)
            convert_vlan_interfaces(self, self.current_ug_path, data)
            convert_dhcp(self, self.current_ug_path, data)
            convert_system_dns(self, self.current_ug_path, data)
            convert_dns_static(self, self.current_ug_path, data)
            convert_gateways_list(self, self.current_ug_path, data)
            convert_static_routes(self, self.current_ug_path, data)
            convert_ip_lists(self, self.current_ug_path, data)
            convert_url_lists(self, self.current_ug_path, data)
            convert_services_list(self, self.current_ug_path, data)
            convert_firewall_rules(self, self.current_ug_path, data)
            convert_dnat_rules(self, self.current_ug_path, data)

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
        if 'interface' in item:
            ifaces[item['interface']] = item['address']
    data['ip address'] = ifaces

    if 'interface list member' in data:
        new_members = {}
        for member in data['interface list member']:
            new_members[member['interface']] = member['list']
        data['interface list member'] = new_members
    else:
        data['interface list member'] = {}

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


def convert_zones(parent, path, data):
    """Конвертируем зоны."""
    if 'interface list' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация Зон.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'Zones')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    zones = []
    for item in data['interface list']:
        zone = {
            'name': item['name'],
            'description': 'Портировано с MikroTik.',
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
        parent.zones.append(item['name'])
        parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" конвертирована.')

    if zones:
        json_file = os.path.join(current_path, 'config_zones.json')
        with open(json_file, "w") as fh:
            json.dump(zones, fh, indent=4, ensure_ascii=False)

        parent.stepChanged.emit(f'GREEN|    Конфигурация Зон выгружена в файл "{json_file}".')
        parent.stepChanged.emit('LBLUE|    Необходимо настроить каждую зону. Включить нужный сервис в контроле доступа, поменять по необходимости параметры защиты от DoS и настроить защиту от спуфинга.')
    else:
        parent.stepChanged.emit('GRAY|    Нет зон для экспорта.')


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
                'description': f"Портировано с MikroTik.\n{item.get('name', '')}",
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
                'mtu': int(item['mtu']) if item['mtu'] else 1500,
                'tap': False
            }
            iface['ipv4'].append(data['ip address'][item['name']])
            if 'interface list member' in data:
                iface['zone_id'] = data['interface list member'].get(item['name'], 0)

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


def convert_vlan_interfaces(parent, path, data):
    """Конвертируем интерфейсы VLAN"""
    if 'interface vlan' not in data:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')

    for item in data['interface vlan']:
        try:
            iface = {
                'name': item['name'],
                'kind': 'vlan',
                'enabled': False,
                'description': f"Портировано с MikroTik.\n{item.get('name', '')} {item.get('comment', '')}",
                'zone_id': 0,
                'master': False,
                'netflow_profile': 'undefined',
                'lldp_profile': 'undefined',
                'ipv4': [],
                'ifalias': '',
                'flow_control': False,
                'mode': 'static',
                'mtu': 1500,
                'tap': False,
                'dhcp_relay': {
                    'enabled': False,
                    'host_ipv4': '',
                    'servers': []
                },
                'vlan_id': int(item['vlan-id']),
                'link': ''
            }
            
            if item['name'] in data['ip address']:
                iface['ipv4'].append(data['ip address'][item['name']])
            else:
                iface['mode'] = 'dhcp'
                iface['dhcp_default_gateway'] = True
            if 'interface list member' in data:
                iface['zone_id'] = data['interface list member'].get(item['name'], 0)

        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Интервейс VLAN {item["name"]} не конвертирован [ErrorKey: {err}].')
            error = 1
            parent.error = 1
        else:
            parent.ifaces.append(iface)
            parent.stepChanged.emit(f'BLACK|    Интервейс VLAN {item["name"]} конвертирован.')
    if error:
        parent.stepChanged.emit('ORANGE|    Прошла ошибка при экспорте интервейсов VLAN.')
    else:
        parent.stepChanged.emit('GREEN|    Интервейсы VLAN конвертированы.')


def convert_dhcp(parent, path, data):
    """Конвертируем настройки DHCP"""
    if 'ip pool' not in data or 'ip dhcp-server' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация настроек DHCP.')
    dhcp_subnets = []

    for dhcp_server in data['ip dhcp-server']:
        dhcp_subnet = {
            'name': dhcp_server['name'],
            'enabled': False,
            'description': f'Портировано с MikroTik.',
            'start_ip': '',
            'end_ip': '',
            'lease_time': 3600,
            'domain': 'example.ru',
            'gateway': '',
            'boot_filename': '',
            'boot_server_ip': '',
            'iface_id': dhcp_server['interface'],
            'netmask': '',
            'nameservers': [],
            'ignored_masc': [],
            'hosts': [],
            'options': []
        }
        for pool in data['ip pool']:
            if pool['name'] == dhcp_server['address-pool']:
                dhcp_subnet['start_ip'], dhcp_subnet['end_ip'] = pool['ranges'].split('-')
        for net in data['ip dhcp-server network']:
            interface = ipaddress.ip_interface(net['address'])
            if ipaddress.ip_address(dhcp_subnet['start_ip']) in interface.network:
                dhcp_subnet['netmask'] = str(interface.netmask)
                dhcp_subnet['gateway'] = net['gateway']
                if 'dns-server' in net:
                    dhcp_subnet['nameservers'].append(net['dns-server'])
                if 'ntp-server' in net:
                    dhcp_subnet['options'].append([42, net['ntp-server']])
        if 'ip dhcp-server lease' in data:
            n = 1
            for item in data['ip dhcp-server lease']:
                if item['server'] == dhcp_server['name']:
                    dhcp_subnet['hosts'].append({
                        'mac': item['mac-address'],
                        'ipv4': item['address'],
                        'hostname': f'Host-{n}'
                    })
                    n += 1
        dhcp_subnets.append(dhcp_subnet)

    if dhcp_subnets:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DHCP')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_dhcp_subnets.json')
        with open(json_file, "w") as fh:
            json.dump(dhcp_subnets, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет настроек DHCP для экспорта.')


def convert_system_dns(parent, path, data):
    """Конвертируем системные DNS серверы"""
    if 'ip dns' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация системных DNS-серверов.')

    dns_servers = []
    for item in data['ip dns']:
        ips = item['servers'].split(',')
        for ip in ips:
            dns_servers.append({
                'dns': ip,
                'is_bad': False if item['allow-remote-requests'] == 'yes' else True
            })

    if dns_servers:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_dns_servers.json')
        with open(json_file, "w") as fh:
            json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Системные DNS-сервера выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет системных DNS-серверов для экспорта.')


def convert_dns_static(parent, path, data):
    """Конвертируем статические записи DNS"""
    if 'ip dns static' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация статических записей DNS.')

    records = []
    for item in data['ip dns static']:
        records.append({
            'name': item['name'],
            'description': '',
            'enabled': True if item.get('disabled', 'no') == 'no' else False,
            'domain_name': item['name'],
            'ip_address': [item['address']]
        })

    if records:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_dns_static.json')
        with open(json_file, "w") as fh:
            json.dump(records, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Статические записи DNS выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет статических записей DNS для экспорта.')


def convert_gateways_list(parent, path, data):
    """Конвертируем список шлюзов"""
    if 'ip route' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация списка шлюзов.')
    error = 0
    list_gateways = []
    for item in data['ip route']:
        gateway = item['gateway']
        if gateway in data['ip address']:
            err, gateway = func.get_netroute(data['ip address'][gateway])
            if err:
                continue
        err, msg = func.ip_isglobal(gateway)
        if err or not msg:
            continue
#        if item['dst-address'] == '0.0.0.0/0':
        else:
            if gateway not in parent.gateways:
                name = f"{gateway} {item.get('comment', '')}"
                if len(name) > 30:
                    name = name[:31]
                try:
                    list_gateways.append({
                        'name': name.strip(),
                        'enabled': False,
                        'description': f"Портировано с MikroTik.\n{item.get('comment', '')}",
                        'ipv4': gateway,
                        'vrf': 'default',
                        'weight': int(item.get('distance', 1)),
                        'multigate': False,
                        'default': False,
                        'iface': 'undefined',
                        'is_automatic': False
                    })
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: Шлюз {gateway} не конвертирован [{err}].')
                    error = 1
                    parent.error = 1
                else:
                    parent.gateways.add(gateway)
                    parent.stepChanged.emit(f'BLACK|    Шлюз {gateway} конвертирован.')
    if list_gateways:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Gateways')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_gateways.json')
        with open(json_file, "w") as fh:
            json.dump(list_gateways, fh, indent=4, ensure_ascii=False)
        if error:
            parent.stepChanged.emit(f'ORANGE|    Прошла ошибка при экспорте шлюзов. Список шлюзов выгружен в файл "{json_file}".')
        else:
            parent.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')


def convert_static_routes(parent, path, data):
    """Конвертируем статические маршруты"""
    if 'ip route' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация статических маршрутов.')
    error = 0
    routes_list = []
    for item in data['ip route']:
        gateway =  item['gateway']
        if item['dst-address'] != '0.0.0.0/0':
            if gateway in data['ip address']:
                err, gateway = func.get_netroute(data['ip address'][gateway])
                if err:
                    continue
            else:
                err, result = func.unpack_ip_address(gateway)   # Проверяем что gateway это IP-адрес а не строка символов.
                if err:
                    err, gateway = func.get_netroute(item['dst-address'])
                    if err:
                        ip = item['dst-address'].split('/')[0]
                        err, gateway = func.get_netroute(f'{ip}/24')
                        if err:
                            continue
            try:
                route = {
                    'name': f"For {item['dst-address']}",
                    'description': f"Портировано с MikroTik.\n{item.get('comment', '')}",
                    'enabled': True if item.get('disabled', 'yes') == 'no' else False,
                    'dest': item['dst-address'],
                    'gateway': gateway,
                    'ifname': 'undefined',
                    'kind': 'unicast',
                    'metric': int(item.get('distance', 1))
                }
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: {err}. Маршрут для "{item["dst-address"]}" не конвертирован.')
                error = 1
            else:
                routes_list.append(route)
                parent.stepChanged.emit(f'BLACK|    Маршрут для {item["dst-address"]} конвертирован.')

    if routes_list:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'VRF')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        vrf_info = [{
            'name': 'default',
            'description': '',
            'interfaces': [],
            'routes': routes_list,
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {},
        }]

        json_file = os.path.join(current_path, 'config_vrf.json')
        with open(json_file, "w") as fh:
            json.dump(vrf_info, fh, indent=4, ensure_ascii=False)
        if error:
            parent.stepChanged.emit(f'ORANGE|    Прошла ошибка при экспорте статических маршрутов. Статические маршруты выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


def convert_ip_lists(parent, path, data):
    """Конвертируем списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return
    error = 0

    if 'ip firewall address-list' in data and data['ip firewall address-list']:
        error = convert_ip_lists_from_address_list(parent, current_path, data['ip firewall address-list'])
    if 'ip firewall filter' in data and data['ip firewall filter']:
        error = convert_ip_lists_firewall_filter(parent, current_path, data['ip firewall filter'])
    if 'ip firewall nat' in data and data['ip firewall nat']:
        error = convert_ip_lists_firewall_filter(parent, current_path, data['ip firewall nat'])

    if parent.ip_lists:
        if error:
            parent.stepChanged.emit('ORANGE|    Некоторые списки IP-адресов не выгружены из-за ошибок.')
        else:
            parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


def convert_ip_lists_from_address_list(parent, current_path, address_list):
    """Конвертируем списки IP-адресов из ip firewall address-list"""
    error = 0
    ip_list = {}
    for item in address_list:
        err, result = func.unpack_ip_address(item['address'])   # Проверяем что это IP-адрес а не строка символов.
        if err:
            continue
        try:
            if item['list'] in ip_list:
                ip_list[item['list']]['content'].append({'value': item['address']})
                if 'comment' in item:
                    ip_list[item['list']]['description'] = f'{ip_list[item["list"]]["description"]}\n{item.get("comment", "")}'
            else:
                ip_list[item['list']] = {
                    'name': func.get_restricted_name(item['list']),
                    'description': f"Портировано с MikroTik.\n{item.get('comment', '')}",
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'threat_level': 3
                    },
                    'content': [{'value': item['address']}]
                }
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: {err}. IP-лист "{item.get("list", item.get("address", ''))}" не конвертирован.')
            error = 1
    if ip_list:
        for key, value in ip_list.items():
            parent.ip_lists.add(value['name'])
            json_file = os.path.join(current_path, f'{key.translate(trans_filename)}.json')
            with open(json_file, "w") as fh:
                json.dump(value, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{key}" выгружен в файл "{json_file}".')
    return error


def convert_ip_lists_firewall_filter(parent, current_path, firewall_filter):
    """Конвертируем списки IP-адресов из ip firewall filter"""
    error = 0
    for item in firewall_filter:
        if 'dst-address' in item and item['dst-address']:
            item['dst_ips'] = ['list_id', item['dst-address']]
            if item['dst-address'] not in parent.ip_lists:
                ip_list = {
                    'name': item['dst-address'],
                    'description': 'Портировано с MikroTik.',
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'threat_level': 3
                    },
                    'content': [{'value': item['dst-address']}]
                }
                parent.ip_lists.add(ip_list['name'])
                json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
                with open(json_file, "w") as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

        if 'src-address' in item and item['src-address']:
            item['src_ips'] = ['list_id', item['src-address']]
            if item['src-address'] not in parent.ip_lists:
                ip_list = {
                    'name': item['src-address'],
                    'description': 'Портировано с MikroTik.',
                    'type': 'network',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {
                        'threat_level': 3
                    },
                    'content': [{'value': item['src-address']}]
                }
                parent.ip_lists.add(ip_list['name'])
                json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
                with open(json_file, "w") as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
    return error


def convert_url_lists(parent, path, data):
    """Конвертируем списки URL из ip firewall address-list"""
    if 'ip firewall address-list' not in data:
        return

    parent.stepChanged.emit('BLUE|Конвертация списков URL.')
    error = 0
    url_list = {}

    for item in data['ip firewall address-list']:
        err, result = func.unpack_ip_address(item['address'])   # Проверяем что это строка символов а не IP-адрес.
        if err:
            try:
                if item['list'] in url_list:
                    url_list[item['list']]['content'].append({'value': item['address']})
                    if 'comment' in item:
                        url_list[item['list']]['description'] = f'{url_list[item["list"]]["description"]}\n{item.get("comment", "")}'
                else:
                    url_list[item['list']] = {
                        'name': func.get_restricted_name(item['list']),
                        'description': f"Портировано с MikroTik.\n{item.get('comment', '')}",
                        'type': 'url',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {
                            'list_complile_type': 'case_insensitive'
                        },
                        'content': [{'value': item['address']}]
                    }
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: {err}. URL-лист "{item.get("list", item.get("address", ''))}" не конвертирован.')
                error = 1

    if url_list:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'URLLists')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit('RED|    {msg}.')
            parent.error = 1
            return

        for key, value in url_list.items():
            parent.url_lists.add(value['name'])
            json_file = os.path.join(current_path, f'{key.translate(trans_filename)}.json')
            with open(json_file, "w") as fh:
                json.dump(value, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список URL "{key}" выгружен в файл "{json_file}".')
        if error:
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списков URL.')
        else:
            parent.stepChanged.emit(f'GREEN|    Списки URL экспортированы.')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет списков URL для экспорта.')


def convert_services_list(parent, path, data):
    """Конвертируем список сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация списка сервисов.')
    services_list = []

    if 'ip firewall filter' in data and data['ip firewall filter']:
        services_list.extend(convert_services_from_filter(parent, data['ip firewall filter']))
    if 'ip firewall nat' in data and data['ip firewall nat']:
        services_list.extend(convert_services_from_nat(parent, data['ip firewall nat']))

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
        parent.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет сервисов для экспорта.')


def convert_services_from_filter(parent, ip_firewall_filter):
    """Конвертируем список сервисов из правил firewall"""
    services_list = []

    for item in ip_firewall_filter:
        item['services'] = []
        if 'protocol' in item:
            if item['protocol'] not in network_proto:
                item['services'] = 'err'
                continue
            service_name = item['protocol']
            description = 'Портировано с MikroTik.'
            if 'dst-port' not in item and 'src-port' not in item:
                if item['protocol'] not in parent.services:
                    if item['protocol'] in {'tcp', 'udp', 'sctp', 'icmp', 'ipv6-icmp'}:
                        service_name = f"Any {item['protocol'].upper()}"
                        description = f"Any {item['protocol'].upper()} packet"
                    services_list.append({
                        'name': service_name,
                        'description': description,
                        'protocols': [
                            {
                                'proto': item['protocol'],
                                'port': '',
                                'app_proto': '',
                                'source_port': '',
                                'alg': ''
                            }
                        ]
                    })
                    parent.services[item['protocol']] = service_name
                    parent.stepChanged.emit(f'BLACK|    Создан сервис {service_name}".')
                item['services'].append(['service', parent.services[item['protocol']]])
            else:
                port = ''
                source_port = ''
                proto = item['protocol']
                app_proto = ''
                if 'dst-port' in item:
                    port = item['dst-port']
                    service_name += f" (dst {item['dst-port']})"
                if 'src-port' in item:
                    source_port = item['src-port']
                    service_name += f" (src {item['src-port']})"
                match port:
                    case '110':
                        proto = 'pop3'
                        app_proto = 'pop3'
                    case '995':
                        proto = 'pop3s'
                        app_proto = 'pop3s'
                    case '25':
                        proto = 'smtp'
                        app_proto = 'smtp'
                    case '465':
                        proto = 'smtps'
                        app_proto = 'smtps'
                if port in ug_services:
                    service_name = ug_services[port]
                if service_name not in parent.services:
                    services_list.append({
                        'name': service_name,
                        'description': description,
                        'protocols': [
                            {
                                'proto': proto,
                                'port': port,
                                'app_proto': app_proto,
                                'source_port': source_port,
                                'alg': ''
                            }
                        ]
                    })
                    parent.services[service_name] = service_name
                item['services'].append(['service', service_name])
                parent.stepChanged.emit(f'BLACK|    Создан сервис {service_name}".')

    return services_list
                

def convert_services_from_nat(parent, ip_firewall_nat):
    """Конвертируем список сервисов из правил dnat"""
    services_list = []

    for item in ip_firewall_nat:
        item['services'] = []
        if 'protocol' in item:
            if item['protocol'] not in network_proto:
                item['services'] = 'err'
                continue
            if item['action'] == 'netmap':
                if 'dst-port' in item and 'to-ports' in item and (item['dst-port'] != item['to-ports']):
                    continue
            service_name = item['protocol']
            description = 'Портировано с MikroTik.'
            if 'to-ports' not in item:
                if item['protocol'] not in parent.services:
                    if item['protocol'] in {'tcp', 'udp', 'sctp', 'icmp', 'ipv6-icmp'}:
                        service_name = f"Any {item['protocol'].upper()}"
                        description = f"Any {item['protocol'].upper()} packet"
                    services_list.append({
                        'name': service_name,
                        'description': description,
                        'protocols': [
                            {
                                'proto': item['protocol'],
                                'port': '',
                                'app_proto': '',
                                'source_port': '',
                                'alg': ''
                            }
                        ]
                    })
                    parent.services[item['protocol']] = service_name
                item['services'].append(['service', parent.services[item['protocol']]])
            else:
                port = item['to-ports']
                proto = item['protocol']
                app_proto = ''
                service_name += f" (dst {port})"
                match port:
                    case '110':
                        proto = 'pop3'
                        app_proto = 'pop3'
                    case '995':
                        proto = 'pop3s'
                        app_proto = 'pop3s'
                    case '25':
                        proto = 'smtp'
                        app_proto = 'smtp'
                    case '465':
                        proto = 'smtps'
                        app_proto = 'smtps'
                if port in ug_services:
                    service_name = ug_services[port]
                if service_name not in parent.services:
                    services_list.append({
                        'name': service_name,
                        'description': description,
                        'protocols': [
                            {
                                'proto': proto,
                                'port': port,
                                'app_proto': app_proto,
                                'source_port': '',
                                'alg': ''
                            }
                        ]
                    })
                    parent.services[service_name] = service_name
                item['services'].append(['service', service_name])
                parent.stepChanged.emit(f'BLACK|    Создан сервис {service_name}".')

    return services_list
                

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

    firewall_rules = []
    n = 0
    for item in data['ip firewall filter']:
#        if item.get('disabled', False) == 'yes':
#            parent.stepChanged.emit(f'bRED|    Правило межсетевого экрана "{item}" не конвертировано так как имеет статус "disabled".')
#            continue
        if item.get('connection-state', False):
            parent.stepChanged.emit(f'bRED|    Правило межсетевого экрана "{item}" не конвертировано так как содержит "connection-state".')
            continue
        if isinstance(item['services'], str):
            parent.stepChanged.emit(f'bRED|    Правило межсетевого экрана "{item}" не конвертировано так как содержит не поддерживаемый сервис.')
            continue
        send_host_icmp = ''
        if 'action' in item:
            if item['action'] in {'drop', 'reject'}:
                action = 'drop'
                if item['action'] == 'reject':
                    send_host_icmp = 'tcp-rst'
            elif item['action'] == 'accept':
                action = 'accept'
            else:
                parent.stepChanged.emit(f'bRED|    Правило межсетевого экрана "{item}" не конвертировано так как содержит действие "{item["action"]}".')
                continue
        else:
            action = 'accept'
        n += 1
        fw_rule = {
            'name': f'Rule - {n}',
            'description': f"Портировано с MikroTik.\n{item.get('comment', '')}",
            'action': action,
            'scenario_rule_id': False,
            'src_zones': [item['in-interface-list']] if item.get('in-interface-list', False) else [],
            'dst_zones': [item['out-interface-list']] if item.get('out-interface-list', False) else [],
            'src_ips': [item['src_ips']] if item.get('src_ips', False) else [],
            'dst_ips': [item['dst_ips']] if item.get('dst_ips', False) else [],
            'services': item['services'],
            'users': [],
            'enabled': False if item.get('disabled', False) == 'yes' else True,
            'limit': False,
            'limit_value': '3/h',
            'limit_burst': 5,
            'log': True if item.get('log', False) == 'yes' else False,
            'log_session_start': False,
            'src_zones_nagate': False,
            'dst_zones_nagate': False,
            'src_ips_nagate': False,
            'dst_ips_nagate': False,
            'services_nagate': False,
            'fragmented': 'ignore',
            'time_restrictions': [],
            'send_host_icmp': send_host_icmp,
            'position_layer': 'local',
            'ips_profile': False,
            'l7_profile': False,
            'hip_profiles': []
        }
        if 'in-interface' in item:
            if item['in-interface'].startswith('!'):
                ifname = item['in-interface'][1:]
                fw_rule['src_zones_nagate'] = True
            else:
                ifname = item['in-interface']
            if ifname in data['interface list member']:
                fw_rule['src_zones'].append(data['interface list member'][ifname])
        if 'out-interface' in item:
            if item['out-interface'].startswith('!'):
                ifname = item['out-interface'][1:]
                fw_rule['dst_zones_nagate'] = True
            else:
                ifname = item['out-interface']
            if ifname in data['interface list member']:
                fw_rule['dst_zones'].append(data['interface list member'][ifname])
        if 'dst-address-list' in item:
            if item['dst-address-list'] in parent.ip_lists:
                fw_rule['dst_ips'].append(['list_id', item['dst-address-list']])
            elif item['dst-address-list'] in parent.url_lists:
                fw_rule['dst_ips'].append(['urllist_id', item['dst-address-list']])
        if 'src-address-list' in item:
            if item['src-address-list'] in parent.ip_lists:
                fw_rule['src_ips'].append(['list_id', item['src-address-list']])
            elif item['src-address-list'] in parent.url_lists:
                fw_rule['src_ips'].append(['urllist_id', item['src-address-list']])

        if not fw_rule['services'] and not fw_rule['dst_ips'] and not fw_rule['src_ips'] and not fw_rule['src_zones'] and not fw_rule['dst_zones']:
            n -= 1
            continue
        firewall_rules.append(fw_rule)

    if firewall_rules:
        json_file = os.path.join(current_path, 'config_firewall_rules.json')
        with open(json_file, "w") as fh:
            json.dump(firewall_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список правил межсетевого экрана выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


def convert_dnat_rules(parent, path, data):
    """Конвертируем правила межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Конвертация правил DNAT и Порт-форвардинг.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'NATandRouting')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit('RED|    {msg}.')
        parent.error = 1
        return

    dnat_rules = []
    n = 0
    for item in data['ip firewall nat']:
#        if item.get('disabled', False) == 'yes':
#            parent.stepChanged.emit(f'bRED|    Правило DNAT "{item}" не конвертировано так как имеет статус "disabled".')
#            continue
        if isinstance(item['services'], str):
            parent.stepChanged.emit(f'bRED|    Правило DNAT "{item}" не конвертировано так как содержит не поддерживаемый сервис.')
            continue
        if not item['services'] and 'dst_ips' not in item and 'src_ips' not in item:
            continue
        send_host_icmp = ''
        if 'action' in item:
            port_mappings = []
            if item['action'] == 'netmap' and item['chain'] == 'dstnat':
                if item['services']:
                    action = 'dnat'
                elif 'dst-port' in item and 'to-ports' in item:
                    action = 'port_mapping'
                    port_mappings = [{'proto': item['protocol'], 'src_port': item['dst-port'], 'dst_port': item['to-ports']}]
                else:
                    parent.stepChanged.emit(f'bRED|    Правило DNAT "{item}" не конвертировано так как содержит действие "{item["action"]}".')
                    continue
            else:
                parent.stepChanged.emit(f'bRED|    Правило DNAT "{item}" не конвертировано так как содержит действие "{item["action"]}".')
                continue
        else:
            continue
        n += 1
        dnat_rule = {
            'name': f'Rule - {n}',
            'description': f"Портировано с MikroTik.\n{item.get('comment', '')}",
            'action': action,
            'zone_in': [item['in-interface-list']] if item.get('in-interface-list', False) else [],
            'zone_out': [item['out-interface-list']] if item.get('out-interface-list', False) else [],
            'source_ip': [item['src_ips']] if item.get('src_ips', False) else [],
            'dest_ip': [item['dst_ips']] if item.get('dst_ips', False) else [],
            'service': item['services'],
            'target_ip': item.get('to-addresses', ''),
            'gateway': '',
            'enabled': False if item.get('disabled', False) == 'yes' else True,
            'log': True if item.get('log', False) == 'yes' else False,
            'log_session_start': False,
            'log_limit': False,
            'log_limit_value': '3/h',
            'log_limit_burst': 5,
            'target_snat': False,
            'snat_target_ip': '',
            'zone_in_nagate': False,
            'zone_out_nagate': False,
            'source_ip_nagate': False,
            'dest_ip_nagate': False,
            'port_mappings': port_mappings,
            'direction': 'input',
            'users': [],
            'position_layer': 'local',
            'scenario_rule_id': False,
        }
        if 'in-interface' in item:
            if item['in-interface'].startswith('!'):
                ifname = item['in-interface'][1:]
                dnat_rule['zone_in_nagate'] = True
            else:
                ifname = item['in-interface']
            if ifname in data['interface list member']:
                dnat_rule['src_zones'].append(data['interface list member'][ifname])

        if 'dst-address-list' in item and item['dst-address-list'] in parent.ip_lists:
            dant_rule['dst_ips'].append(['list_id', item['dst-address-list']])
        if 'src-address-list' in item and item['src-address-list'] in parent.ip_lists:
            dnat_rule['src_ips'].append(['list_id', item['src-address-list']])

        dnat_rules.append(dnat_rule)

    if dnat_rules:
        json_file = os.path.join(current_path, 'config_nat_rules.json')
        with open(json_file, "w") as fh:
            json.dump(dnat_rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список правил DNAT/Порт-форвардинг выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил DNAT/Порт-форвардинг для экспорта.')

#####################################################################################################

def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
