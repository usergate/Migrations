#!/usr/bin/python3
#
# export_cisco_asa_config.py (convert configuration from Cisco ASA to NGFW UserGate).
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
# Модуль предназначен для выгрузки конфигурации Cisco ASA в формат json NGFW UserGate.
# Версия 1.1
#

import os, sys, json
import ipaddress, copy
import common_func as func
from collections import deque
from PyQt6.QtCore import QThread, pyqtSignal
from services import (trans_table, trans_userlogin, trans_name, trans_filename, service_ports,
                      ug_services, zone_services, ip_proto, network_proto, MONTHS, TIME_ZONE)


class ConvertCiscoASAConfig(QThread):
    """Преобразуем файл конфигурации Cisco ASA в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, current_asa_path, current_ug_path):
        super().__init__()
        self.current_asa_path = current_asa_path
        self.current_ug_path = current_ug_path
        self.error = 0
        self.ip_lists = set()

    def run(self):
        self.stepChanged.emit('GREEN|Конвертация конфигурации Cisco ASA в формат UserGate NGFW.')
        convert_config_file(self, self.current_asa_path)
        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации Cisco ASA в формат UserGate NGFW прервана.\n')
        else:
            json_file = os.path.join(self.current_asa_path, 'cisco_asa.json')
            err, data = func.read_json_file(self, json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации Cisco ASA в формат UserGate NGFW прервана.\n')
                self.error = 1
            else:
#                convert_settings_ui(self, self.current_ug_path, data['timezone'])
#                convert_ntp_settings(self, self.current_ug_path, data['ntp'])
#                convert_modules(self, self.current_ug_path, data)
                convert_zones(self, self.current_ug_path, data)
                convert_zone_access(self, self.current_ug_path, data)
#                convert_dns_servers(self, self.current_ug_path, data['dns']['system_dns'])
#                convert_dns_rules(self, self.current_ug_path, data['dns']['dns_rules'])
#                convert_vlan_interfaces(self, self.current_ug_path, data)
#                convert_gateways(self, self.current_ug_path, data)
#                convert_routes(self, self.current_ug_path, data)
#                convert_dhcp_settings(self, self.current_ug_path, data)
#                convert_local_groups(self, self.current_ug_path, data)
#                convert_local_users(self, self.current_ug_path, data['local-users'])
#                convert_auth_servers(self, self.current_ug_path, data)
                convert_service_object(self, self.current_ug_path, data)
                convert_ip_lists(self, self.current_ug_path, data['ip_lists'])
#                convert_url_lists(self, self.current_ug_path, data['url_lists'])
                convert_network_object_group(self, self.current_ug_path, data)
                convert_service_object_group(self, self.current_ug_path, data)
                convert_protocol_object_group(self, self.current_ug_path, data)
#                convert_time_sets(self, self.current_ug_path, data)
#                convert_firewall_rules(self, self.current_ug_path, data)
#                convert_webtype_ace(self, self.current_ug_path, data)
                convert_dnat_rule(self, self.current_ug_path, data)
            if self.error:
                self.stepChanged.emit('iORANGE|Конвертация конфигурации Cisco ASA в формат UserGate NGFW прошла с ошибками.\n')
            else:
                self.stepChanged.emit('iGREEN|Конвертация конфигурации Cisco ASA в формат UserGate NGFW прошла успешно.\n')


def convert_config_file(parent, path):
    """Преобразуем файл конфигурации Cisco ASA в json."""
    parent.stepChanged.emit('BLUE|Преобразование файла конфигурации Cisco ASA в json.')
    if not os.path.isdir(path):
        parent.stepChanged.emit(f'RED|    Не найден каталог {path} с конфигурации Cisco ASA.')
        parent.error = 1
        return

    error = 0
    config_file = 'cisco_asa.cfg'
    asa_config_file = os.path.join(path, config_file)
    config_data = []

    try:
        with open(asa_config_file, "r") as fh:
            for line in fh:
                config_data.append(line)
    except FileNotFoundError:
        parent.stepChanged.emit(f'RED|    Error! Не найден файл {asa_config_file} с конфигурации Cisco ASA.')
        parent.error = 1
        return

    data = {
        'timezone': '',
        'ntp': [],
        'domain-name': '',
        'zones': {},
        'dns': {
            'domain-lookup': [],
            'dns_rules': [],
            'system_dns': []
        },
        'ifaces': [],
        'gateways': {},
        'routes': [],
        'cli-ssh': [],
        'web-console': [],
        'auth-type': {},
        'auth_servers': [],
        'time-range': {},
        'dhcp-opt': {
            'options': []
        },
        'dhcp-subnets': {},
        'local-users': {},
        'local-groups': {},
        'identity_domains': {},
        'services': {},
        'ip_lists': {},
        'url_lists': {},
        'dnat_rules': {},
        'network-group': {},
        'service-group': {},
        'protocol-group': {},
        'icmp-group': {},
        'direction': {},
        'fw_access-list': {},
        'fw_rule_number': 0,
        'cf_access-list': {},
        'cf_rule_number': 0,
        'nat_rules': [],
        'nat_rule_number': 0,
    }

    for line in config_data:
        if line[:1] in {':', '!'}:
            continue
        x = line.translate(trans_table).rsplit(' ')
        if x[0] == 'mtu':
            data['zones'][x[1].translate(trans_name)] = int(x[2])

    num = 0
    while (len(config_data) - num):
        line = config_data[num]
        if line[:1] in {':', '!'}:
            num += 1
            continue
        tmp_block = []
        x = line.translate(trans_table).rsplit(' ')
        match x[0]:
            case 'domain-name':
                data['domain-name'] = x[1]
            case 'dns':
                match x[1:]:
                    case ['domain-lookup', zone_name]:
                        data['dns']['domain-lookup'].append(zone_name)
                    case 'forwarder':
                        create_dns_servers(data, x)
                    case ['server-group', servergroup_name]:
                        num, tmp_block = get_block(config_data, num)
                        create_dns_rules(data, servergroup_name, tmp_block)
            case 'interface':
                num, tmp_block = get_block(config_data, num)
                create_interface(data, tmp_block)
            case 'route':
                create_route(data, x)
            case 'telnet' | 'ssh'| 'http':
                match x:
                    case ['telnet' | 'ssh', ip, mask, zone_name]:
                        if ip not in ('version', 'key-exchange', 'cipher'):
                            data['cli-ssh'].append({
                                'zone': zone_name,
                                'ip': func.pack_ip_address(ip, mask)
                            })
                    case ['http', ip, mask, zone_name]:
                            data['web-console'].append({
                                'zone': zone_name,
                                'ip': func.pack_ip_address(ip, mask)
                            })
            case 'aaa-server':
                num, tmp_block = get_block(config_data, num)
                create_auth_servers(data, x, tmp_block)
            case 'time-range':
                num, tmp_block = get_block(config_data, num)
                data['time-range'][x[1].translate(trans_name)] = tmp_block
            case 'clock':
                data['timezone'] = TIME_ZONE.get(x[3], "Europe/Moscow")
            case 'ntp':
                match x:
                    case ['ntp', 'server', ip, *other]:
                        data['ntp'].append(ip)
            case 'dhcp':
                create_dhcp_settings(data, x[1:])
            case 'username':
                if x[2] == 'password':
                    data['local-users'][x[1]] = []
            case 'user-identity':
                create_user_identity_domains(data, x[1:])
            case 'object':
                match x[1]:
                    case 'service':
                        num, tmp_block = get_block(config_data, num)
                        data['services'][x[2]] = tmp_block
                    case 'network':
                        num, tmp_block = get_block(config_data, num)
                        if tmp_block:
                            match tmp_block[0][0]:
                                case 'nat':
                                    data['dnat_rules'][x[2]] = tmp_block[0]
                                case 'subnet'|'host'|'range':
                                    data['ip_lists'][x[2]] = tmp_block
                                case 'fqdn':
                                    data['url_lists'][x[2]] = tmp_block
                                case _:
                                    parent.stepChanged.emit(f'bRED|    object network {x[2]} не конвертирован.')
                        else:
                            parent.stepChanged.emit(f'rNOTE|    object network {x[2]} не конвертирован так как не имеет содержимого.')
            case 'object-group':
                match x[1]:
                    case 'network':
                        num, tmp_block = get_block(config_data, num)
                        data['network-group'][x[2]] = tmp_block
                    case 'service':
                        num, tmp_block = get_block(config_data, num)
                        data['service-group']['|'.join(x[2:])] = tmp_block
                    case 'protocol':
                        num, tmp_block = get_block(config_data, num)
                        data['protocol-group'][x[2]] = tmp_block
                    case 'user':
                        num, tmp_block = get_block(config_data, num)
                        data['local-groups'][x[2]] = tmp_block
                    case 'icmp-type':
                        num, tmp_block = get_block(config_data, num)
                        data['icmp-group'][x[2]] = tmp_block
                    case _:
                        parent.stepChanged.emit(f'bRED|    object network {x[2]} не конвертирован.')
            case 'access-group':
                create_access_group(data, x[1:])
        num += 1

    num = 0
    remark = []
    while (len(config_data) - num):
        line = config_data[num]
        if line[:1] in {':', '!'}:
            num += 1
            continue
        tmp_block = []
        x = line.translate(trans_table).rsplit(' ')
        match x[0]:
            case 'access-list':
                match x[2]:
                    case 'remark':
                        line = config_data[num+1]
                        y = line.translate(trans_table).rstrip().split(' ')
                        if y[1] == x[1]:
                            remark.append(' '.join(x[3:]))
                    case 'extended':
                        create_ace(data, x[1], x[3:], remark)
                        remark.clear()
                    case 'line':
                        if x[4] == 'extended':
                            create_ace(data, x[1], x[5:], remark)
                        remark.clear()
                    case 'webtype':
                        create_webtype_ace(data, x[1], x[3:], remark)
                        remark.clear()
                    case _:
                        string = line.rstrip('\n')
                        parent.stepChanged.emit('bRED|    Access-list "{string}" - не обработан.')
#            case 'nat':
#                convert_nat_rule(x)
        num += 1

#    print(json.dumps(data, indent=4))

    json_file = os.path.join(path, 'cisco_asa.json')
    with open(json_file, 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    if error:
        parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Cisco ASA в формат json.')
    else:
        parent.stepChanged.emit(f'BLACK|    Конфигурация Cisco ASA в формате json выгружена в файл "{json_file}".')

def get_block(config_data, num):
    """Читаем файл и создаём блок записей для раздела конфигурации"""
    block = []
    data_index = num + 1
    while config_data[data_index].startswith(' '):
        block.append(config_data[data_index].translate(trans_table).strip().split(' '))
        data_index += 1 
    return data_index - 1, block

def create_dns_servers(data, x):
    """Заполняем список системных DNS"""
    data['dns']['system_dns'].append(x[2])

def create_dns_rules(data, rule_name, data_block):
    """
    Если в data_block нет domain-name, то создаём системные DNS-сервера.
    Если есть, создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS.
    """
    dns_rule = {
        "name": rule_name,
        "domains": [],
        "dns_servers": [],
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

def create_interface(data, data_block):
    """Конвертируем интерфейсы VLAN."""
    iface = {
        'nameif': '',
        'description': '',
        'vlan': 0,
        'ipv4': ''
    }
    for item in data_block:
            match item[0]:
                case 'description':
                    iface['description'] = ' '.join(item[1:])
                case 'vlan':
                    iface['vlan'] = int(item[1])
                case 'nameif':
                    iface['nameif'] = item[1]
                case 'ip':
                    iface['ipv4'] = func.pack_ip_address(item[2], item[3])
    if iface['vlan']:
        data['ifaces'].append(iface)

def create_route(data, array):
    """Конвертируем шлюзы и статические маршруты в VRF по умолчанию"""
    [iface, network, mask, next_hop, *other] = array[1:]
    iface = iface.translate(trans_name)
    if network == '0':
        network = '0.0.0.0'
    if mask == '0':
        mask = '0.0.0.0'
    if network == mask == '0.0.0.0':
        gtw_name = f"{iface} (backup)" if iface in data['gateways'] else iface
        gateway = {
            "ipv4": next_hop,
            "weight": int(other[0]),
        }
        data['gateways'][gtw_name] = gateway
    else:
        network_dest = func.pack_ip_address(network, mask)
        route = {
            "name": f"Route for {network_dest}",
            "dest": network_dest,
            "gateway": next_hop,
            "metric": int(other[0])
        }
        data['routes'].append(route)

def create_auth_servers(data, x, data_block):
    """Конвертируем сервера авторизации"""
    match x:
        case ['aaa-server', auth_server, 'protocol', protocol]:
            data['auth-type'][auth_server] = protocol

        case ['aaa-server', auth_server, zone_name, 'host', ip]:
            if (protocol := data['auth-type'].get(auth_server), None):
                auth_srv = {
                    'name': f'{auth_server} ({ip})',
                    'description': '',
                    'address': ip,
                }
                if protocol in ['ldap', 'kerberos']:
                    auth_srv['description'] = 'ldap'
                if protocol == 'radius':
                    auth_srv['description'] = 'radius'
                if protocol.startswith('tacacs'):
                    auth_srv['description'] = 'tacacs'
                auth_srv.update({k: v for k, v in data_block})
                data['auth_servers'].append(auth_srv)

def create_dhcp_settings(data, dhcp_array):
    """Конвертируем настройки DHCP"""
    match dhcp_array:
        case ['address', ip_range, name]:
            data['dhcp-subnets'][name] = {
                'ip_range': ip_range,
                'reserv': []
            }
        case ['reserve-address', ip, mac, name]:
            data['dhcp-subnets'][name]['reserv'].append([ip, mac])
        case ['dns', *ips]:
            data['dhcp-opt']['dns'] = ips
        case ['lease', lease]:
            data['dhcp-opt']['lease'] = int(lease) if (120 < int(lease) < 3600000) else 3600
        case ['domain', name]:
            data['dhcp-opt']['domain'] = name
        case ['option', code, 'ip'|'ascii', *ips]:
            data['dhcp-opt']['options'].append([int(code), ", ".join(ips)])
    
def create_user_identity_domains(data, line):
    """Определяем домены идентификации"""
    match line:
        case ['domain', domain, 'aaa-server', server]:
            domain = domain.split(".")
            if len(domain) == 1:
                data['identity_domains'][domain[0]] = data['domain-name']
            else:
                for item in data['auth_servers']:
                    if item['name'].startswith(domain[0]):
                        dn = ".".join([y[1] for y in [x.split("=") for x in item['ldap-base-dn'].split(",")]]).lower()
                        data['identity_domains'][domain[0]] = dn
                        break
        case ['default-domain', domain]:
            if domain != 'LOCAL':
                domain = domain.split(".")
                data['identity_domains']['default'] = data['identity_domains'][domain[0]]

def create_access_group(data, x):
    """
    Конвертируе access-group. Сопоставляем имя access-list с зоной интерфейса и определяем источник это или назначение.
    """
    if x[0] not in data['direction']:
        data['direction'][x[0]] = {
            "src_zones": [],
            "dst_zones": []
        }
    match x:
        case [access_list_name, 'in', 'interface', zone_name]:
            data['direction'][access_list_name]['src_zones'].append(zone_name.translate(trans_name))
        case [access_list_name, 'out', 'interface', zone_name]:
            data['direction'][access_list_name]['dst_zones'].append(zone_name.translate(trans_name))
        case [access_list_name, 'interface', ifname, 'global']:
            pass
        case _:
            data['direction'].pop(x[0], None)

def create_ace(data, acs_name, rule_block, remark):
    """Подгатавливаем access-list к конвертации. Формируем имя правила и описание."""
    data['fw_rule_number'] += 1
    name = f'Rule {data["fw_rule_number"]}'
    data['fw_access-list'][name] = {
        'name': acs_name,
        'description': ', '.join(remark),
        'content': rule_block
    }

def create_webtype_ace(data, acs_name, rule_block, remark):
    """Подгатавливаем access-list к конвертации. Формируем имя правила и описание."""
    data['cf_rule_number'] += 1
    name = f'Rule {data["cf_rule_number"]}'
    data['cf_access-list'][name] = {
        'name': acs_name,
        'description': ', '.join(remark),
        'content': rule_block
    }

#------------------------------------ Конвертация словаря data в json UG NGFW -----------------------------------------
def convert_modules(parent, path, data):
    """Выгружаем UserGate->Настройки->Модули"""
    parent.stepChanged.emit('BLUE|Конвертация настроек раздела "UserGate->Настройки->Модули".')
    if data['domain-name']:
        modules = {
            'auth_captive': f'auth.{data["domain-name"]}',
            'logout_captive': f'logout.{data["domain-name"]}',
            'block_page_domain': f'block.{data["domain-name"]}',
            'ftpclient_captive': f'ftpclient.{data["domain-name"]}',
            'ftp_proxy_enabled': False
        }

        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        json_file = os.path.join(current_path, 'config_settings_modules.json')
        with open(json_file, 'w') as fh:
            json.dump(modules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройка модулей выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет настроек модулей для экспорта.')


def convert_zones(parent, path, data):
    """Создаём зону"""
    parent.stepChanged.emit('BLUE|Конвертация Зон.')
    if data['zones']:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Zones')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        zones = []
        for key, value in data['zones'].items():
            if key.lower() == 'management':
                continue
            zones.append({
                'name': key,
                'description': 'Перенесено с Cisco ASA',
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
                        'enabled': False,
                        'service_id': 'SNMP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Captive-портал и страница блокировки',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'XML-RPC для управления',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Кластер',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'VRRP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Консоль администрирования',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'DNS',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'HTTP(S)-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Агент аутентификации',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SMTP(S)-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'POP(S)-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'CLI по SSH',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'VPN',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SCADA',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Reverse-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Веб-портал',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SAML сервер',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Log analyzer',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'OSPF',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'BGP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SNMP-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'SSH-прокси',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Multicast',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'NTP сервис',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'RIP',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'UserID syslog collector',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'BFD',
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 'Endpoints connect',
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
            })
        json_file = os.path.join(current_path, 'config_zones.json')
        with open(json_file, 'w') as fh:
            json.dump(zones, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки зон выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет зон для экспорта.')


def convert_zone_access(parent, path, data):
    """Устанавливаем контроль доступа для зоны"""
    parent.stepChanged.emit('BLUE|Конвертация контроля доступа для зон.')
    section_path = os.path.join(path, 'Network')
    current_path = os.path.join(section_path, 'Zones')
    json_file = os.path.join(current_path, 'config_zones.json')
    err, zones = func.read_json_file(parent, json_file)
    if err:
        return

    indicator = 0
    if data['dns']['domain-lookup']:
        indicator = 1
        for zone_name in data['dns']['domain-lookup']:
            for zone in zones:
                if zone['name'] == zone_name:
                    for service in zone['services_access']:
                        if service['service_id'] == 'DNS':
                            service['enabled'] = True

    if data['cli-ssh']:
        indicator = 1
        for item in data['cli-ssh']:
            if item['zone'] in data['zones']:
                for zone in zones:
                    if zone['name'] == item['zone']:
                        for service in zone['services_access']:
                            if service['service_id'] == 'CLI по SSH':
                                service['enabled'] = True
                                service['allowed_ips'].append(item['ip'])

    if data['web-console']:
        indicator = 1
        for item in data['web-console']:
            if item['zone'] in data['zones']:
                for zone in zones:
                    if zone['name'] == item['zone']:
                        for service in zone['services_access']:
                            if service['service_id'] == 'Captive-портал и страница блокировки':
                                service['enabled'] = True
                            if service['service_id'] == 'Консоль администрирования':
                                service['enabled'] = True
                                service['allowed_ips'].append(item['ip'])

    if indicator:
        """Преобразуем список IP в группу IP-адресов. Созданную группу добавляем в библиотеку."""
        for zone in zones:
            for x in zone['services_access']:
                if x['allowed_ips']:
                    list_name = f'For Zone: {zone["name"]} (service: {x["service_id"]})'
                    iplist_name = func.create_ip_list(parent, path, ips=x['allowed_ips'], name=list_name)
                    if iplist_name:
                        x['allowed_ips'] = [["list_id", iplist_name]]
                    else:
                        parent.stepChanged.emit(f'ORANGE|    Не удалось создать IP-list "{list_name}". Оставляем отдельные IP-адреса.')

        json_file = os.path.join(current_path, 'config_zones.json')
        with open(json_file, 'w') as fh:
            json.dump(zones, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Параметры контроля доступа на зонах установлены.')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет параметров контроля доступа зон для экспорта.')


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
    """Создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS"""
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
                'description': 'Перенесено с Cisco ASA',
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


def convert_vlan_interfaces(parent, path, data):
    """Конвертируем интерфейсы VLAN."""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
    if data['ifaces']:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Interfaces')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        ifaces = []
        for item in data['ifaces']:
            ifaces.append({
                'name': item.get('nameif', item['ipv4']),
                'kind': 'vlan',
                'enabled': False,
                'description': item['description'],
                'zone_id': item['nameif'] if item['nameif'] in data['zones'] else 0,
                'master': False,
                'netflow_profile': 'undefined',
                'lldp_profile': 'undefined',
                'ipv4': [item['ipv4']],
                'ifalias': '',
                'flow_control': False,
                'mode': 'static',
                'mtu': data['zones'][item['nameif']] if item['nameif'] in data['zones'] else 1500,
                'tap': False,
                'dhcp_relay': {
                    'enabled': False,
                    'host_ipv4': '',
                    'servers': []
                },
                'vlan_id': item['vlan'],
                'link': ''
            })

        if ifaces:
            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump(ifaces, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit(f'GRAY|    Нет интерфейсов VLAN для экспорта.')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет интерфейсов VLAN для экспорта.')


def convert_gateways(parent, path, data):
    """Конвертируем шлюзы"""
    parent.stepChanged.emit('BLUE|Конвертация шлюзов.')
    if data['gateways']:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Gateways')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        gateways = []
        for key, value in data['gateways'].items():
            gateways.append({
                'name': key,
                'enabled': True,
                'description': '',
                'ipv4': value['ipv4'],
                'vrf': 'default',
                'weight': value['weight'],
                'multigate': False,
                'default': False,
                'iface': 'undefined',
                'is_automatic': False,
            })

        if gateways:
            json_file = os.path.join(current_path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(gateways, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Настройки шлюзов выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit(f'GRAY|    Нет шлюзов для экспорта.')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет шлюзов для экспорта.')


def convert_routes(parent, path, data):
    """Конвертируем статические маршруты"""
    parent.stepChanged.emit('BLUE|Конвертация статических маршрутов.')
    if data['routes']:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'VRF')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        default_vrf = {
            "name": "default",
            "descriprion": "",
            "interfaces": [],
            "routes": [],
            "ospf": {},
            "bgp": {},
            "rip": {},
            "pimsm": {}
        }
        for route in data['routes']:
            default_vrf['routes'].append({
                'name': route['name'],
                'description': '',
                'enabled': False,
                'dest': route['dest'],
                'gateway': route['gateway'],
                'ifname': 'undefined',
                'kind': 'unicast',
                'metric': route['metric']
            })

        json_file = os.path.join(current_path, 'config_vrf.json')
        with open(json_file, 'w') as fh:
            json.dump([default_vrf], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет статических маршрутов для экспорта.')


def convert_auth_servers(parent, path, data):
    """Конвертируем сервера аутентификации"""
    parent.stepChanged.emit('BLUE|Конвертация серверов аутентификации.')
    if data['auth_servers']:
        section_path = os.path.join(path, 'UsersAndDevices')
        current_path = os.path.join(section_path, 'AuthServers')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        ldap_servers = []
        for item in data['auth_servers']:
            if item['description'] == 'ldap':
                dn = ''
                ldap_srv = {
                    'name': item['name'],
                    'description': 'Перенесено с Cisco ASA',
                    'enabled': True,
                    'ssl': False,
                    'address': item['address'],
                    'bind_dn': '',
                    'password': '',
                    'domains': [],
                    'roots': [],
                    'keytab_exists': False
                }
                if 'ldap-over-ssl' in item and item['ldap-over-ssl'] == 'enable':
                    ldap_srv['ssl'] = True
                if 'ldap-base-dn' in item:
                    dn = ".".join([y[1] for y in [x.split("=") for x in item['ldap-base-dn'].split(",")]]).lower()
                    ldap_srv['domains'].append(dn)
                    ldap_srv['roots'].append(item['ldap-base-dn'])
                if 'ldap-login-dn' in item:
                    login = item['ldap-login-dn'] if '=' in item['ldap-login-dn'] else f'{item["ldap-login-dn"]}@{dn}'
                    ldap_srv['bind_dn'] = login
                if 'ldap-login-password' in item:
                    ldap_srv['password'] = item['ldap-login-password']
                if 'kerberos-realm' in item:
                    ldap_srv['domains'].append(item['kerberos-realm'])
                    ldap_srv['roots'].append(item['kerberos-realm'])
                    ldap_srv['bind_dn'] = f'login@{item["kerberos-realm"]}'
                    ldap_srv['password'] = "secret"
                ldap_servers.append(ldap_srv)

        radius_servers = []
        for item in data['auth_servers']:
            if item['description'] == 'radius':
                address = {'host': item['address'], 'port': int(item.get('authentication-port', 1812))}
                radius_servers.append({
                    'name': item['name'],
                    'description': 'Перенесено с Cisco ASA',
                    'enabled': True,
                    'secret': item.get('key', ''),
                    'addresses': [address]
                })

        tacacs_servers = []
        for item in data['auth_servers']:
            if item['description'] == 'tacacs':
                tacacs_servers.append({
                    'name': item['name'],
                    'description': 'Перенесено с Cisco ASA',
                    'enabled': True,
                    'use_single_connection': False,
                    'timeout': int(item.get('timeout', 4)),
                    'address': item['address'],
                    'port': int(item.get('server-port', 49)),
                    'secret': item.get('key', ''),
                })

        if ldap_servers:
            json_file = os.path.join(current_path, 'config_ldap_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Сервера аутентификации LDAP выгружены в файл "{json_file}".')

        if radius_servers:
            json_file = os.path.join(current_path, 'config_radius_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Сервера аутентификации RADIUS выгружены в файл "{json_file}".')

        if tacacs_servers:
            json_file = os.path.join(current_path, 'config_tacacs_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(tacacs_servers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Сервера аутентификации TACACS выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет серверов аутентификации для экспорта.')


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
            'description': '',
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


def convert_settings_ui(parent, path, timezone):
    """Конвертируем часовой пояс"""
    parent.stepChanged.emit('BLUE|Конвертация часового пояса.')
    if timezone:
        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        settings = {"ui_timezone": timezone}

        json_file = os.path.join(current_path, 'config_settings_ui.json')
        with open(json_file, 'w') as fh:
            json.dump(settings, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Значение часового пояса выгружено в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет часового пояса для экспорта.')


def convert_ntp_settings(parent, path, ntp_data):
    """Конвертируем настройки для NTP"""
    parent.stepChanged.emit('BLUE|Конвертация настроек NTP.')
    if ntp_data:
        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        ntp = {
            "ntp_servers": [],
            "ntp_enabled": True,
            "ntp_synced": True
        }
        for ip in ntp_data:
            if len(ntp['ntp_servers']) < 2:
                ntp['ntp_servers'].append(ip)

        json_file = os.path.join(current_path, 'config_ntp.json')
        with open(json_file, 'w') as fh:
            json.dump(ntp, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройка NTP выгружена в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет настроек NTP для экспорта.')


def convert_dhcp_settings(parent, path, data):
    """Конвертируем настройки DHCP"""
    parent.stepChanged.emit('BLUE|Конвертация настроек DHCP.')
    if data['dhcp-subnets']:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DHCP')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return
    
        dhcp_subnets = []
        for key, item in data['dhcp-subnets'].items():
            ips = item['ip_range'].split('-')
            netmask = '255.255.255.0'
            if data['dhcp-opt']['options']:
                options = [x for x in data['dhcp-opt']['options'] if x[0] != 3]
                gateways = [y for x, y in data['dhcp-opt']['options'] if x == 3]
                gateway = gateways[0] if gateways else f'{ips[0].rpartition(".")[0]}.1'
                for mask in ('255.255.255.0', '255.255.0.0', '255.0.0.0'):
                    sub1 = ipaddress.ip_interface(f'{gateway}/{mask}')
                    sub2 = ipaddress.ip_interface(f'{ips[0]}/{mask}')
                    if sub2.ip in sub1.network:
                        netmask = mask
                        break
            else:
                options = []
                gateway = f'{ips[0].rpartition(".")[0]}.1'
            reserve = []
            number = 0
            for ip, mac in item['reserv']:
                number += 1
                mac_address = ":".join([f"{x[:2]}:{x[2:]}" for x in mac.split('.')])
                reserve.append({"mac": mac_address.upper(), "ipv4": ip, "hostname": f"Any{key.title()}-{number}"})

            dhcp_subnets.append({
                'name': f'DHCP server for {key}',
                'enabled': False,
                'description': 'Перенесено с Cisco ASA',
                'start_ip': ips[0],
                'end_ip': ips[1],
                'lease_time': lease if (120 < (lease := int(data['dhcp-opt']['lease'])) < 3600000) else 3600,
                'domain': data['dhcp-opt']['domain'],
                'gateway': gateway,
                'boot_filename': '',
                'boot_server_ip': '',
                'iface_id': 'port0',
                'netmask': netmask,
                'nameservers': data['dhcp-opt']['dns'],
                'ignored_macs': [],
                'hosts': reserve,
                'options': options,
            })

        json_file = os.path.join(current_path, 'config_dhcp_subnets.json')
        with open(json_file, 'w') as fh:
            json.dump(dhcp_subnets, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет настроек DHCP для экспорта.')


def convert_local_groups(parent, path, data):
    """Конвертируем локальные группы пользователей"""
    parent.stepChanged.emit('BLUE|Конвертация локальных групп пользователей.')
    if data['local-groups']:
        section_path = os.path.join(path, 'UsersAndDevices')
        current_path = os.path.join(section_path, 'Groups')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        groups = {}
        for key, value in data['local-groups'].items():
            group = {
                "name": key,
                "description": "",
                "is_ldap": False,
                "is_transient": False,
                "users": []
            }
            for item in value:
                match item:
                    case ['user', user]:
                        user_list = user.split("\\")
                        if user_list[0] == 'LOCAL' and user_list[1] in data['local-users']:
                            group['users'].append(user_list[1])
                        elif user_list[0] in data['identity_domains']:
                            group['users'].append(f"{user_list[1]} ({data['identity_domains'][user_list[0]]}\\{user_list[1]})")
                        else:
                            if len(user_list) == 1:
                                if 'default' in data['identity_domains']:
                                    group['users'].append(f"{user_list[0]} ({data['identity_domains']['default']}\\{user_list[0]})")
                                else:
                                    group['users'].append(user_list[0])
                    case ['group-object', group_name]:
                        group['users'].extend(groups[group_name]['users'])
                    case ['description', *content]:
                        group['description'] = " ".join(content)
            groups[key] = group

        for key, value in groups.items():
            for user in value['users']:
                if len(user.split(' ')) == 1:
                    data['local-users'][user].append(key)

        json_file = os.path.join(current_path, 'config_groups.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in groups.values()], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список локальных групп пользователей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет локальных групп пользователей для экспорта.')


def convert_local_users(parent, path, local_users):
    """Конвертируем локального пользователя"""
    parent.stepChanged.emit('BLUE|Конвертация локальных пользователей.')
    if local_users:
        section_path = os.path.join(path, 'UsersAndDevices')
        current_path = os.path.join(section_path, 'Users')
        err, msg = func.create_dir(current_path)
        if err:
            parent.error = 1
            parent.stepChanged.emit(f'RED|    {msg}.')
            return

        users = []
        for user_name, groups in local_users.items():
            users.append({
                "name": user_name,
                "enabled": True,
                "auth_login": user_name.translate(trans_userlogin),
                "is_ldap": False,
                "static_ip_addresses": [],
                "ldap_dn": "",
                "emails": [],
                "first_name": "",
                "last_name": "",
                "phones": [],
                "groups": groups
            })
        json_file = os.path.join(current_path, 'config_users.json')
        with open(json_file, 'w') as fh:
            json.dump(users, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет локальных пользователей для экспорта.')


def convert_service_object(parent, path, data):
    """Конвертируем сетевой сервис"""
    parent.stepChanged.emit('BLUE|Конвертация сервисов.')
    if not data['services']:
        parent.stepChanged.emit(f'GRAY|    Нет сервисов для экспорта.')
        return

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {msg}.')
        return

    for key, value in data['services'].items():
        service = {
            'name': key,
            'description': '',
            'protocols': []
        }
        port = ''
        source_port = ''
        proto = None

        for item in value:
            match item:
                case ['service', protocol]:
                    if protocol.isdigit():
                        protocol = ip_proto.get(protocol, None)
                    if protocol and protocol in network_proto:
                        proto = protocol
                    else:
                        parent.stepChanged.emit(f'bRED|    Сервис {name} не конвертирован. Протокол {protocol} не поддерживается в UG NGFW.')
                case ['service', 'icmp', *other]:
                    proto = 'icmp'
                case ['service', 'sctp', *other]:
                    proto = 'sctp'
                case ['service', 'tcp' | 'udp', *other]:
                    proto = item[1]
                    match other:
                        case ['source', 'eq', src_port]:
                            source_port = get_service_number(src_port)
                        case ['source', 'range', port1, port2]:
                            source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                        case ['destination', 'eq', dst_port]:
                            port = get_service_number(dst_port)
                        case ['destination', 'range', port1, port2]:
                            port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                        case ['source', 'eq', src_port, 'destination', protocol, *dst_ports]:
                            source_port = get_service_number(src_port)
                            port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                        case ['source', 'range', port1, port2, 'destination', protocol, *dst_ports]:
                            source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                            port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                        case _:
                            parent.stepChanged.emit(f'bRED|    Сервис {name} не конвертирован. Операторы lt, gt, neq не поддерживаются в UG NGFW.')
                case ['description', *content]:
                    service['description'] = " ".join(content)

        if proto:
            service['protocols'].append({
                'proto': proto,
                'port': port,
                'app_proto': '',
                'source_port': source_port,
                'alg': ''
            })
            data['services'][key] = service

    if 'Any SCTP' not in data['services']:
        service = {
            'name': 'Any SCTP',
            'description': '',
            'protocols': [{'proto': 'sctp', 'port': '', 'app_proto': '', 'source_port': '', 'alg': ''}]
            }
        data['services']['Any SCTP'] = service

    json_file = os.path.join(current_path, 'config_services_list.json')
    with open(json_file, 'w') as fh:
        json.dump([x for x in data['services'].values()], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')


def convert_ip_lists(parent, path, ip_lists):
    """Конвертируем object network в списки IP-адресов"""
    parent.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
    if not ip_lists:
        parent.stepChanged.emit(f'GRAY|    Нет списков IP-адресов для экспорта.')
        return

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {msg}.')
        return

    for key, value in ip_lists.items():
        parent.ip_lists.add(key)
        ip_list = {
            'name': key,
            'description': '',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        for item in value:
            match item:
                case ['subnet', ip, mask]:
                    subnet = ipaddress.ip_network(f'{ip}/{mask}')
                    ip_list['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
                case ['host', ip]:
                    ip_list['content'].append({'value': ip})
                case ['range', start_ip, end_ip]:
                    ip_list['content'].append({'value': f'{start_ip}-{end_ip}'})
                case ['description', *content]:
                    ip_list['description'] = " ".join(content)

        json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список IP-адресов {ip_list["name"]} выгружен в файл "{json_file}".')

    parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


def convert_url_lists(parent, path, url_lists):
    """Конвертируем object network в списки URL"""
    parent.stepChanged.emit('BLUE|Конвертация списков URL.')
    if not url_lists:
        parent.stepChanged.emit(f'GRAY|    Нет списков URL для экспорта.')
        return

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'URLLists')
    err, msg = func.create_dir(current_path)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {msg}.')
        return

    for key, value in url_lists.items():
        url_list = {
            'name': key,
            'description': '',
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': []
        }
        for item in value:
            match item:
                case ['fqdn', domain_name]:
                    url_list['content'].append({'value': domain_name})
                case ['fqdn', 'v4', domain_name]:
                    url_list['content'].append({'value': domain_name})
                case ['description', *content]:
                    url_list['description'] = " ".join(content)

        json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(url_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список URL {url_list["name"]} выгружен в файл "{json_file}".')

    parent.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')


def convert_network_object_group(parent, path, data):
    """Конвертируем object-group network в список IP-адресов и список URL если object-group содержит объект с FQDN"""
    parent.stepChanged.emit('BLUE|Конвертация групп IP-адресов и URL.')
    if not data['network-group']:
        parent.stepChanged.emit(f'GRAY|    Нет групп IP-адресов и URL для экспорта.')
        return

    section_path = os.path.join(path, 'Libraries')
    ip_path = os.path.join(section_path, 'IPAddresses')
    url_path = os.path.join(section_path, 'URLLists')

    ip_groups = {}
    url_groups = {}
    for key, value in data['network-group'].items():
        ip_list = {
            'name': key,
            'description': '',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        url_list = {
            'name': key,
            'description': '',
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': []
        }
        for item in value:
            match item:
                case ['network-object', 'host', ip]:
                    ip_list['content'].append({'value': ip})
                case ['network-object', 'object', object_name]:
                    try:
                        ip_list['content'].extend(match_item(data['ip_lists'][object_name]))
                    except KeyError:
                        url_list['content'].extend(match_item(data['url_lists'][object_name]))
                case ['network-object', ip, mask]:
                    subnet = ipaddress.ip_network(f'{ip}/{mask}')
                    ip_list['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
                case ['group-object', group_name]:
                    if group_name in ip_groups:
                        ip_list['content'].append({'list': group_name})
                    elif group_name in url_groups:
                        url_list['content'].extend(url_groups[group_name])
                    else:
                        parent.stepChanged.emit(f'bRED|    Не найдена группа URL/IP-адресов "{group_name}" для object-group "{key}".')
                case ['description', *content]:
                    ip_list['description'] = ' '.join(content)
                    url_list['description'] = ' '.join(content)

        if ip_list['content']:
            ip_groups[key] = ip_list['content']
            parent.ip_lists.add(key)
            data['ip_lists'][key] = []
            json_file = os.path.join(ip_path, f'{ip_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

        if url_list['content']:
            url_groups[key] = url_list['content']
            data['url_lists'][key] = []
            json_file = os.path.join(url_path, f'{url_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

    parent.stepChanged.emit(f'GREEN|    Списки групп URL/IP-адресов выгружены.')


def convert_service_object_group(parent, path, data):
    """Конвертируем object-group service в список сервисов"""
    parent.stepChanged.emit('BLUE|Конвертация групп сервисов.')
    if not data['service-group']:
        parent.stepChanged.emit(f'GRAY|    Нет групп сервисов для экспорта.')
        return

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {msg}.')
        return

    for key, value in data['service-group'].items():
        descr = key.split('|')
        service = {
            'name': descr[0],
            'description': '',
            'protocols': []
        }
        for item in value:
            proto_array = []
            source_port = ''
            port = ''
            match item:
                case ['service-object', 'object', object_name]:
                    service['protocols'].extend(data['services'][object_name]['protocols'])
                case ['service-object', 'icmp', *other]:
                    proto_array.insert(0, 'icmp')
                case ['service-object', 'icmp6', *other]:
                    proto_array.insert(0, 'ipv6-icmp')
                case ['service-object', 'sctp', *other]:
                    proto_array.insert(0, 'sctp')
                case ['service-object', 'tcp'|'udp'|'tcp-udp', *other]:
                    proto_array = item[1].split('-')
                    match other:
                        case ['source', 'eq', src_port]:
                            source_port = get_service_number(src_port)
                        case ['source', 'range', port1, port2]:
                            source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                        case ['destination', 'eq', dst_port]:
                            port = get_service_number(dst_port)
                        case ['destination', 'range', port1, port2]:
                            port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                        case ['source', 'eq', src_port, 'destination', protocol, *dst_ports]:
                            source_port = get_service_number(src_port)
                            port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                        case ['source', 'range', port1, port2, 'destination', protocol, *dst_ports]:
                            source_port = f'{get_service_number(port1)}-{get_service_number(port2)}'
                            port = get_service_number(dst_ports[0]) if protocol == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                        case ['source'|'destination', 'lt'|'gt'|'neq', *tmp]:
                            parent.stepChanged.emit(f'bRED|    Сервис {item} в правиле {descr[0]} не конвертирован. Операторы lt, gt, neq не поддерживаются в UG NGFW.')
                            continue
                case ['service-object', protocol]:
                    if protocol.isdigit():
                        protocol = ip_proto.get(protocol, None)
                    if protocol and protocol in network_proto:
                        proto_array.insert(0, protocol)
                    else:
                        parent.stepChanged.emit(f'bRED|    Сервис {item} в {descr[0]} не конвертирован. Нельзя задать протокол {protocol} в UG NGFW.')
                        continue
                case ['port-object', 'eq'|'range', *dst_ports]:
                    proto_array = descr[1].split('-')
                    port = get_service_number(dst_ports[0]) if item[1] == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                case ['group-object', group_name]:
                    service['protocols'].extend(data['services'][group_name]['protocols'])
                case ['description', *content]:
                    service['description'] = " ".join(content)

            for proto in proto_array:
                service['protocols'].append({
                    'proto': proto,
                    'port': port,
                    'app_proto': '',
                    'source_port': source_port,
                    'alg': ''
                })

        data['services'][descr[0]] = service

    json_file = os.path.join(current_path, 'config_services_list.json')
    with open(json_file, 'w') as fh:
        json.dump([x for x in data['services'].values()], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'GREEN|    Список групп сервисов выгружен в файл "{json_file}".')


def convert_protocol_object_group(parent, path, data):
    """Конвертируем object-group protocol в список сервисов"""
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|    {msg}.')
        return

    parent.stepChanged.emit('BLUE|Конвертация групп протоколов в сервисы.')
    if data['service-group']:
        for key, value in data['protocol-group'].items():
            service = {
                'name': key,
                'description': '',
                'protocols': []
            }
            proto = set()
            for item in value:
                match item:
                    case ['protocol-object', protocol]:
                        if protocol.isdigit():
                            protocol = ip_proto.get(protocol, None)
                        if protocol and protocol in network_proto:
                            proto.add(protocol)
                        elif protocol == 'ip':
                            proto.update(['tcp', 'udp'])
                        else:
                            parent.stepChanged.emit(f'bRED|    Сервис {item} в {key} не конвертирован. Нельзя задать протокол {protocol} в UG NGFW.')
                            continue
                    case ['description', *content]:
                        service['description'] = " ".join(content)
            for x in proto:
                service['protocols'].append(
                    {
                        'proto': x,
                        'port': '',
                        'source_port': '',
                    }
                )
            data['services'][key] = service
    
    """Конвертируем object-group icmp в список сервисов"""
    if data['icmp-group']:
        for key in data['icmp-group']:
            service = {
                'name': key,
                'description': '',
                'protocols': [
                    {
                        'proto': 'icmp',
                        'port': '',
                        'source_port': '',
                    }
                ]
            }
            data['services'][key] = service

    json_file = os.path.join(current_path, 'config_services_list.json')
    with open(json_file, 'w') as fh:
        json.dump([x for x in data['services'].values()], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'GREEN|    Список групп протоколов выгружен в файл "{json_file}".')


def convert_firewall_rules(parent, path, data):
    """
    Конвертируем access-lists в правила МЭ.
    Не активные ACE пропускаются. ACE не назначенные интерфейсам пропускаются.
    ACE с именами ASA интерфейсов пропускаются.
    ACE c security-group и object-group-security пропускаются.
    """
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
    if not data['fw_access-list']:
        parent.stepChanged.emit(f'GRAY|    Нет правил межсетевого экрана для экспорта.')
        return

    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'Firewall')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    fw_rules = []
    for key, value in data['fw_access-list'].items():
        not_valid = {'inactive', 'interface', 'security-group', 'object-group-security'}
        intersection = not_valid.intersection(value['content'])
        if intersection:
            parent.stepChanged.emit(f'bRED|    ACE "{" ".join(value["content"])}" пропущено так как содержит параметр {intersection}.')
            continue

        deq = deque(value['content'])
        rule = {
            'name': f'{key} ({value["name"]})',
            'description': value['description'],
            'action': 'drop' if deq.popleft() == 'deny' else 'accept',
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
        if value['name'] not in data['direction']:
            parent.stepChanged.emit(f'LBLUE|    Для правила "{rule["name"]}" создайте зону зону "{value["name"]}" и укажите её как источник или назначение.')
        else:
            rule['src_zones'].extend(data['direction'][value['name']]['src_zones'])
            rule['dst_zones'].extend(data['direction'][value['name']]['dst_zones'])

        protocol = deq.popleft()
        match protocol:
            case 'object'|'object-group':
                protocol = deq.popleft()
                rule['services'].append(["service", protocol])
            case 'ip':
                pass
            case 'icmp':
                rule['services'].append(["service", "Any ICMP"])
            case 'tcp':
                rule['services'].append(["service", "Any TCP"])
            case 'udp':
                rule['services'].append(["service", "Any UDP"])
            case 'sctp':
                rule['services'].append(["service", "Any SCTP"])

        argument = deq.popleft()
        match argument:
            case 'object-group-user':
                rule['users'].append(['group', deq.popleft()])
            case 'user':
                user = deq.popleft()
                match user:
                    case 'any':
                        rule['users'].append(['special', 'known_user'])
                    case 'none':
                        rule['users'].append(['special', 'unknown_user'])
                    case _:
                        user_list = user.split("\\")
                        if user_list[0] == 'LOCAL' and user_list[1] in data['local-users']:
                            rule['users'].append(['user', user_list[1]])
                        elif user_list[0] in data['identity_domains']:
                            rule['users'].append(['user', f'{data["identity_domains"][user_list[0]]}\\{user_list[1]}'])
            case 'user-group':
                group = deq.popleft()
                group_list = group.split("\\\\")
                if group_list[0] in data['identity_domains']:
                    rule['users'].append(['group', f'{data["identity_domains"][group_list[0]]}\\{group_list[1]}'])
#            case 'interface':
#                zone = deq.popleft()
#                if zone in zones:
#                    rule['dst_zones'].append(zone)
            case _:
                ips_mode = 'src_ips'
                get_ips(parent, path, data, ips_mode, argument, rule, deq)

        while deq:
            argument = deq.popleft()
            match argument:
                case 'lt'|'gt'|'neq':
                    return
                case 'eq':
                    port = deq.popleft()
                    service_name = f'Eq {port} ({key})'
                    create_service(data, service_name, ips_mode, protocol, port)
                    rule['services'].clear()
                    rule['services'].append(["service", service_name])
                    parent.stepChanged.emit(f'NOTE|    Создан сервис "{service_name}" для правила "{rule["name"]}".')
                case 'range':
                    port1 = deq.popleft()
                    port2 = deq.popleft()
                    service_name = f'Range {port1}-{port2} (Rule {rule_number})'
                    create_service(service_name, ips_mode, protocol, port1, port2)
                    rule['services'].clear()
                    rule['services'].append(["service", service_name])
                    parent.stepChanged.emit(f'NOTE|    Создан сервис "{service_name}" для правила "{rule["name"]}".')
                case 'object-group':
                    ips_mode = 'dst_ips'
                    get_ips(parent, path, data, ips_mode, argument, rule, deq)
                case 'log':
                    other = list(deq)
                    deq.clear()
                    if 'time-range' in other:
                        time_object = other.index('time-range') + 1
                        rule['time_restrictions'].append(time_object)
                case 'time-range':
                    rule['time_restrictions'].append(deq.popleft())
#                case 'interface':
#                    zone = deq.popleft()
#                   if zone in zones:
#                        rule['dst_zones'].append(zone)
                case _:
                    ips_mode = 'dst_ips'
                    get_ips(parent, path, data, ips_mode, argument, rule, deq)

        fw_rules.append(rule)
        parent.stepChanged.emit(f'BLACK|    Создано правило межсетевого экрана "{rule["name"]}".')

    json_file = os.path.join(current_path, 'config_firewall_rules.json')
    with open(json_file, 'w') as fh:
        json.dump(fw_rules, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'GREEN|    Список правил межсетевого экрана выгружен в файл "{json_file}".')

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
    else:
        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in data['services'].values()], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список сервисов, созданных для правил МЭ выгружен в файл "{json_file}".')


def convert_webtype_ace(parent, path, data):
    """Конвертируем access-list webtype в правило КФ. Не активные ACE пропускаются."""
    parent.stepChanged.emit('BLUE|Конвертация правил контентной фильтрации.')
    if not data['cf_access-list']:
        parent.stepChanged.emit(f'GRAY|    Нет правил контентной фильтрации для экспорта.')
        return

    section_path = os.path.join(path, 'SecurityPolicies')
    current_path = os.path.join(section_path, 'ContentFiltering')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    cf_rules = []
    for key, value in data['cf_access-list'].items():
        if 'inactive' in value['content']:
            parent.stepChanged.emit(f'bRED|    ACE "{" ".join(value["content"])}" пропущено так как содержит параметр "inactive".')
            continue

        deq = deque(value['content'])
        rule = {
            'name': f'{key} ({value["name"]})',
            'description': value['description'],
            'position': 'last',
            'action': 'drop' if deq.popleft() == 'deny' else 'accept',
            'public_name': '',
            'enabled': False,
            'enable_custom_redirect': False,
            'blockpage_template_id': -1,
            'users': [],
            'url_categories': [],
            'src_zones': [],
            'dst_zones': [],
            'src_ips': [],
            'dst_ips': [],
            'morph_categories': [],
            'urls': [],
            'referers': [],
            'referer_categories': [],
            'user_agents': [],
            'time_restrictions': [],
            'content_types': [],
            'http_methods': [],
            'src_zones_negate': False,
            'dst_zones_negate': False,
            'src_ips_negate': False,
            'dst_ips_negate': False,
            'url_categories_negate': False,
            'urls_negate': False,
            'content_types_negate': False,
            'user_agents_negate': False,
            'custom_redirect': '',
            'enable_kav_check': False,
            'enable_md5_check': False,
            'rule_log': False,
            'scenario_rule_id': False,
            'layer': 'Content Rules',
            'users_negate': False
        }

        while deq:
            parameter = deq.popleft()
            match parameter:
                case 'url':
                    url = deq.popleft()
                    url_list_name = f"For {key} (Content Filtering)"
                    if create_url_list(parent, path, url, url_list_name):
                        rule['urls'].append(url_list_name)
                case 'tcp':
                    address = deq.popleft()
                    get_ips(parent, path, data, 'dst_ips', address, rule, deq)
                case 'time_range':
                    rule['time_restrictions'].append(deq.popleft())

        if rule['urls'] or rule['time_restrictions'] or rule['dst_ips']:
            cf_rules.append(rule)
            parent.stepChanged.emit(f'BLACK|    Создано правило контентной фильтрации "{rule["name"]}".')

    json_file = os.path.join(current_path, 'config_content_rules.json')
    with open(json_file, 'w') as fh:
        json.dump(cf_rules, fh, indent=4, ensure_ascii=False)

    if cf_rules:
        parent.stepChanged.emit(f'GREEN|    Список правил правил контентной фильтрации выгружен в файл "{json_file}".')
        parent.stepChanged.emit(f'LBLUE|       После импорта на UG NGFW, обязательно проверьте импортированные правила фильтрации контента.')
        parent.stepChanged.emit(f'LBLUE|       Отредактируйте правила, задайте зоны и адреса источника/назначения, пользователей и другие параметры.')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет правил контентной фильтрации для экспорта.')

def convert_dnat_rule(parent, path, data):
    """Конвертируем object network в правило DNAT или Port-форвардинг"""
    parent.stepChanged.emit('BLUE|Конвертация правил DNAT/Port-форвардинг.')
    if not data['dnat_rules']:
        parent.stepChanged.emit(f'GRAY|    Нет правил DNAT/Port-форвардинг для экспорта.')
        return

    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'NATandRouting')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    nat_rules = []
    for key, value in data['dnat_rules'].items():
        if ('inactive' in value) or ('interface' in value):
            parent.stepChanged.emit(f'bRED|    Правило NAT "{key}" пропущено так как не активно или содержит интерфейс.')
            continue
        if value[2] != 'static':
            continue

        data['nat_rule_number'] += 1
        rule = {
            'name': f'Rule {data["nat_rule_number"]} ({key})',
            'description': '',
            'action': 'dnat',
            'position': 'last',
            'zone_in': [],
            'zone_out': [],
            'source_ip': [],
            'dest_ip': [],
            'service': [],
            'target_ip': data['ip_lists'][key][0][1],
            'gateway': '',
            'enabled': False,
            'log': False,
            'log_session_start': True,
            'log_limit': False,
            'log_limit_value': '3/h',
            'log_limit_burst': 5,
            'target_snat': False,
            'snat_target_ip': '',
            'zone_in_nagate': False,
            'zone_out_nagate': False,
            'source_ip_nagate': False,
            'dest_ip_nagate': False,
            'port_mappings': [],
            'direction': 'input',
            'users': [],
            'scenario_rule_id': False
        }
        zone_out, zone_in = value[1][1:-1].split(',')
        if len(value) == 3 or 'net-to-net' in value:
            rule['zone_in'] = [zone_in] if zone_in != 'any' else []

        if value[3] in parent.ip_lists:
            rule['dest_ip'].append(["list_id", value[3]])
            rule['snat_target_ip'] = data['ip_lists'][value[3]][0][1]
        elif f"host {value[3]}" in parent.ip_lists:
            rule['dest_ip'].append(["list_id", f"host {value[3]}"])
            rule['snat_target_ip'] = value[3]
        else:
            iplist_name = func.create_ip_list(parent, path, ips=[value[3]])
            data['ip_lists'][iplist_name] = [['host', value[3]]]
            rule['dest_ip'].append(["list_id", iplist_name])
            rule['snat_target_ip'] = value[3]

        if 'service' in value:
            i = value.index('service')
            proto = value[i+1]
            src_port = value[i+3]
            dst_port = value[i+2]
            if src_port == dst_port:
                if dst_port in ug_services:
                    rule['service'].append(['service', ug_services[dst_port]])
                elif dst_port in data['services']:
                    rule['service'].append(['service', dst_port])
                else :
                    service = {
                        'name': dst_port,
                        'description': f'Service for DNAT rule ({rule["name"]})',
                        'protocols': [{
                            'proto': proto,
                            'port': service_ports.get(dst_port, dst_port),
                            'app_proto': '',
                            'source_port': '',
                            'alg': ''
                        }]
                    }
                    rule['service'].append(['service', dst_port])
                    data['services'][dst_port] = service
                    parent.stepChanged.emit(f'NOTE|    Создан сервис "{dst_port}" для правила "{rule["name"]}".')
            else:
                rule['action'] = 'port_mapping'
                rule['port_mappings'].append({
                    'proto': proto,
                    'src_port': int(service_ports.get(src_port, src_port)),
                    'dst_port': int(service_ports.get(dst_port, dst_port))
                })
        data['nat_rules'].append(rule)
        parent.stepChanged.emit(f'BLACK|    Создано правило DNAT/Port-форвардинг "{rule["name"]}".')

    json_file = os.path.join(current_path, 'config_nat_rules.json')
    with open(json_file, 'w') as fh:
        json.dump(data['nat_rules'], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'GREEN|    Список правил межсетевого экрана выгружен в файл "{json_file}".')

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'Services')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
    else:
        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in data['services'].values()], fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список сервисов, созданных для правил DNAT/Port-форвардинг выгружен в файл "{json_file}".')


#-------------------------------------------------------------------------------------------------------------
def convert_nat_rule(rule_block):
    """Конвертируем правило NAT"""
    if ('inactive' in rule_block) or ('interface' in rule_block):
        print(f'\033[36mПравило NAT "{rule_block}" пропущено так как не активно или содержит интерфейс.\033[0m')
        return

#    nonlocal natrule_number
    natrule_number = 0
    natrule_number += 1
    rule = {
        "name": f"Rule {natrule_number} NAT",
        "description": "",
        "action": "nat",
        "position": "last",
        "zone_in": [],
        "zone_out": [],
        "source_ip": [],
        "dest_ip": [],
        "service": [],
        "target_ip": "",
        "gateway": "",
        "enabled": False,
        "log": False,
        "log_session_start": True,
        "target_snat": False,
        "snat_target_ip": "",
        "zone_in_nagate": False,
        "zone_out_nagate": False,
        "source_ip_nagate": False,
        "dest_ip_nagate": False,
        "port_mappings": [],
        "direction": "input",
        "users": [],
        "scenario_rule_id": False
    }
    zone_in, zone_out = rule_block[1][1:-1].split(',')
    rule['zone_in'] = [zone_in.translate(trans_name)] if zone_in != 'any' else []
    rule['zone_out'] = [zone_out.translate(trans_name)] if zone_out != 'any' else []
    
    if 'dynamic' in rule_block:
        i = rule_block.index('dynamic')
        if rule_block[i+1] != 'any':
            if rule_block[i+1] == 'pat-pool':
                i += 1
            if rule_block[i+1] in ip_dict:
                rule['source_ip'].append(["list_id", rule_block[i+1]])
            elif f"host {rule_block[i+1]}" in ip_dict:
                rule['source_ip'].append(["list_id", f"host {rule_block[i+1]}"])
            else:
                rule['source_ip'].append(create_ip_list(rule_block[i+1]))
        if rule_block[i+2] != 'any':
            if rule_block[i+2] == 'pat-pool':
                i += 1
            if rule_block[i+2] in ip_dict:
                rule['dest_ip'].append(["list_id", rule_block[i+2]])
            elif f"host {rule_block[i+2]}" in ip_dict:
                rule['dest_ip'].append(["list_id", f"host {rule_block[i+2]}"])
            else:
                rule['dest_ip'].append(create_ip_list(rule_block[i+2]))
        if 'description' in rule_block:
            i = rule_block.index('description')
            rule['description'] = " ".join(rule_block[i+1:])
    else:
        return

    nat_rules.append(rule)

############################################# Служебные функции ###################################################
def create_service(data, name, ips_mode, protocol, port1, port2=None):
    """Для ACE. Создаём сервис, заданный непосредственно в правиле, а не в сервисной группе."""
    if port2:
        port = f'{get_service_number(port1)}-{get_service_number(port2)}'
    else:
        port = get_service_number(port1)
    if protocol in {'tcp', 'udp','sctp'}:
            service = {
                'name': name,
                'description': '',
                'protocols': [
                    {
                        'proto': protocol,
                        'port': '',
                        'app_proto': '',
                        'source_port': '',
                        'alg': ''
                    }
                ]
            }
            if ips_mode == 'src_ips':
                service['protocols'][0]['source_port'] = port
            else:
                service['protocols'][0]['port'] = port
    elif protocol in data['services']:
        service = copy.deepcopy(data['services'][protocol])
        service['name'] = name
        for item in service['protocols']:
            if ips_mode == 'src_ips':
                item['source_port'] = port
            else:
                item['port'] = port

    data['services'][name] = service


def get_ips(parent, path, data, ips_mode, address, rule, deq):
    """Для convert_firewall_rules()"""
    match address:
        case 'any'|'any4'|'any6':
            pass
        case 'object'|'object-group':
            ip_or_service_list = deq.popleft()
            if ip_or_service_list in data['ip_lists']:
                rule[ips_mode].append(["list_id", ip_or_service_list])
            elif ip_or_service_list in data['url_lists']:
                rule[ips_mode].append(["urllist_id", ip_or_service_list])
            elif ip_or_service_list in data['services']:
                rule['services'].clear()
                rule['services'].append(["service", ip_or_service_list])
        case 'host':
            ip = deq.popleft()
            iplist_name = func.create_ip_list(parent, path, ips=[ip], name=f'host {ip}')
            data['ip_lists'][iplist_name] = []
            rule[ips_mode].append(['list_id', iplist_name])
        case 'interface':
            ip = deq.popleft()
        case _:
            try:
                ipaddress.ip_address(address)   # проверяем что это IP-адрес или получаем ValueError
                mask = deq.popleft()
                subnet = ipaddress.ip_network(f'{address}/{mask}')
                ip = f'{address}/{subnet.prefixlen}'
                iplist_name = func.create_ip_list(parent, path, ips=[ip], name=f'subnet {ip}')
                data['ip_lists'][iplist_name] = []
                rule[ips_mode].append(['list_id', iplist_name])
            except (ValueError, IndexError):
                pass


def match_item(value):
    """Делаем content групп URL/IP-адресов для функции convert_network_object_group()"""
    content = []
    for item in value:
        match item:
            case ['subnet', ip, mask]:
                subnet = ipaddress.ip_network(f'{ip}/{mask}')
                content.append({'value': f'{ip}/{subnet.prefixlen}'})
            case ['host', ip]:
                content.append({'value': ip})
            case ['range', start_ip, end_ip]:
                content.append({'value': f'{start_ip}-{end_ip}'})
            case ['fqdn', domain_name]:
                content.append({'value': domain_name})
            case ['fqdn', 'v4', domain_name]:
                content.append({'value': domain_name})
    return content


def get_service_number(service):
    """Получить цифровое значение сервиса из его имени"""
    if service.isdigit():
        return service
    elif service in service_ports:
        return service_ports.get(service, service)


def create_url_list(parent, path, url, name):
    """Для ACL webtype - создаём URL-лист."""
    if url == 'any':
        return False
    proto, _, urlpath = url.partition("://")
    if proto not in ('http', 'https', 'ftp'):
        parent.stepChanged.emit(f'bRED|    URL {url} в access-list (webtype) пропущен. Неподдерживаемый тип протокола: "{proto}"')
        return False
    if ('?' in urlpath) or ('[' in urlpath) or (']' in urlpath):
        parent.stepChanged.emit(f'bRED|    URL {url} в access-list (webtype) пропущен. Не допустимые сиволы в url.')
        return False

    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'URLLists')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return False

    url_list = {
        'name': name,
        'description': '',
        'type': 'url',
        'url': '',
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {'list_compile_type': 'case_insensitive'},
        'content': [{'value': url}]
    }
    json_file = os.path.join(current_path, f'{url_list["name"].strip().translate(trans_filename)}.json')
    with open(json_file, 'w') as fh:
        json.dump(url_list, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'NOTE|    Создан список URL "{url_list["name"]}" и выгружен в файл "{json_file}".')

    return True

#-----------------------------------------------------------------------------------------------------------------------
def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
