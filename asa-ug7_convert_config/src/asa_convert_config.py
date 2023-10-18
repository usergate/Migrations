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
# Программа предназначена для переноса конфигурации с устройств Cisco ASA на NGFW UserGate версии 7.
# Версия 2.8
#

import os, sys, json
import stdiomask
import ipaddress
import copy
from datetime import datetime as dt
from collections import deque
from services import character_map, character_map_for_users, character_map_for_name, service_ports, ug_services, zone_services
from utm import UtmXmlRpc


def convert_file(utm, file_name):
    """Преобразуем файл конфигурации Cisco ASA в json."""
    print('Преобразование файла конфигурации Cisco ASA в json.')

    trans_table = str.maketrans(character_map)
    trans_name = str.maketrans(character_map_for_name)

    err, protocol_names = utm.get_ip_protocol_list()
    exit_if_error(err, protocol_names)

    dhcp_enabled = 0
    rule_number = 0
    cfrule_number = 0
    natrule_number = 0
    ip_protocol_list = protocol_names
    zones = {}
    iface_mtu = {}
    system_dns = []
    dns_rules = []
    interfaces = []
    gateways = []
    auth_servers = {}
    timerestrictiongroup = {}
    dhcp = {}
    users = {}
    identity_domains = {}
    groups = {}
    services = {}
    ip_dict = {}
    url_dict = {}
    direction = {}
    fw_rules = []
    cf_rules = []
    nat_rules = []
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
    time_zone = {
        "2": "Europe/Kaliningrad",
        "3": "Europe/Moscow",
        "4": "Europe/Samara",
        "5": "Asia/Yekaterinburg",
        "6": "Asia/Omsk",
        "7": "Asia/Krasnoyarsk",
        "8": "Asia/Irkutsk",
        "9": "Asia/Yakutsk",
        "10": "Asia/Vladivostok",
        "11": "Asia/Magadan",
        "12": "Asia/Kamchatka"
    }
    ntp = {
        "ntp_servers": [],
        "ntp_enabled": True,
        "ntp_synced": True
    }

    def pack_ip_address(ip, mask):
        if ip == '0':
            ip = '0.0.0.0'
        if mask == '0':
            mask = '128.0.0.0'
        ip_address = ipaddress.ip_interface(f'{ip}/{mask}')
        return f'{ip}/{ip_address.network.prefixlen}'

    def convert_modules(x):
        """Выгружаем UserGate->Настройки->Модули"""
        data = {
            "auth_captive": f"auth.{x[1]}",
            "logout_captive": f"logout.{x[1]}",
            "block_page_domain": f"block.{x[1]}",
            "ftpclient_captive": f"ftpclient.{x[1]}",
            "ftp_proxy_enabled": False,
            "http_cache_mode": "off",
            "http_cache_docsize_max": 1,
            "http_cache_precache_size": 64,
        }
        if not os.path.isdir('data/UserGate/GeneralSettings'):
            os.makedirs('data/UserGate/GeneralSettings')
        with open('data/UserGate/GeneralSettings/config_settings.json', 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    def convert_zone(zone_name, mtu):
        """Создаём зону"""
        if x[1].lower() != 'management':
            zone = {
                "name": zone_name.translate(trans_name),
                "description": "",
                "dos_profiles": [
                    {
                        "enabled": True,
                        "kind": "syn",
                        "alert_threshold": 3000,
                        "drop_threshold": 6000,
                        "aggregate": False,
                        "excluded_ips": []
                    },
                    {
                        "enabled": True,
                        "kind": "udp",
                        "alert_threshold": 3000,
                        "drop_threshold": 6000,
                        "aggregate": False,
                        "excluded_ips": []
                    },
                    {
                        "enabled": True,
                        "kind": "icmp",
                        "alert_threshold": 100,
                        "drop_threshold": 200,
                        "aggregate": False,
                        "excluded_ips": []
                    }
                ],
                "services_access": [
                    {
                        'enabled': True,
                        'service_id': 1,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 2,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 4,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 5,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 6,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 7,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 8,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 9,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 10,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 11,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 12,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 13,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 14,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 15,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 16,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 17,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 18,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 19,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 20,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 21,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 22,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 23,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 24,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 25,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 26,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 27,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 28,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 29,
                        'allowed_ips': []
                    },
                    {
                        'enabled': False,
                        'service_id': 30,
                        'allowed_ips': []
                    }
                ],
                "readonly": False,
                "enable_antispoof": False,
                "antispoof_invert": False,
                "networks": [],
                "sessions_limit_enabled": False,
                "sessions_limit_threshold": 0,
                "sessions_limit_exclusions": [],
            }
            zones[zone_name] = zone
            iface_mtu[zone_name] = int(mtu)

    def convert_zone_access(array):
        """Устанавливаем контроль доступа для зоны"""
        match array:
            case [service, 'domain-lookup', zone_name]:
                for service in zones[zone_name]['services_access']:
                    if service['service_id'] == 9:
                        service['enabled'] = True
            case ['telnet' | 'ssh', ip, mask, zone_name]:
                if ip in ('version', 'key-exchange'):
                    return
                ipv4 = pack_ip_address(ip, mask)
                for service in zones[zone_name]['services_access']:
                    if service['service_id'] == 14:
                        service['enabled'] = True
                        service['allowed_ips'].append(ipv4)
            case ['http', ip, mask, zone_name]:
                ipv4 = pack_ip_address(ip, mask)
                for service in zones[zone_name]['services_access']:
                    if service['service_id'] == 4:
                        service['enabled'] = True
                    elif service['service_id'] == 8:
                        service['enabled'] = True
                        service['allowed_ips'].append(ipv4)

    def convert_dns_servers(x):
        """Заполняем список системных DNS"""
        system_dns.append({'dns': x[2], 'is_bad': False})

    def convert_dns_rules(rule_name, tmp_block):
        """Создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS"""
        dns_rule = {
            "name": rule_name,
            "description": "",
            "enabled": True,
            "domains": [],
            "dns_servers": [],
        }
        for item in tmp_block:
            match item[0]:
                case 'name-server':
                    dns_rule['dns_servers'].append(item[1])
                case 'domain-name':
                    dns_rule['domains'].append(f'*.{item[1]}')
        if dns_rule['domains']:
            dns_rules.append(dns_rule)
        else:
            for x in dns_rule['dns_servers']:
                system_dns.append({'dns': x, 'is_bad': False})

    def convert_interface(tmp_block):
        """Конвертируем интерфейсы VLAN. Нельзя использовать интерфейсы Management и slave"""
        iface = {
            "name": "",
            "kind": "vlan",
            "enabled": False,
            "description": "",
            "zone_id": "",
            "master": False,
            "netflow_profile": "undefined",
            "running": False,
            "ipv4": [],
            "mode": "static",
            "mtu": 1500,
            "tap": False,
            "dhcp_relay": {
                "enabled": False,
                "host_ipv4": "",
                "servers": []
            },
            "vlan_id": 0,
            "link": ""
        }
        if tmp_block[0][0] == 'vlan':
            for item in tmp_block:
                match item:
                    case [key, value]:
                        if key == 'vlan':
                            iface['vlan_id'] = int(value)
                        elif key == 'nameif':
                            try:
                                iface['zone_id'] = zones[value]['name']
                                iface['mtu'] = iface_mtu[value]
                            except KeyError:
                                print(f"\033[33m\tНе найдено MTU для интерфейса {value}. Зона интерфейса будет установлена в Undefined.\033[0m")
                                iface['zone_id'] = 0
                                iface['mtu'] = 1500
#                            iface['name'] = ''
#                            iface['link'] = ''
                            
                        elif key == 'description':
                            iface['description'] = value
                    case [key, _, ip, mask]:
                        if key == 'ip':
                            iface['ipv4'].append(pack_ip_address(ip, mask))
            interfaces.append(iface)

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

    def convert_auth_servers(x, tmp_block):
        """Конвертируем сервера авторизации"""
        match x:
            case ['aaa-server', auth_server_name, 'protocol', protocol]:
                if protocol.startswith('tacacs'):
                    auth_servers[auth_server_name] = {
                        "name": f"{auth_server_name} (tacacs)",
                        "description": "tacacs",
                        "enabled": True,
                        "use_single_connection": False,
                        "timeout": 4,
                        "address": "",
                        "port": 49,
                        "secret": "",
                }
                if protocol == 'radius':
                    auth_servers[auth_server_name] = {
                        "name": f"{auth_server_name} (radius)",
                        "description": "radius",
                        "enabled": True,
                        "secret": "",
                        "addresses": []
                }
                if protocol == 'ldap':
                    auth_servers[auth_server_name] = {
                        "name": f"{auth_server_name} (ldap)",
                        "description": "ldap",
                        "enabled": True,
                        "ssl": False,
                        "address": "",
                        "bind_dn": "",
                        "password": "",
                        "domains": [],
                        "roots": [],
                        "keytab_exists": False
                }
                if protocol == 'kerberos':
                    auth_servers[auth_server_name] = {
                        "name": f"{auth_server_name} (kerberos)",
                        "description": "ldap",
                        "enabled": True,
                        "ssl": False,
                        "address": "",
                        "bind_dn": "",
                        "password": "",
                        "domains": [],
                        "roots": [],
                        "keytab_exists": False
                }
            case ['aaa-server', auth_server_name, zone_name, 'host', ip]:
                if auth_server_name in auth_servers:
                    if auth_servers[auth_server_name]['description'] == 'tacacs':
                        auth_servers[auth_server_name]['address'] = ip
                        for item in tmp_block:
                            if item[0] == 'key':
                                auth_servers[auth_server_name]['secret'] = item[1]
                            if item[0] == 'timeout':
                                auth_servers[auth_server_name]['timeout'] = int(item[1])
                            if item[0] == 'server-port':
                                auth_servers[auth_server_name]['port'] = item[1]
                    if auth_servers[auth_server_name]['description'] == 'radius':
                        address = {'host': ip, 'port': 1812}
                        for item in tmp_block:
                            if item[0] == 'key':
                                auth_servers[auth_server_name]['secret'] = item[1]
                            elif item[0] == 'authentication-port':
                                address['port'] = item[1]
                        auth_servers[auth_server_name]['addresses'].append(address)
                    if auth_servers[auth_server_name]['description'] == 'ldap':
                        if not auth_servers[auth_server_name]['address']:
                            auth_servers[auth_server_name]['address'] = ip
                            dn = ''
                            for item in tmp_block:
                                if item[0] == 'ldap-base-dn':
                                    dn = ".".join([y[1] for y in [x.split("=") for x in item[1].split(",")]]).lower()
                                    auth_servers[auth_server_name]['domains'].append(dn)
                                    auth_servers[auth_server_name]['roots'].append(item[1])
                                elif item[0] == 'ldap-login-dn':
                                    login = item[1] if '=' in item[1] else f"{item[1]}@{dn}"
                                    auth_servers[auth_server_name]['bind_dn'] = login
                                elif item[0] == 'ldap-login-password':
                                    auth_servers[auth_server_name]['password'] = item[1]
                                elif item[0] == 'ldap-over-ssl' and item[1] == 'enable':
                                    auth_servers[auth_server_name]['ssl'] = True
                                elif item[0] == 'kerberos-realm':
                                    auth_servers[auth_server_name]['domains'].append(item[1])
                                    auth_servers[auth_server_name]['roots'].append(item[1])
                                    auth_servers[auth_server_name]['bind_dn'] = f"login@{item[1]}"
                                    auth_servers[auth_server_name]['password'] = "secret"
                        else:
                            convert_auth_servers(['aaa-server', f'{auth_server_name} ({ip})', 'protocol', 'ldap'], [])
                            convert_auth_servers(['aaa-server', f'{auth_server_name} ({ip})', zone_name, 'host', ip], tmp_block)

    def convert_time_sets(rule_name, tmp_block):
        """Конвертируем time set (календари)"""
        week = {
            "Monday": 1,
            "Tuesday": 2,
            "Wednesday": 3,
            "Thursday": 4,
            "Friday": 5,
            "Saturday": 6,
            "Sunday": 7
        }
        timerestrictiongroup[rule_name] = {
            "name": rule_name.translate(trans_name),
            "description": "",
            "type": "timerestrictiongroup",
            "url": "",
            "list_type_update": "static",
            "schedule": "disabled",
            "attributes": {},
            "content": []
        }
        i = 0
        for item in tmp_block:
            i += 1
            time_restriction = {
                "name": f"{timerestrictiongroup[rule_name]['name']} {i}",
                "type": "span" if item[0] == "absolute" else "weekly"
            }
            match item:
                case ['absolute', 'start' | 'end', time, day, month, year]:
                    if item[1] == 'start':
                        time_restriction['time_from'] = time
                        time_restriction['fixed_date_from'] = dt.strptime(f"{day}-{month}-{year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                    elif item[1] == 'end':
                        time_restriction['time_to'] = time
                        time_restriction['fixed_date_to'] = dt.strptime(f"{day}-{month}-{year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                case ['absolute', 'start', start_time, start_day, start_month, start_year, 'end', end_time, end_day, end_month, end_year]:
                    time_restriction['time_from'] = start_time
                    time_restriction['fixed_date_from'] = dt.strptime(f"{start_day}-{start_month}-{start_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                    time_restriction['time_to'] = end_time
                    time_restriction['fixed_date_to'] = dt.strptime(f"{end_day}-{end_month}-{end_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                case ['absolute', 'end', end_time, end_day, end_month, end_year, 'start', start_time, start_day, start_month, start_year]:
                    time_restriction['time_from'] = start_time
                    time_restriction['fixed_date_from'] = dt.strptime(f"{start_day}-{start_month}-{start_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                    time_restriction['time_to'] = end_time
                    time_restriction['fixed_date_to'] = dt.strptime(f"{end_day}-{end_month}-{end_year}", '%d-%B-%Y').strftime('%Y-%m-%dT%H:%M:%S')
                case ['periodic', *time_set]:
                    if time_set[0] in ('weekend', 'weekdays', 'daily'):
                        time_restriction['time_from'] = time_set[1] if time_set[1] != 'to' else '00:00'
                        time_restriction['time_to'] = time_set[len(time_set)-1]
                        if time_set[0] == 'daily':
                            time_restriction['type'] = 'daily'
                        else:
                            time_restriction['days'] = [6, 7] if time_set[0] == 'weekend' else [1, 2, 3, 4, 5]
                    else:
                        start, end = time_set[:time_set.index('to')], time_set[time_set.index('to')+1:]
                        days = set()
                        for x in start:
                            if week.get(x, None):
                                days.add(week[x])
                            else:
                                time_restriction['time_from'] = x
                        for x in end:
                            if week.get(x, None):
                                days = {y for y in range(min(days), week[x]+1)}
                            else:
                                time_restriction['time_to'] = x
                        if not time_restriction.get('time_from', None):
                            time_restriction['time_from'] = "00:00"
                        if not time_restriction.get('time_to', None):
                            time_restriction['time_to'] = "23:59"
                        if days:
                            time_restriction['days'] = sorted(list(days))
                        else:
                            time_restriction['type'] = 'daily'

            timerestrictiongroup[rule_name]['content'].append(time_restriction)

    def convert_settings_ui(x):
        """Конвертируем часовой пояс и настройки интерфейса"""
        data = {
            "ui_timezone": time_zone.get(x[3], "Europe/Moscow"),
            "ui_language": "ru",
            "web_console_ssl_profile_id": "Default SSL profile (web console)",
            "response_pages_ssl_profile_id": "Default SSL profile",
            "webui_auth_mode": "password"
        }

        if not os.path.isdir('data/UserGate/GeneralSettings'):
            os.makedirs('data/UserGate/GeneralSettings')
        with open('data/UserGate/GeneralSettings/config_settings_ui.json', 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    def convert_ntp_settings(x):
        """Конвертируем настройки для NTP"""
        match x:
            case ['ntp', 'server', ip, *other]:
                if len(ntp['ntp_servers']) < 2:
                    ntp['ntp_servers'].append(ip)

    def convert_dhcp_settings(line):
        """Конвертируем настройки DHCP"""
        nonlocal dhcp_enabled
        if not dhcp_enabled:
            while True:
                task = input('\033[36mКонвертировать настройки DHCP subnets? ["yes", "no"]: \033[0m')
                if task == "no":
                    dhcp_enabled = 1
                    return
                elif task == "yes":
                    dhcp_enabled = 2
                    break
        elif dhcp_enabled == 1:
            return
        
        match line:
            case ['dhcp', 'address', ip_range, zone_name]:
                err, data = utm.get_interfaces_list()
                exit_if_error(err, data)
                dst_ports = {x['name']: x.get('ipv4', None) for x in data if not x['name'].startswith('tunnel')}

                print(f"\n\033[36mКонвертируется DHCP subnet\033[0m {ip_range} \033[36mУкажите порт UG-NGFW для него.\033[0m")
                print(f"\033[36mСуществуют следующие порты:\033[0m {sorted(dst_ports.keys())}")
                while True:
                    port = input("\033[36mВведите имя порта:\033[0m ")
                    if port not in dst_ports:
                        print("\033[31m\tВы ввели несуществующий порт.\033[0m")
                    else:
                        break

                ips = ip_range.split('-')

                if dst_ports[port]:
                    gateway = ipaddress.ip_interface(dst_ports[port][0])
                else:
                    while True:
                        gateway = input(f"\n\033[36mУ данного порта нет IP-адреса. Введите IP шлюза для subnet\033[0m {ip_range} [{ips[0]}/24]: ")
                        try:
                            gateway = ipaddress.ip_interface(gateway)
                        except ValueError:
                            print("\033[31m Введённый адрес не является IP-адресом.\033[0m")
                        else:
                            break
                while True:
                    if ipaddress.ip_address(ips[0]) not in gateway.network:
                        print(f"\033[31mIP-адреса диапазона {ip_range} не принадлежат подсети {gateway.network}\033[0m")
                        gateway = input(f"\n\033[36mВведите IP шлюза для subnet\033[0m {ip_range} [{ips[0]}/24]: ")
                        gateway = ipaddress.ip_interface(gateway)
                    else:
                        break

                dhcp[zone_name] = {
                    "node_name": utm.node_name,
                    "name": f"DHCP server for {zone_name}",
                    "enabled": False,
                    "description": "Перенесено с Cisco ASA",
                    "start_ip": ips[0],
                    "end_ip": ips[1],
                    "lease_time": 3600,
                    "domain": "",
                    "gateway": str(gateway.ip),
                    "boot_filename": "",
                    "boot_server_ip": "",
                    "iface_id": port,
                    "netmask": str(gateway.netmask),
                    "nameservers": [],
                    "ignored_macs": [],
                    "hosts": [],
                    "options": [],
                    "cc": 0
                }
            case ['dhcp', 'reserve-address', ip, mac, zone_name]:
                dhcp[zone_name]['cc'] += 1
                mac_address = ":".join([f"{x[:2]}:{x[2:]}" for x in mac.split('.')])
                dhcp[zone_name]['hosts'].append({"mac": mac_address.upper(), "ipv4": ip, "hostname": f"any{dhcp[zone_name]['cc']}"})
            case ['dhcp', 'dns', *ips]:
                for item in dhcp:
                    for name_server in ips:
                        dhcp[item]['nameservers'].append(name_server)
            case ['dhcp', 'lease', lease]:
                for item in dhcp:
                    dhcp[item]['lease_time'] = int(lease) if (120 < int(lease) < 3600000) else 3600
            case ['dhcp', 'domain', name]:
                for item in dhcp:
                    dhcp[item]['domain'] = name
            case ['dhcp', 'option', code, 'ip'|'ascii', *ips]:
                for item in dhcp:
                    dhcp[item]['options'].append([int(code), ", ".join(ips)])
#                    if code == '3':
#                        dhcp[item]['gateway'] = ips[0]
#                    else:

    def convert_local_users(user_name, attribute):
        """Конвертируем локального пользователя"""
        if attribute == 'password':
            trans_table_for_users = str.maketrans(character_map_for_users)
            local_user = {
                "groups": [],
                "name": user_name,
                "enabled": True,
                "auth_login": user_name.translate(trans_table_for_users),
                "icap_clients": [],
                "is_ldap": False,
                "static_ip_addresses": [],
                "ldap_dn": "",
                "emails": [],
                "first_name": "",
                "last_name": "",
                "phones": []
            }
            users[user_name] = local_user

    def convert_user_identity_domains(line):
        """Определяем домены идентификации"""
        match line:
            case ['domain', domain, 'aaa-server', server]:
                domain = domain.split(".")
                identity_domains[domain[0]] = auth_servers[server]['domains'][0]
            case ['default-domain', domain]:
                domain = domain.split(".")
                identity_domains['default'] = identity_domains[domain[0]]

    def convert_user_groups_object_group(name, object_block):
        """Конвертируем локальные группы пользователей"""
        group = {
            "name": name,
            "description": "",
            "is_ldap": False,
            "is_transient": False,
            "users": []
        }
        for item in object_block:
            match item:
                case ['user', user]:
                    user_list = user.split("\\")
                    if user_list[0] == 'LOCAL' and user_list[1] in users:
                        group['users'].append(user_list[1])
                    elif user_list[0] in identity_domains:
                        group['users'].append(f"{user_list[1]} ({identity_domains[user_list[0]]}\\{user_list[1]})")
                    else:
                        if len(user_list) == 1:
                            if 'default' in identity_domains:
                                group['users'].append(f"{user_list[0]} ({identity_domains['default']}\\{user_list[0]})")
                            else:
                                group['users'].append(user_list[0])
                case ['group-object', group_name]:
                    group['users'].extend(groups[group_name]['users'])
                case ['description', *content]:
                    group['description'] = " ".join(content)

        groups[name] = group

    def get_service_number(service):
        """Получить цифровое значение сервиса из его имени"""
        if service.isdigit():
            return service
        elif service in service_ports:
            return service_ports.get(service, service)

    def convert_service_object(name, object_block):
        """Конвертируем сетевой сервис"""
        service = {
            "name": name,
            "description": "",
            "protocols": []
        }
        port = ''
        source_port = ''
        proto = ''

        for item in object_block:
            match item:
                case ['service', protocol]:
                    if protocol.isdigit():
                        protocol = ip_proto.get(protocol, None)
                    if protocol and protocol in ip_protocol_list:
                        proto = protocol
                    else:
                        print(f"\033[31m\tСервис {name} не конвертирован. Протокол {protocol} не поддерживается в UG NGFW.\033[0m")
                        return
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
                            print(f"\033[31m\tСервис {name} не конвертирован. Операторы lt, gt, neq не поддерживаются в UG NGFW.\033[0m")
                case ['description', *content]:
                    service['description'] = " ".join(content)

        service['protocols'].append(
            {
                'proto': proto,
                'port': port,
                'source_port': source_port,
             }
        )
        services[name] = service

    def convert_network_object(name, object_block):
        """Конвертируем object network в список IP-адресов"""
        tmp_dict = {
            "name": name,
            "description": "",
            "type": "network",
            "url": "",
            "attributes": {"threat_level": 3},
            "content": []
        }
        for item in object_block:
            match item:
                case ['nat', *other]:
                    convert_dnat_rule(name, item)
                    return
                case ['subnet', ip, mask]:
                    subnet = ipaddress.ip_network(f'{ip}/{mask}')
                    tmp_dict['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
                    tmp_dict['type'] = 'network'
                case ['host', ip]:
                    tmp_dict['content'].append({'value': ip})
                    tmp_dict['type'] = 'network'
                case ['range', start_ip, end_ip]:
                    tmp_dict['content'].append({'value': f'{start_ip}-{end_ip}'})
                    tmp_dict['type'] = 'network'
                case ['fqdn', domain_name]:
                    tmp_dict['content'].append({'value': domain_name})
                    tmp_dict['type'] = 'url'
                case ['fqdn', 'v4', domain_name]:
                    tmp_dict['content'].append({'value': domain_name})
                    tmp_dict['type'] = 'url'
                case ['description', *content]:
                    tmp_dict['description'] = " ".join(content)
                case _:
                    print("Error:", name, object_block)

        if tmp_dict['type'] == 'url':
            url_dict[name] = tmp_dict
        else:
            ip_dict[name] = tmp_dict

    def convert_network_object_group(name, object_block):
        """Конвертируем object-group network в список IP-адресов и список URL если object-group содержит объект с FQDN"""
        ip_list = {
            'name': name,
            'description': '',
            'type': 'network',
            'url': '',
            'attributes': {'threat_level': 3},
            'content': []
        }
        url_list = {
            'name': name,
            'description': '',
            'type': 'url',
            'url': '',
            'attributes': {'threat_level': 3},
            'content': []
        }
        for item in object_block:
            match item:
                case ['network-object', 'host', ip]:
                    ip_list['content'].append({'value': ip})
                case ['network-object', 'object', object_name]:
                    try:
                        ip_list['content'].extend(ip_dict[object_name]['content'])
                    except KeyError:
                        url_list['content'].extend(url_dict[object_name]['content'])
                case ['network-object', ip, mask]:
                    subnet = ipaddress.ip_network(f'{ip}/{mask}')
                    ip_list['content'].append({'value': f'{ip}/{subnet.prefixlen}'})
                case ['group-object', group_name]:
                    try:
                        ip_list['content'].extend(ip_dict[group_name]['content'])
                    except KeyError:
                        pass
                    try:
                        url_list['content'].extend(url_dict[group_name]['content'])
                    except KeyError:
                        pass
                case ['description', *content]:
                    ip_list['description'] = ' '.join(content)
                    url_list['description'] = ' '.join(content)

        if ip_list['content']:
            ip_dict[name] = ip_list
        if url_list['content']:
            url_dict[name] = url_list

    def convert_service_object_group(descr, object_block):
        """Конвертируем object-group service в список сервисов"""
        service = {
            "name": descr[0],
            "description": "",
            "protocols": []
        }

        for item in object_block:
            proto_array = []
            source_port = ''
            port = ''
            match item:
                case ['service-object', 'object', object_name]:
                    service['protocols'].extend(services[object_name]['protocols'])
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
                            print(f"\033[33mСервис {item} в правиле {descr[0]} не конвертирован.\n\tОператоры lt, gt, neq не поддерживаются в UG NGFW.\033[0m")
                            continue
                case ['service-object', protocol]:
                    if protocol.isdigit():
                        protocol = ip_proto.get(protocol, None)
                    if protocol and protocol in ip_protocol_list:
                        proto_array.insert(0, protocol)
                    else:
                        print(f"\033[33mСервис {item} в {descr[0]} не конвертирован.\n\tНельзя задать протокол {protocol} в UG NGFW.\033[0m")
                        continue
                case ['port-object', 'eq'|'range', *dst_ports]:
                    proto_array = descr[1].split('-')
                    port = get_service_number(dst_ports[0]) if item[1] == 'eq' else f'{get_service_number(dst_ports[0])}-{get_service_number(dst_ports[1])}'
                case ['group-object', group_name]:
                    service['protocols'].extend(services[group_name]['protocols'])
                case ['description', *content]:
                    service['description'] = " ".join(content)

            for proto in proto_array:
                service['protocols'].append(
                    {
                        "proto": proto,
                        "port": port,
                        "source_port": source_port,
                     }
                )

        services[descr[0]] = service

    def convert_protocol_object_group(name, object_block):
        """Конвертируем object-group protocol в список сервисов"""
        service = {
            "name": name,
            "description": "",
            "protocols": []
        }

        for item in object_block:
            proto = set()
            match item:
                case ['protocol-object', protocol]:
                    if protocol.isdigit():
                        protocol = ip_proto.get(protocol, None)
                    if protocol and protocol in ip_protocol_list:
                        proto.add(protocol)
                    elif protocol == 'ip':
                        proto.update({'tcp', 'udp'})
                    else:
                        print(f"\033[33mСервис {item} в {name} не конвертирован.\n\tНельзя задать протокол {protocol} в UG NGFW.\033[0m")
                        continue
                case ['description', *content]:
                    service['description'] = " ".join(content)
            for x in proto:
                service['protocols'].append(
                    {
                        "proto": x,
                        "port": "",
                        "source_port": "",
                    }
                )
        services[name] = service
        
    def convert_icmp_object_group(name):
        """Конвертируем object-group icmp в список сервисов"""
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
        data['services'][name] = service

    def convert_access_group(x):
        """
        Конвертируе access-group. Сопоставляем имя access-list с зоной интерфейса и определяем источник это или назначение.
        """
        if x[0] not in direction:
            direction[x[0]] = {
                "src_zones": [],
                "dst_zones": []
            }
        match x:
            case [access_list_name, 'in', 'interface', zone_name]:
                direction[access_list_name]['src_zones'].append(zone_name.translate(trans_name))
            case [access_list_name, 'out', 'interface', zone_name]:
                direction[access_list_name]['dst_zones'].append(zone_name.translate(trans_name))
            case [access_list_name, 'interface', ifname, 'global']:
                pass
            case _:
                direction.pop(x[0], None)

    def create_ip_list(ip, mask=None):
        """Возвращает имя IP листа в функцию get_ips()"""
        ip_list = {
            "name": f"host {ip}",
            "description": "",
            "type": "network",
            "url": "",
            "attributes": {"thread_level": 3},
            "content": []
        }
        if mask:
            subnet = ipaddress.ip_network(f'{ip}/{mask}')
            ip_list['content'].append({"value": f'{ip}/{subnet.prefixlen}'})
            ip_list['name'] = f'subnet {ip}_{subnet.prefixlen}'
        else:
            ip_list['content'].append({"value": ip})

        ip_dict[ip_list['name']] = ip_list
        return ["list_id", ip_list['name']]

    def get_ips(ips_mode, address, rule, deq):
        match address:
            case 'any'|'any4'|'any6':
                pass
            case 'object'|'object-group':
                ip_or_service_list = deq.popleft()
                if ip_or_service_list in ip_dict:
                    rule[ips_mode].append(["list_id", ip_or_service_list])
                elif ip_or_service_list in url_dict:
                    rule[ips_mode].append(["urllist_id", ip_or_service_list])
                elif ip_or_service_list in services:
                    rule['services'].clear()
                    rule['services'].append(["service", ip_or_service_list])
            case 'host':
                ip = deq.popleft()
                rule[ips_mode].append(create_ip_list(ip))
            case 'interface':
                ip = deq.popleft()
            case _:
                try:
                    mask = deq.popleft()
                    rule[ips_mode].append(create_ip_list(address, mask))
                except IndexError:
                    pass

    def create_service(name, ips_mode, protocol, port1, port2=None):
        """Для ACE. Создаём сервис, заданный непосредственно в правиле, а не в сервисной группе."""
        if port2:
            port = f'{get_service_number(port1)}-{get_service_number(port2)}'
        else:
            port = get_service_number(port1)
        if protocol in {'tcp', 'udp','sctp'}:
                service = {
                    "name": name,
                    "description": "",
                    "protocols": [
                        {
                            "proto": protocol,
                            "port": "",
                            "source_port": ""
                        }
                    ]
                }
                if ips_mode == 'src_ips':
                    service['protocols'][0]['source_port'] = port
                else:
                    service['protocols'][0]['port'] = port
        elif protocol in services:
            service = copy.deepcopy(services[protocol])
            service['name'] = name
            for item in service['protocols']:
                if ips_mode == 'src_ips':
                    item['source_port'] = port
                else:
                    item['port'] = port

        services[name] = service

    def convert_ace(acs_name, rule_block, remark):
        """
        Конвертируем ACE в правило МЭ.
        Не активные ACE пропускаются. ACE не назначенные интерфейсам пропускаются.
        ACE с именами ASA интерфейсов пропускаются.
        """
        if (acs_name not in direction) or ('inactive' in rule_block) or ('interface' in rule_block):
            return

        nonlocal rule_number
        rule_number += 1
        deq = deque(rule_block)
        rule = {
            "name": f"Rule {rule_number} ({acs_name})",
            "description": ", ".join(remark),
            "action": "drop" if deq.popleft() == 'deny' else "accept",
            "position": "last",
            "scenario_rule_id": False,     # При импорте заменяется на UID или "0". 
            "src_zones": [],
            "dst_zones": [],
            "src_ips": [],
            "dst_ips": [],
            "services": [],
            "apps": [],
            "users": [],
            "enabled": False,
            "limit": True,
            "limit_value": "3/h",
            "limit_burst": 5,
            "log": False,
            "log_session_start": True,
            "src_zones_negate": False,
            "dst_zones_negate": False,
            "src_ips_negate": False,
            "dst_ips_negate": False,
            "services_negate": False,
            "apps_negate": False,
            "fragmented": "ignore",
            "time_restrictions": [],
            "send_host_icmp": "",
        }
        rule['src_zones'].extend(direction[acs_name]['src_zones'])
        rule['dst_zones'].extend(direction[acs_name]['dst_zones'])

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
                if 'Any SCTP' not in services:
                    service = {
                        "name": 'Any SCTP',
                        "description": "",
                        "protocols": [{"proto": "sctp", "port": "", "source_port": ""}]
                    }
                    services['Any SCTP'] = service
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
                        if user_list[0] == 'LOCAL' and user_list[1] in users:
                            rule['users'].append(['user', user_list[1]])
                        elif user_list[0] in identity_domains:
                            rule['users'].append(["user", f"{identity_domains[user_list[0]]}\\{user_list[1]}"])
            case 'user-group':
                group = deq.popleft()
                group_list = group.split("\\\\")
                if group_list[0] in identity_domains:
                    rule['users'].append(["group", f"{identity_domains[group_list[0]]}\\{group_list[1]}"])
#            case 'interface':
#                zone = deq.popleft()
#                if zone in zones:
#                    rule['dst_zones'].append(zone)
            case _:
                ips_mode = 'src_ips'
                get_ips(ips_mode, argument, rule, deq)
        while deq:
            argument = deq.popleft()
            match argument:
                case 'lt'|'gt'|'neq':
                    return
                case 'eq':
                    port = deq.popleft()
                    service_name = f'Eq {port} (Rule {rule_number})'
                    create_service(service_name, ips_mode, protocol, port)
                    rule['services'].clear()
                    rule['services'].append(["service", service_name])
                case 'range':
                    port1 = deq.popleft()
                    port2 = deq.popleft()
                    service_name = f'Range {port1}-{port2} (Rule {rule_number})'
                    create_service(service_name, ips_mode, protocol, port1, port2)
                    rule['services'].clear()
                    rule['services'].append(["service", service_name])
                case 'object-group':
                    ips_mode = 'dst_ips'
                    get_ips(ips_mode, argument, rule, deq)
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
#                    if zone in zones:
#                        rule['dst_zones'].append(zone)
                case _:
                    ips_mode = 'dst_ips'
                    get_ips(ips_mode, argument, rule, deq)

        fw_rules.append(rule)

    def convert_webtype_ace(acs_name, rule_block, remark):
        """
        Конвертируем ACE webtype в правило КФ. Не активные ACE пропускаются.
        """
        if 'inactive' in rule_block:
            return

        nonlocal cfrule_number
        cfrule_number += 1
        deq = deque(rule_block)
        action = deq.popleft()
        rule = {
            "name": f"Rule {cfrule_number} ({acs_name})",
            "description": ", ".join(remark),
            "position": "last",
            "action": "drop" if action == 'deny' else "accept",
            "public_name": "",
            "enabled": True,
            "enable_custom_redirect": False,
            "blockpage_template_id": -1,
            "users": [],
            "url_categories": [],
            "src_zones": [],
            "dst_zones": [],
            "src_ips": [],
            "dst_ips": [],
            "morph_categories": [],
            "urls": [],
            "referers": [],
            "referer_categories": [],
            "user_agents": [],
            "time_restrictions": [],
            "content_types": [],
            "http_methods": [],
            "src_zones_negate": False,
            "dst_zones_negate": False,
            "src_ips_negate": False,
            "dst_ips_negate": False,
            "url_categories_negate": False,
            "urls_negate": False,
            "content_types_negate": False,
            "user_agents_negate": False,
            "custom_redirect": "",
            "enable_kav_check": False,
            "enable_md5_check": False,
            "rule_log": False,
            "scenario_rule_id": False,
            "users_negate": False
        }

        while deq:
            parameter = deq.popleft()
            match parameter:
                case 'url':
                    url = deq.popleft()
                    url_list_name = f"For {acs_name}-{cfrule_number}"
                    if not create_url_list(url, url_list_name, rule):
                        return
                case 'tcp':
                    address = deq.popleft()
                    get_ips('dst_ips', address, rule, deq)
                case 'time_range':
                    rule['time_restrictions'].append(deq.popleft())
                case 'time-range':
                    rule['time_restrictions'].append(deq.popleft())

        cf_rules.append(rule)

    def create_url_list(url, name, rule):
        """Для ACL webtype - создаём URL-лист."""
        if url == 'any':
            if rule['action'] == 'accept':
                print(f'\033[36mURL "{url}" в разрешающем ACE (webtype) пропущен так как в NGFW дублирует дефолтное правило КФ.\033[0m')
                return False
            else:
                return True
        proto, sep, path = url.partition("://")
        if proto not in ('http', 'https', 'ftp'):
            print(f'\033[36mURL {url} в ACE (webtype) пропущен. Неподдерживаемый тип протокола: "{proto}"\033[0m')
            return False
        if ('?' in path) or ('[' in path) or (']' in path):
            print(f"\033[36mURL {url} в ACE (webtype) пропущен. Не допустимые сиволы в url.\033[0m")
            return False

        url_list = {
            "name": name,
            "description": "",
            "type": "url",
            "url": "",
            "attributes": {"threat_level": 3},
            "content": [{"value": url}]
        }
        url_dict[name] = url_list
        rule['urls'].append(name)
        return True

    def convert_dnat_rule(ip_list, rule_block):
        """Конвертируем object network в правило DNAT или Port-форвардинг"""
#        print(ip_dict[ip_list]['content'][0]['value'], "\t", rule_block)
        if ('inactive' in rule_block) or ('interface' in rule_block):
            print(f'\033[36mПравило NAT "{rule_block}" пропущено так как не активно или содержит интерфейс.\033[0m')
            return

        nonlocal natrule_number
        natrule_number += 1
        rule = {
            "name": f"Rule {natrule_number} ({ip_list})",
            "description": "",
            "action": "dnat",
            "position": "last",
            "zone_in": [],
            "zone_out": [],
            "source_ip": [],
            "dest_ip": [],
            "service": [],
            "target_ip": ip_dict[ip_list]['content'][0]['value'],
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
        zone_out, zone_in = rule_block[1][1:-1].split(',')
        if len(rule_block) == 3 or 'net-to-net' in rule_block:
            rule['zone_in'] = [zone_in] if zone_in != 'any' else []
        if rule_block[2] == 'static':
            if rule_block[3] in ip_dict:
                rule['dest_ip'].append(["list_id", rule_block[3]])
                rule['snat_target_ip'] = ip_dict[rule_block[3]]['content'][0]['value']
            elif f"host {rule_block[3]}" in ip_dict:
                rule['dest_ip'].append(["list_id", f"host {rule_block[3]}"])
                rule['snat_target_ip'] = ip_dict[f"host {rule_block[3]}"]['content'][0]['value']
            else:
                rule['dest_ip'].append(create_ip_list(rule_block[3]))
                rule['snat_target_ip'] = rule_block[3]

            if 'service' in rule_block:
                i = rule_block.index('service')
                proto = rule_block[i+1]
                src_port = rule_block[i+3]
                dst_port = rule_block[i+2]
                if src_port == dst_port:
                    if dst_port in ug_services:
                        rule['service'].append(["service", ug_services[dst_port]])
                    elif dst_port in services:
                        rule['service'].append(["service", dst_port])
                    else :
                        service = {
                            "name": dst_port,
                            "description": f'Service for DNAT rule (Rule {natrule_number})',
                            "protocols": [{"proto": proto, "port": service_ports.get(dst_port, dst_port), "source_port": ""}]
                        }
                        services[dst_port] = service
                        rule['service'].append(["service", dst_port])
                else:
                    rule['action'] = 'port_mapping'
                    rule['port_mappings'].append({"proto": proto,
                                                  "src_port": int(service_ports.get(src_port, src_port)),
                                                  "dst_port": int(service_ports.get(dst_port, dst_port))})
        else:
            return

        nat_rules.append(rule)

    def convert_nat_rule(rule_block):
        """Конвертируем правило NAT"""
#        print(ip_dict[ip_list]['content'][0]['value'], "\t", rule_block)
        if ('inactive' in rule_block) or ('interface' in rule_block):
            print(f'\033[36mПравило NAT "{rule_block}" пропущено так как не активно или содержит интерфейс.\033[0m')
            return

        nonlocal natrule_number
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

    def make_block_of_line(fh):
        """Читаем файл и создаём блок записей для раздела конфигурации"""
        block = []
        string = fh.readline()
        while string:
            if string.startswith(' '):
                block.append(string.translate(trans_table).strip().split(' '))
                string = fh.readline()
            else:
                break
        return string, block

    if os.path.isdir('data_ca'):
        with open(f"data_ca/{file_name}.txt", "r") as fh:
            line = fh.readline()
            while line:
                if line[:1] in {':', '!'}:
                    line = fh.readline()
                    continue
                x = line.translate(trans_table).rsplit(' ')
                if x[0] == 'mtu':
                    convert_zone(x[1], x[2])
                line = fh.readline()

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
                    case 'access-group':
                        convert_access_group(x[1:])
                        line = fh.readline()
                    case _:
                        line = fh.readline()

        with open(f"data_ca/{file_name}.txt", "r") as fh:
            remark = []
            line = fh.readline()
            while line:
                if line[:1] in {':', '!'}:
                    line = fh.readline()
                    continue
                x = line.translate(trans_table).rstrip().split(' ')
                match x[0]:
                    case 'access-list':
                        match x[2]:
                            case 'remark':
                                line = fh.readline()
                                y = line.translate(trans_table).rstrip().split(' ')
                                if y[1] == x[1]:
                                    remark.append(' '.join(x[3:]))
                            case 'extended':
                                convert_ace(x[1], x[3:], remark)
                                remark.clear()
                                line = fh.readline()
                            case 'line':
                                if x[4] == 'extended':
                                    convert_ace(x[1], x[5:], remark)
                                remark.clear()
                                line = fh.readline()
                            case 'webtype':
                                convert_webtype_ace(x[1], x[3:], remark)
                                remark.clear()
                                line = fh.readline()
                            case _:
                                string = line.rstrip('\n')
                                print(f"\033[36mACE: {string} - не обработано.\033[0m")                                
                                line = fh.readline()
                    case 'nat':
                        convert_nat_rule(x)
                        line = fh.readline()
                    case _:
                        line = fh.readline()

    else:
        print(f'Не найден каталог с конфигурацией Cisco ASA.')
        return

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

    if not os.path.isdir('data/UsersAndDevices/Users'):
        os.makedirs('data/UsersAndDevices/Users')
    with open('data/UsersAndDevices/Users/config_users.json', 'w') as fh:
        json.dump(list(users.values()), fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/UsersAndDevices/Groups'):
        os.makedirs('data/UsersAndDevices/Groups')
    with open('data/UsersAndDevices/Groups/config_groups.json', 'w') as fh:
        json.dump(list(groups.values()), fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/Libraries/TimeSets'):
        os.makedirs('data/Libraries/TimeSets')
    with open('data/Libraries/TimeSets/config_calendars.json', 'w') as fh:
        json.dump(list(timerestrictiongroup.values()), fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/Libraries/Services'):
        os.makedirs('data/Libraries/Services')
    with open('data/Libraries/Services/config_services.json', 'w') as fh:
        json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/Libraries/URLLists'):
        os.makedirs('data/Libraries/URLLists')
    for list_name, value in url_dict.items():
        with open(f'data/Libraries/URLLists/{list_name}.json', 'w') as fh:
            json.dump(value, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/Libraries/IPAddresses'):
        os.makedirs('data/Libraries/IPAddresses')
    for list_name, value in ip_dict.items():
        with open(f'data/Libraries/IPAddresses/{list_name}.json', 'w') as fh:
            json.dump(value, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/NetworkPolicies/Firewall'):
        os.makedirs('data/NetworkPolicies/Firewall')
    with open('data/NetworkPolicies/Firewall/config_firewall_rules.json', 'w') as fh:
        json.dump(fw_rules, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/SecurityPolicies/ContentFiltering'):
        os.makedirs('data/SecurityPolicies/ContentFiltering')
    with open('data/SecurityPolicies/ContentFiltering/config_content_rules.json', 'w') as fh:
        json.dump(cf_rules, fh, indent=4, ensure_ascii=False)

    if not os.path.isdir('data/NetworkPolicies/NATandRouting'):
        os.makedirs('data/NetworkPolicies/NATandRouting')
    with open('data/NetworkPolicies/NATandRouting/config_nat_rules.json', 'w') as fh:
        json.dump(nat_rules, fh, indent=4, ensure_ascii=False)

######################################## Импорт ####################################################
def import_settings(utm):
    """Импортировать настройки"""
    print('Импорт настроек кэширования HTTP и модулей раздела "Настройки":')
    try:
        with open("data/UserGate/GeneralSettings/config_settings.json", "r") as fh:
            settings = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mНастройки кэширования HTTP и модулей не импортированы!\n\tНе найден файл "data/UserGate/GeneralSettings/config_settings.json" с сохранённой конфигурацией!\033[0;0m')
        return

    params = {
        'auth_captive': 'Домен Auth captive-портала',
        'logout_captive': 'Домен Logout captive-портала',
        'block_page_domain': 'Домен страницы блокировки',
        'ftpclient_captive': 'FTP поверх HTTP домен',
        'ftp_proxy_enabled': 'FTP поверх HTTP',
        'http_cache_mode': 'Режим кэширования',
        'http_cache_docsize_max': 'Мксимальный размер объекта кэширования http',
        'http_cache_precache_size': 'Размер RAM-кэша',
    }

    for key, value in settings.items():
        err, result = utm.set_settings_param(key, value)
        if err == 1:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\t{params[key]} - \033[32mUpdated!\033[0m')

def import_ui(utm):
    """Импортировать настройки интерфейса"""
    print('Импорт "Настройки интерфейса" веб-консоли раздела "Настройки":')

    err, result = utm.get_ssl_profiles_list()
    if err == 1:
        print(f"\033[31m{result}\033[0m")
        return
    list_ssl_profiles = {x['name']: x['id'] for x in result}

    try:
        with open("data/UserGate/GeneralSettings/config_settings_ui.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Настройки интерфейса" не импортирован!\n\tНе найден файл "data/UserGate/GeneralSettings/config_settings_ui.json" с сохранённой конфигурацией!\033[0;0m')
        return

    params = {
        'ui_timezone': 'Часовой пояс',
        'ui_language': 'Язык интерфейса по умолчанию',
        'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
        'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/авторизации',
    }

    try:
        data['web_console_ssl_profile_id'] = list_ssl_profiles[data['web_console_ssl_profile_id']]
        data['response_pages_ssl_profile_id'] = list_ssl_profiles[data['response_pages_ssl_profile_id']]
    except KeyError as err:
        print(f'\t\033[33mНе найден профиль SSL {err}".\n\tЗагрузите профили SSL и повторите попытку.\033[0m')
        data.pop('web_console_ssl_profile_id', None)
        data.pop('response_pages_ssl_profile_id', None)

    for key, value in data.items():
        if key != 'webui_auth_mode':
            err, result = utm.set_settings_param(key, value)
            if err == 1:
                print(f"\033[31m{result}\033[0m")
            else:
                print(f'\t{params[key]} - \033[32mUpdated!\033[0m.')

def import_ntp(utm):
    """Импортировать настройки NTP"""
    print('Импорт настроек NTP раздела "Настройки":')
    try:
        with open("data/UserGate/GeneralSettings/config_ntp.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mНастройки NTP не импортированы!\n\tНе найден файл "data/UserGate/GeneralSettings/config_ntp.json" с сохранённой конфигурацией!\033[0;0m')
        return

    data.pop('utc_time', None)

    err, result = utm.add_ntp_config(data)
    if err == 1:
        print(f"\033[31m{result}\033[0m")
    else:
        print(f'\tНастройки NTP обновлены.')

def import_IP_lists(utm):
    """Импортировать списки IP адресов"""
    print('Импорт списков IP-адресов раздела "Библиотеки":')

    if os.path.isdir('data/Libraries/IPAddresses'):
        files_list = os.listdir('data/Libraries/IPAddresses')
        if files_list:
            for file_name in files_list:
                try:
                    with open(f"data/Libraries/IPAddresses/{file_name}", "r") as fh:
                        ip_list = json.load(fh)
                except FileNotFoundError as err:
                    print(f'\t\033[31mСписок "IP-адреса" не импортирован!\n\tНе найден файл "data/Libraries/IPAddresses/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                    return

                content = ip_list.pop('content')
                err, result = utm.add_nlist(ip_list)
                if err == 2:
                    print(f'\t{result}', end= ' - ')
                    result = utm.list_ip[ip_list['name']]
                    err1, result1 = utm.update_nlist(result, ip_list)
                    if err1 == 1:
                        print("\n", f"\033[31m\t{result1}\033[0m")
                        continue
                    else:
                        print("\033[32mUpdated!\033[0;0m")
                elif err == 1:
                    print(f"\033[31m\t{result}\033[0m")
                    continue
                else:
                    utm.list_ip[ip_list['name']] = result
                    print(f'\tДобавлен список IP-адресов: "{ip_list["name"]}".')
                if content:
                    err2, result2 = utm.add_nlist_items(result, content)
                    if err2 == 2:
                        print(f"\t{result2}")
                    elif err2 == 1:
                        print(f"\033[31m\t{result2}\033[0m")
                    else:
                        print(f'\tСодержимое списка "{ip_list["name"]}" обновлено. Added {result2} record.')
                else:
                    print(f'\tСписок "{ip_list["name"]}" пуст.')
        else:
            print("\033[33m\tНет списков IP-адресов для импорта.\033[0m")
    else:
        print("\033[33m\tНет списков IP-адресов для импорта.\033[0m")

def import_url_lists(utm):
    """Импортировать списки URL на UTM"""
    print('Импорт списков URL раздела "Библиотеки":')

    if os.path.isdir('data/Libraries/URLLists'):
        files_list = os.listdir('data/Libraries/URLLists')
        if files_list:
            for file_name in files_list:
                try:
                    with open(f"data/Libraries/URLLists/{file_name}", "r") as fh:
                        url_list = json.load(fh)
                except FileNotFoundError as err:
                    print(f'\t\033[31mСписок "Списки URL" не импортирован!\n\tНе найден файл "data/Libraries/URLLists/{file_name}" с сохранённой конфигурацией!\033[0;0m')
                    return

                print(f'\tДобавляется список URL: "{url_list["name"]}".')
                content = url_list.pop('content')
                err, result = utm.add_nlist(url_list)
                if err == 2:
                    print(f"\t{result}", end= " - ")
                    result = utm.list_url[url_list['name']]
                    err1, result1 = utm.update_nlist(result, url_list)
                    if err1 == 1:
                        print("\n", f'\033[31m\t{result1}\033[0m')
                        continue
                    else:
                        print("\033[32mOk!\033[0;0m")
                elif err == 1:
                    print(f"\033[31m\t{result}\033[0m")
                    continue
                else:
                    utm.list_url[url_list['name']] = result
                    print(f'\tСписок URL: "{url_list["name"]}" добавлен.')
                if content:
                    for item in content:
                        err2, result2 = utm.add_nlist_item(result, item)
                        if err2 == 1:
                            print(f"\033[31m\t\tURL '{item['value']}' не добавлен.\033[0m")
                            print(f"\033[31m\t\t{result2}\033[0m")
                        elif err2 == 2:
                            print(f"\t\tURL '{item['value']}' уже существует.")
                        else:
                            print(f"\t\tURL '{item['value']}' добавлен в список.")
#                    print(f'\t\tСодержимое списка "{url_list["name"]}" обновлено.')
                else:
                    print(f'\t\tСписок "{url_list["name"]}" пуст.')
        else:
            print("\033[33m\tНет списков URL для импорта.\033[0m")
    else:
        print("\033[33m\tНет списков URL для импорта.\033[0m")

def import_services(utm):
    """Импортировать список сервисов раздела библиотеки"""
    print('Импорт списка сервисов раздела "Библиотеки":')
    try:
        with open("data/Libraries/Services/config_services.json", "r") as fh:
            services = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Сервисы" не импортирован!\n\tНе найден файл "data/Libraries/Services/config_services.json" с сохранённой конфигурацией!\033[0;0m')
        return

    for item in services:
        err, result = utm.add_service(item)
        if err == 2:
            print(f"\t{result}", end= ' - ')
            try:
                err1, result1 = utm.update_service(utm.services[item['name']], item)
            except KeyError as keyerr:
                print(f"\n\t\t\033[31mService {keyerr} not updated.\n\t\tУстановите последнее обновление на UTM и повторите попытку.\033[0m")
            else:
                if err1 != 0:
                    print(f"\n\t\t{result1}")
                else:
                    print("\033[32mOk!\033[0;0m")
        elif err == 1:
            print(f"\t{result}")
        else:
            utm.services[item['name']] = result
            print(f'\tСервис "{item["name"]}" добавлен.')

def import_time_restricted_lists(utm):
    """Импортировать содержимое календарей"""
    try:
        with open("data/Libraries/TimeSets/config_calendars.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        return

    print('Импорт списка "Календари" раздела "Библиотеки":')
    if not data:
        print("\033[33m\tНет списков Календарей для импорта.\033[0m")
        return

    for item in data:
        content = item.pop('content')
        err, result = utm.add_nlist(item)
        if err == 2:
            print(f"\t{result}", end= ' - ')
            result = utm.list_calendar[item['name']]
            err1, result1 = utm.update_nlist(result, item)
            if err1 == 1:
                print("\n", f"\033[31m\t{result1}\033[0m")
            else:
                print("\033[32mOk!\033[0;0m")
        elif err == 1:
            print(f"\033[31m\t{result}\033[0m")
            continue
        else:
            utm.list_calendar[item['name']] = result
            print(f'\tДобавлен элемент календаря: "{item["name"]}".')
        for x in content:
            err2, result2 = utm.add_nlist_item(result, x)
            if err2 == 1:
                print(f"\033[31m\t\t{result2}\033[0m")
        print(f'\t\tСодержимое списка "{item["name"]}" обновлено.')

def import_zones(utm):
    """Импортировать зоны на UTM"""
    print('Импорт списка "Зоны" раздела "Сеть":')

    try:
        with open("data/Network/Zones/config_zones.json", "r") as fd:
            zones = json.load(fd)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Зоны" не импортирован!\n\tНе найден файл "data/Network/Zones/config_zones.json" с сохранённой конфигурацией!\033[0;0m')
        return

    for item in zones:
        if item['sessions_limit_threshold'] < 0:
            item['sessions_limit_threshold'] = 0
        if utm.version_hight >= 7 and utm.version_midle >= 1:
            transforn_allowed_ips(utm, item)
        err, result = utm.add_zone(item)
        if err == 2:
            print(f"\t{result}", end= ' - ')
            err1, result1 = utm.update_zone(utm.zones[item['name']], item)
            if err1 == 2:
                print(f"\t{result1}")
            elif err == 1:
                print(f"\033[31m\t{result}\033[0m")
            else:
                print("\033[32mOk!\033[0;0m")
        elif err == 1:
            print(f"\033[31m\t{result}\033[0m")
        else:
            utm.zones[item['name']] = result
            print(f"\tЗона '{item['name']}' добавлена.")
    print('\033[36;1mВнимание:\033[0m \033[36mНеобходимо настроить каждую зону. Включить нужный сервис в контроле доступа,')
    print('поменять по необходимости параметры защиты от DoS и настроить защиту от спуфинга.\033[0m')

def transforn_allowed_ips(utm, zone):
    """Преобразуем список IP в группу IP-адресов. Созданную группу добавляем в библиотеку."""
    for x in zone['services_access']:
        if x['allowed_ips']:
            ip_list = {
                "name": f"For Zone: {zone['name']} (service: {zone_services[x['service_id']]})",
                "description": "",
                "type": "network",
                "url": "",
                "attributes": {"threat_level": 3},
            }
            err, result = utm.add_nlist(ip_list)
            if err == 1:
                print(f"\t{result1}")
                x['allowed_ips'] = []
            else:
                content = [{"value": ips} for ips in x['allowed_ips']]
                err1, result1 = utm.add_nlist_items(result, content)
                if err == 1:
                    print(f"\t{result1}")
                x['allowed_ips'] = [["list_id", result]]

def import_interfaces(utm):
    """Импортировать интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    print('Импорт VLAN в раздел "Сеть/Интерфейсы":')
    while True:
        task = input('\033[36mИмпортировать интерфейсы VLAN? ["yes", "no"]: \033[0m')
        if task == "no":
            return
        elif task == "yes":
            break
    try:
        with open("data/Network/Interfaces/config_interfaces.json", "r") as fd:
            ifaces = json.load(fd)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Интерфейсы" не импортирован!\n\tНе найден файл "data/Network/Interfaces/config_interfaces.json" с сохранённой конфигурацией!\033[0;0m')
        return

    management_port = ''
    utm_vlans = {}
    interfaces_list = {}

    # Составляем список легитимных интерфейсов.
    _, result = utm.get_interfaces_list()

    for item in result:
        if item['kind'] == 'vlan':
            utm_vlans[item['vlan_id']] = item['name']
        for ip in item['ipv4']:
            if ip.startswith(utm.server_ip):
                management_port = item["name"]
                print(f'\tИнтерфейс "{item["name"]}" [{utm.server_ip}] используется для текущей сессии.')
                print('\tОн не будет использоваться для создания интерфейсов VLAN.')
        if item['kind'] not in ('bridge', 'bond', 'adapter') or item['master']:
            continue
        if item["name"] == management_port:
            continue
        interfaces_list[item['name']] = item['kind']

    for item in ifaces:
        if item["vlan_id"] in utm_vlans:
            print(f'VLAN {item["vlan_id"]} уже существует на порту {utm_vlans[item["vlan_id"]]}')
            continue
        print(f'\n\033[36mДобавляется VLAN\033[0m {item["vlan_id"]}, ip: {item["ipv4"]}. \033[36mНеобходимо выбрать интерфейс для создания VLAN.')
        print(f'Существуют следующие интерфейсы:\033[0m {sorted(interfaces_list.keys())}')
        while True:
            port = input('\033[36mВведите имя интерфейса или "no" для пропуска: \033[0m')
            if port != 'no' and port not in interfaces_list.keys():
                print('\033[31m\tВы ввели название не легитимного интерфейса.\033[0m')
            else:
                break
        if port == "no":
            print(f"VLAN {item['vlan_id']} пропущен.")
            continue

        item['link'] = port
        item['description'] = item['name']
        item['name'] = f'{port}.{item["vlan_id"]}'

        if item['kind'] == 'vlan' and item['link'] != management_port:
            if item['link'] not in interfaces_list:
                print(f'\t\033[33mСетевой адаптер "{item["link"]}" не существует - VLAN "{item["name"]}" создан не будет!\033[0m')
                continue

        if item['zone_id']:
            try:
                item['zone_id'] = utm.zones[item['zone_id']]
            except KeyError as err:
                print(f'\t\033[33mЗона {err} для интерфейса "{item["name"]}" не найдена.\n\tСоздайте зону {err} и присвойте этому VLAN.\033[0m')
                item['zone_id'] = 0

        item.pop('kind')
        err, result = utm.add_interface_vlan(item)
        if err:
            print(f'\033[33m\tИнтерфейс "{item["name"]}" не добавлен!\033[0m')
            print(f"\033[31m{result}\033[0m")
        else:
            utm_vlans[item['vlan_id']] = item['name']
            print(f'\tИнтерфейс "{item["name"]}" добавлен.')

def import_gateways_list(utm):
    """Импортировать список шлюзов"""
    print('Импорт списка "Шлюзы" раздела "Сеть":')
    try:
        with open("data/Network/Gateways/config_gateways.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Шлюзы" не импортирован!\n\tНе найден файл "data/Network/Gateways/config_gateways.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет шлюзов для импорта.")
        return

    err, result = utm.get_gateways_list()
    exit_if_error(err, result)
    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}

    for item in data:
        if not item['is_automatic']:
            if item['name'] in gateways_list:
                print(f'\tШлюз "{item["name"]}" уже существует', end= ' - ')
                err, result = utm.update_gateway(gateways_list[item['name']], item)
                if err:
                    print("\n", f"\033[31m\t{result}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = utm.add_gateway(item)
                if err:
                    print(f"\033[31m\t{result}\033[0m")
                else:
                    gateways_list[item['name']] = result
                    print(f'\tШлюз "{item["name"]}" добавлен.')

def import_dhcp_subnets(utm):
    """Добавить DHCP subnets на UTM"""
    try:
        with open("data/Network/DHCP/config_dhcp_subnets.json", "r") as fd:
            subnets = json.load(fd)
    except FileNotFoundError as err:
        return

    print("Импорт DHCP subnets:")
    if not subnets:
        print("\tНет DHCP subnets для импорта.")
        return

    err, data = utm.get_interfaces_list()
    exit_if_error(err, data)
    dst_ports = [x['name'] for x in data if not x['name'].startswith('tunnel')]

    err, data = utm.get_dhcp_list()
    exit_if_error(err, data)
    old_dhcp_subtets = [x['name'] for x in data]

    for item in subnets:
        if item['name'] in old_dhcp_subtets:
            print(f'\tDHCP subnet "{item["name"]}" уже существует!')
            continue
        if item['name'] == "":
            item['name'] = "No Name subnet" 
        if "cc" in item.keys():
            item.pop("cc")
            item.pop("node_name")
        err, result = utm.add_dhcp_subnet(item)
        print(f"\033[31m\t{result}\033[0m") if err else print(f'\tSubnet "{item["name"]}" добавлен.')

def import_dns_servers(utm):
    """Импортировать список системных DNS серверов"""
    print('Импорт системных DNS серверов раздела "Сеть":')
    try:
        with open("data/Network/DNS/config_dns_servers.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\033[33mСписок системных DNS серверов не импортирован!\033[0;0m')
        print(f'\t\033[36mНе найден файл "data/Network/DNS/config_dns_servers.json" с сохранённой конфигурацией!\033[0;0m')
        print(f'\t\033[36mВведите системные DNS сервера для выхода в интернет вручную.\033[0;0m')
        return

    for item in data:
        err, result = utm.add_dns_server(item)
        if err == 2:
            print(f"\t{result}")
        elif err == 1:
            print(f"\033[31m\t{result}\033[0m")
        else:
            print(f'\tDNS сервер "{item["dns"]}" добавлен.')

def import_dns_rules(utm):
    """Импортировать список правил DNS прокси"""
    print('Импорт списка правил DNS-прокси раздела "Сеть":')
    try:
        with open("data/Network/DNS/config_dns_rules.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\033[31mСписок правил DNS прокси не импортирован!\033[0;0m')
        print(f'\t\033[36m\tНе найден файл "data/Network/DNS/config_dns_rules.json" с сохранённой конфигурацией!\033[0;0m')
        print(f'\t\033[36mВероятно у вас нет правил DNS-прокси.\033[0;0m')
        return

    err, result = utm.get_dns_rules()
    exit_if_error(err, result)
    dns_rules = [x['name'] for x in result]

    for item in data:
        if item['name'] in dns_rules:
            print(f'\tПравило DNS прокси "{item["name"]}" уже существует.')
        else:
            err, result = utm.add_dns_rule(item)
            if err == 2:
                print(f"\t{result}")
            elif err == 1:
                print(f"\033[31m\t{result}\033[0m")
            else:
                print(f'\tПравило DNS прокси "{item["name"]}" добавлено.')

def import_virt_routes(utm):
    """Импортировать список виртуальных маршрутизаторов"""
    print(f'Импорт статических маршрутов в Виртуальный маршрутизатор по умолчанию раздела "Сеть":')
    try:
        with open("data/Network/VRF/config_routers.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mВиртуальные маршрутизаторы не импортированы!\n\tНе найден файл "data/Network/VRF/config_routers.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print('\tНет данных для импорта. Файл "data/Network/VRF/config_routers.json" пуст.')
        return

    err, result = utm.get_routers_list()
    exit_if_error(err, result)
    virt_routers = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in virt_routers:
            err, result = utm.update_vrf(virt_routers[item['name']], item)
            if err:
                print(f'\033[31m\t{result}\033[0m')
            else:
                print(f'\tВиртуальный маршрутизатор "{item["name"]}" - \033[32mUpdated!\033[0m')
        else:
            err, result = utm.add_vrf(item)
            if err == 2:
                print(f'\033[31m\t{result}\033[0m')
            else:
                print(f'\tСоздан виртуальный маршрутизатор "{item["name"]}".')
    print('\t\033[36mДобавленные маршруты не активны. Необходимо проверить маршрутизацию и включить их.\033[0m')

def import_radius_server(utm):
    """Импортировать список серверов RADIUS"""
    try:
        with open("data/UsersAndDevices/AuthServers/config_radius_servers.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        return

    print('Импорт списка серверов RADIUS раздела "Пользователи и устройства":')
    if not data:
        print("\tНет серверов авторизации RADIUS для импорта.")
        return

    for item in data:
        if item['name'] in utm.auth_servers:
            print(f'\tСервер RADIUS "{item["name"]}" уже существует.')
            continue
        err, result = utm.add_auth_server('radius', item)
        if err:
            print(f"\033[31m\t{result}\033[0m")
        else:
            utm.auth_servers[item['name']] = result
            print(f'\tСервер авторизации RADIUS "{item["name"]}" добавлен.')

def import_tacacs_server(utm):
    """Импортировать список серверов TACACS"""
    try:
        with open("data/UsersAndDevices/AuthServers/config_tacacs_servers.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        return

    print('Импорт списка серверов TACACS раздела "Пользователи и устройства":')
    if not data:
        print("\tНет серверов авторизации TACACS для импорта.")
        return

    for item in data:
        if item['name'] in utm.auth_servers:
            print(f'\tСервер TACACS "{item["name"]}" уже существует.')
            continue
        err, result = utm.add_auth_server('tacacs', item)
        if err:
            print(f"\033[31m\t{result}\033[0m")
        else:
            utm.auth_servers[item['name']] = result
            print(f'\tСервер авторизации TACACS "{item["name"]}" добавлен.')

def import_ldap_server(utm):
    """Импортировать список серверов LDAP"""
    try:
        with open("data/UsersAndDevices/AuthServers/config_ldap_servers.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        return

    print('Импорт списка серверов LDAP раздела "Пользователи и устройства":')
    if not data:
        print("\tНет серверов авторизации LDAP для импорта.")
        return

    ind = 0
    for item in data:
        if item['name'] in utm.auth_servers:
            print(f'\tСервер LDAP "{item["name"]}" уже существует.')
            continue
        item['keytab_exists'] = False
        item.pop("cc", None)
        err, result = utm.add_auth_server('ldap', item)
        if err:
            print(f"\033[31m\t{result}\033[0m")
        else:
            utm.auth_servers[item['name']] = result
            ind = 1
            print(f'\tСервер авторизации LDAP "{item["name"]}" добавлен.')
    if ind:
        print(f'\t\033[36mНеобходимо включить импортированные LDAP-коннекторы, ввести пароль и импортировать keytab файл.\033[0m')

def import_users(utm):
    """Импортировать список локальных пользователей"""
    print('Импорт списка локальных пользователей раздела "Пользователи и устройства":')
    try:
        with open("data/UsersAndDevices/Users/config_users.json", "r") as fh:
            users = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок локальных пользователей не импортирован!\n\tНе найден файл "data/UsersAndDevices/Users/config_users.json" с сохранённой конфигурацией!\033[0;0m')
        return

    err, result = utm.get_users_list()
    exit_if_error(err, result)
    users_list = {x['auth_login'] for x in result}

    for item in users:
        if item['auth_login'] in users_list:
            print(f'\tПользователь "{item["name"]}" уже существует.')
            continue
        err, result = utm.add_user(item)
        if err == 2:
            print(f'\t{result}')
        elif err == 1:
            print(f'\033[31m\t{result}\033[0m')
        else:
            users_list.add(item['auth_login'])
            print(f'\tЛокальный пользователь "{item["name"]}" добавлен.')
    print('\033[36;1mВнимание:\033[0m \033[36mТире и пробел в логине заменены на символ подчёркивания. Точка, прямой и обратный слеши убраны.')
    print('Так как пароли не переносятся, необходимо задать пароль для всех пользователей или задать')
    print('статические IP/MAC/VLAN для авторизации пользователя.\033[0m')

def import_local_groups(utm):
    """Импортировать локальные группы"""
    try:
        with open("data/UsersAndDevices/Groups/config_groups.json", "r") as fh:
            groups = json.load(fh)
    except FileNotFoundError as err:
        return

    print('Импорт списка локальных групп раздела "Пользователи и устройства":')

    err, result = utm.get_users_list()
    exit_if_error(err, result)
    users_list = {x['auth_login']: x['id'] for x in result}

    for item in groups:
        users = item.pop('users')
        err, result = utm.add_group(item)
        if err == 2:
            print(f"\t{result}", end= ' - ')
            err1, result1 = utm.update_group(utm.list_groups[item['name']], item)
            if err1:
                print("\n", f"\033[31m\t{result1}\033[0m")
            else:
                print("\033[32mOk!\033[0;0m")
        elif err == 1:
            print(f"\033[31m\t{result}\033[0m")
        else:
            utm.list_groups[item['name']] = result
            print(f'\tЛокальная группа "{item["name"]}" добавлена.')

        domain_users = []
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1:
                domain_users.append(user_array)
            else:
                err2, result2 = utm.add_user_in_group(utm.list_groups[item['name']], users_list[user_name])
                if err2:
                    print(f"\033[31m\t{result2}\033[0m")
                else:
                    print(f'\t\tПользователь "{user_name}" добавлен в группу "{item["name"]}".')
        for user in domain_users:
            domain, name = user[1][1:len(user[1])-1].split('\\')
            err, result = utm.get_ldap_user_guid(domain, name)
            if err:
                print(f"\033[31m\t{result}\033[0m")
                break
            elif not result:
                print(f'\t\033[31mНет LDAP-коннектора для домена "{domain}" или в домене нет пользователя {name}.')
                print('\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                break
            err2, result2 = utm.add_user_in_group(utm.list_groups[item['name']], result)
            if err2:
                print(f"\033[31m\t\t{result2}\033[0m")
            else:
                print(f'\t\tПользователь "{name}@{domain}" добавлен в группу "{item["name"]}".')

def import_firewall_rules(utm):
    """Импортировать список правил межсетевого экрана"""
    print('Импорт списка "Межсетевой экран" раздела "Политики сети":')
    try:
        with open("data/NetworkPolicies/Firewall/config_firewall_rules.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Межсетевой экран" не импортирован!\n\tНе найден файл "data/NetworkPolicies/Firewall/config_firewall_rules.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет правил межсетевого экрана для импорта.")
        return

    err, result = utm.get_firewall_rules()
    exit_if_error(err, result)
    firewall_rules = {x['name']: x['id'] for x in result}

    for item in data:
        get_guids_users_and_groups(utm, item)
        item['src_zones'] = get_zones(utm, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones(utm, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips(utm, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips(utm, item['dst_ips'], item['name'])
        item['services'] = get_services(utm, item['services'], item['name'])
        set_time_restrictions(utm, item)

        rule_id = firewall_rules.get(item['name'], None)
        if rule_id:
            print(f'\tПравило МЭ "{item["name"]}" уже существует', end= ' - ')
            err, result = utm.update_firewall_rule(rule_id, item)
            if err:
                print("\n", f"\033[31m\t{result1}\033[0m")
            else:
                print("\033[32mUpdated!\033[0;0m")
        else:
            err, result = utm.add_firewall_rule(item)
            if err:
                print(f"\033[31m\t{result}\033[0m")
            else:
                firewall_rules[item['name']] = result
                print(f'\tПравило МЭ "{item["name"]}" добавлено.')

def import_content_rules(utm):
    """Импортировать список правил фильтрации контента"""
    print('Импорт правил "Фильтрация контента" раздела "Политики безопасности":')
    try:
        with open("data/SecurityPolicies/ContentFiltering/config_content_rules.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mПравила фильтрации контента не импортированы!\n\tНе найден файл "data/SecurityPolicies/ContentFiltering/config_content_rules.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print("\tНет правил фильтрации контента для импорта.")
        return

    err, result = utm.get_content_rules()
    exit_if_error(err, result)
    content_rules = {x['name']: x['id'] for x in result}

    for item in data:
        set_time_restrictions(utm, item)
        set_urls_and_categories(utm, item)

        rule_id = content_rules.get(item['name'], None)
        if rule_id:
            print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
            item.pop('position', None)
            err, result = utm.update_content_rule(rule_id, item)
            if err:
                print("\n", f"\033[31m\t{result1}\033[0m")
            else:
                print("\033[32mUpdated!\033[0;0m")
        else:
            err, result = utm.add_content_rule(item)
            if err:
                print(f"\033[31m\t{result}\033[0m")
            else:
                content_rules[item['name']] = result
                print(f'\tПравило "{item["name"]}" добавлено.')
    print('\033[36;1mВнимание:\033[0m \033[36mПроверьте импортированные правила фильтрации контента.')
    print('Отредактируйте правила, задайте зоны и адреса источника/назначения, пользователей и другие параметры.\033[0m')

def import_nat_rules(utm):
    """Импортировать список правил NAT"""
    print('Импорт списка "NAT и маршрутизация" раздела "Политики сети":')
    try:
        with open("data/NetworkPolicies/NATandRouting/config_nat_rules.json", "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "NAT и маршрутизация" не импортирован!\n\tНе найден файл "data/NetworkPolicies/NATandRouting/config_nat_rules.json" с сохранённой конфигурацией!\033[0;0m')
        return

    if not data:
        print('\tНет правил в списке "NAT и маршрутизация" для импорта.')
        return

    err, result = utm.get_traffic_rules()
    exit_if_error(err, result)
    nat_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item['zone_in'] = get_zones(utm, item['zone_in'], item['name'])
        item['zone_out'] = get_zones(utm, item['zone_out'], item['name'])
        item['source_ip'] = get_ips(utm, item['source_ip'], item['name'])
        item['dest_ip'] = get_ips(utm, item['dest_ip'], item['name'])
        item['service'] = get_services(utm, item['service'], item['name'])

        if item['action'] == 'route':
            print(f'\t\033[33mПроверьте шлюз для правила ПБР "{item["name"]}".\n\tВ случае отсутствия, установите вручную.\033[0m')

        rule_id = nat_rules.get(item['name'], None)
        if rule_id:
            print(f'\tПравило "{item["name"]}" уже существует', end= ' - ')
            err, result = utm.update_traffic_rule(rule_id, item)
            if err:
                print("\n", f"\033[31m\t{result1}\033[0m")
            else:
                print("\033[32mUpdated!\033[0;0m")
        else:
            err, result = utm.add_traffic_rule(item)
            if err:
                print(f"\033[31m\t{result}\033[0m")
            else:
                nat_rules[item['name']] = result
                print(f'\tПравило "{item["name"]}" добавлено.')

############################################# Служебные функции ###################################################
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

def get_zones(utm, zones, rule_name):
    """Получить UID-ы зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for zone in zones:
        try:
            new_zones.append(utm.zones[zone])
        except KeyError as err:
            print(f'\t\033[33mЗона {err} для правила "{rule_name}" не найдена.\n\tЗагрузите список зон и повторите попытку.\033[0m')
    return new_zones

def get_ips(utm, rule_ips, rule_name):
    """Получить UID-ы списков IP-адресов и URL-листов. Если списки не существует на NGFW, то они пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', utm.list_ip[ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', utm.list_url[ips[1]]])
        except KeyError as err:
            print(f'\t\033[33mНе найден адрес источника/назначения {err} для правила "{rule_name}".\n\tЗагрузите списки IP-адресов и URL и повторите попытку.\033[0m')
    return new_rule_ips

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

def exit_if_error(err, result):
    if err:
        print(f"\033[31m\t{result}\033[0m")
        sys.exit(1)

def menu():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m                    Конвертация конфигурации с Cisco ASA на NGFW                   \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ca' в текущей директории на NGFW UserGate.\033[0m\n")
    print('\033[33mПеред запуском конвертации Удостоверьтесь, что:')
    print('\t1. В текущей директории создан каталог "data_ca".')
    print('\t2. Конфигурация Cisco ASA выложена в каталог "data_ca" в текущей директории.')
    print('\t3. Файл конфигурации имеет имя "config_asa.txt". Если это не так, переименуйте его.')
    print('\t4. Вы подключились к веб-консоли администратора в зоне Management.\033[0m')
    print('\033[36m\nПереносятся настройки:')
    print('\tМодули                         - "Настойки/Модули"')
    print('\tЧасовой пояс                   - "Настойки/Настройки интерфейса"')
    print('\tНастройка NTP                  - "Настойки/Настройка времени сервера"')
    print('\tСписки IP-адресов              - "Библиотеки/IP-адреса"')
    print('\tСписки URL                     - "Библиотеки/Списки URL"')
    print('\tСервисы                        - "Библиотеки/Сервисы"')
    print('\tВременные интервалы            - "Библиотеки/Календари"')
    print('\tПользователи                   - "Пользователи и устройства/Пользователи"')
    print('\tЛокальные группы пользователей - "Пользователи и устройства/Группы"')
    print('\tRadius, Tacacs, LDAP           - "Пользователи и устройства/Серверы аутентификации"')
    print('\tЗоны                           - "Сеть/Зоны"')
    print('\tИнтерфейсы VLAN                - "Сеть/Интерфейсы"')
    print('\tШлюзы                          - "Сеть/Шлюзы"')
    print('\tDHCP                           - "Сеть/DHCP"')
    print('\tDNS                            - "Сеть/DNS"')
    print('\tСтатические маршруты           - "Сеть/Виртуальные маршрутизаторы/Статические маршруты"')
    print('\tAccess-lists                   - "Политики сети/Межсетевой экран"')
    print('\tNAT, DNAT, Port-форвардинг     - "Политики сети/NAT и маршрутизация"')
    print('\tWebtype ACLs                   - "Политики безопасности/Фильтрация контента"\033[0m')

    print("\n")   
    print("1  - Экспорт конфигурации из файла.")
    print("2  - Импорт конфигурации на NGFW.")
    print("\033[33m0  - Выход.\033[0m")

    while True:
        try:
            mode = int(input("\nВведите номер нужной операции: "))
            if mode not in (0, 1, 2):
                print("Вы ввели несуществующую команду.")
            elif mode == 0:
                sys.exit()
            else:
                return mode
        except ValueError:
            print("Ошибка! Введите число.")

def menu_import():
    print("\033c")
    print(f"\033[1;36;43mUserGate\033[1;37;43m                    Конвертация конфигурации с Cisco ASA на NGFW                   \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mЭкспорт подготовленной конфигурации из каталога 'data' в текущей директории на NGFW UserGate v7.\033[0m\n")
    print("Выберите раздел для импорта.\n")
    print('   1  - Списки IP-адресов          - "Библиотеки/IP-адреса"')
    print('   2  - Списки URL                 - "Библиотеки/Списки URL"')
    print('   3  - Сервисы                    - "Библиотеки/Сервисы"')
    print('   4  - Временные интервалы        - "Библиотеки/Календари"')
    print('   5  - Часовой пояс               - "UserGate/Настойки/Настройки интерфейса"')
    print('   6  - Настройка NTP              - "UserGate/Настойки/Настройка времени сервера"')
    print('   7  - Модули                     - "UserGate/Настойки/Модули"')
    print('   8  - Зоны                       - "Сеть/Зоны"')
    print('   9  - Интерфейсы VLAN            - "Сеть/Интерфейсы"')
    print('  10  - Шлюзы                      - "Сеть/Шлюзы"')
    print('  11  - DHCP                       - "Сеть/DHCP"')
    print('  12  - DNS                        - "Сеть/DNS"')
    print('  13  - Статические маршруты       - "Сеть/Виртуальные маршрутизаторы/Статические маршруты"')
    print('  14  - Radius                     - "Пользователи и устройства/Серверы аутентификации"')
    print('  15  - Tacacs                     - "Пользователи и устройства/Серверы аутентификации"')
    print('  16  - LDAP                       - "Пользователи и устройства/Серверы аутентификации"')
    print('  17  - Пользователи               - "Пользователи и устройства/Пользователи"')
    print('  18  - Группы пользователей       - "Пользователи и устройства/Группы"')
    print('  19  - Access-lists               - "Политики сети/Межсетевой экран"')
    print('  20  - NAT, DNAT, Port-форвардинг - "Политики сети/NAT и маршрутизация"')
    print('  21  - Webtype ACLs               - "Политики безопасности/Фильтрация контента"')
    print("\n")   
    print("  99  - Импортировать всё.")
    print("  \033[33m 0  - Вверх (вернуться в предыдущее меню).\033[0m")

    while True:
        try:
            mode = int(input("\nВведите номер нужной операции: "))
            if mode not in (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 99):
                print("Вы ввели несуществующую команду.")
#            elif mode == 0:
#                sys.exit()
            else:
                return mode
        except ValueError:
            print("Ошибка! Введите число.")

def main():
    print("\033c")
    print("\033[1;36;43mUserGate\033[1;37;43m                     Конвертация конфигурации с Cisco ASA на NGFW                   \033[1;36;43mUserGate\033[0m\n")
    print("\033[32mПрограмма импортирует конфигурацию из каталога 'data_ca' в текущей директории на NGFW UserGate.\033[0m\n")
    server_ip = ""
    login = ""
    password = ""
    try:
        while True:
            mode = menu()
            if mode == 1:
                file_name = "config_asa"
                if not os.path.isfile(f"data_ca/{file_name}.txt"):
                    print(f'\t\033[31mИмпорт aborted!\n\tНе найден файл "data_ca/config_asa.txt" с конфигурацией Cisco ASA!\033[0;0m')
                    sys.exit(1)

                server_ip = input("\033[36m\nВведите IP-адрес UTM:\033[0m ")
                login = input("\033[36mВведите логин администратора UTM:\033[0m ")
                password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
                utm = UtmXmlRpc(server_ip, login, password)
                utm.connect()
                utm.login()
                print()

                try:
                    convert_file(utm, file_name)
                except json.JSONDecodeError as err:
                    print(f"\n\033[31mОшибка парсинга конфигурации: {err}\033[0m")
                    sys.exit(1)
                finally:
                    print("\033[32mЭкспорт конфигурации завершён.\033[0m\n")
                    while True:
                        input_value = input("\nНажмите пробел для возврата в меню: ")
                        if input_value == " ":
                            utm.logout()
                            break
            elif mode == 2:
                while True:
                    section = menu_import()
                    if not section:
                        break
                    if not server_ip:
                        server_ip = input("\033[36m\nВведите IP-адрес UTM:\033[0m ")
                        login = input("\033[36mВведите логин администратора UTM:\033[0m ")
                        password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
                    utm = UtmXmlRpc(server_ip, login, password)
                    utm.connect()
                    utm.login()
                    print()

                    err, (ldap, radius, tacacs, _, _) = utm.get_auth_servers()
                    exit_if_error(err, f'Error utm.get_auth_servers - [{ldap}].')
                    utm.auth_servers = {x['name']: x['id'] for x in [*ldap, *radius, *tacacs]}

                    err, result = utm.get_users_list()
                    exit_if_error(err, result)
                    utm.list_users = {x['name']: x['id'] for x in result}

                    err, result = utm.get_groups_list()
                    exit_if_error(err, result)
                    utm.list_groups = {x['name']: x['id'] for x in result}

                    err, result = utm.get_zones_list()
                    exit_if_error(err, result)
                    utm.zones = {x['name']: x['id'] for x in result}

                    err, result = utm.get_services_list()
                    exit_if_error(err, result)
                    utm.services = {x['name']: x['id'] for x in result}

                    err, result = utm.get_nlists_list('network')
                    exit_if_error(err, result)
                    utm.list_ip = {x['name']: x['id'] for x in result}

                    err, result = utm.get_nlists_list('url')
                    exit_if_error(err, result)
                    utm.list_url = {x['name']: x['id'] for x in result}
                    
                    err, result = utm.get_nlists_list('timerestrictiongroup')
                    exit_if_error(err, result)
                    utm.list_calendar = {x['name']: x['id'] for x in result}

                    match section:
                        case 99:
                            import_IP_lists(utm)
                            import_url_lists(utm)
                            import_services(utm)
                            import_time_restricted_lists(utm)
                            import_ui(utm)
                            import_ntp(utm)
                            import_settings(utm)
                            import_zones(utm)
                            import_interfaces(utm)
                            import_gateways_list(utm)
                            import_dhcp_subnets(utm)
                            import_dns_servers(utm)
                            import_dns_rules(utm)
                            import_virt_routes(utm)
                            import_radius_server(utm)
                            import_tacacs_server(utm)
                            import_ldap_server(utm)
                            import_users(utm)
                            import_local_groups(utm)
                            import_firewall_rules(utm)
                            import_content_rules(utm)
                            import_nat_rules(utm)
                        case 1:
                            import_IP_lists(utm)
                        case 2:
                            import_url_lists(utm)
                        case 3:
                            import_services(utm)
                        case 4:
                            import_time_restricted_lists(utm)
                        case 5:
                            import_ui(utm)
                        case 6:
                            import_ntp(utm)
                        case 7:
                            import_settings(utm)
                        case 8:
                            import_zones(utm)
                        case 9:
                            import_interfaces(utm)
                        case 10:
                            import_gateways_list(utm)
                        case 11:
                            import_dhcp_subnets(utm)
                        case 12:
                            import_dns_servers(utm)
                            import_dns_rules(utm)
                        case 13:
                            import_virt_routes(utm)
                        case 14:
                            import_radius_server(utm)
                        case 15:
                            import_tacacs_server(utm)
                        case 16:
                            import_ldap_server(utm)
                        case 17:
                            import_users(utm)
                        case 18:
                            import_local_groups(utm)
                        case 19:
                            import_firewall_rules(utm)
                        case 20:
                            import_nat_rules(utm)
                        case 21:
                            import_content_rules(utm)
                    utm.logout()
                    print("\n\033[32mИмпорт конфигурации Cisco ASA на NGFW UserGate завершён.\033[0m\n")
                    while True:
                        input_value = input("\nНажмите пробел для возврата в меню: ")
                        if input_value == " ":
#                            utm.logout()
                            break

    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        sys.exit()

if __name__ == '__main__':
    main()
