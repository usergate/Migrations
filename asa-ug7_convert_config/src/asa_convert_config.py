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
# Версия 2.1
#

import os, sys, json
import stdiomask
import ipaddress
from datetime import datetime as dt
from services import character_map, character_map_for_users, character_map_for_name, service_ports
from utm import UtmXmlRpc


def convert_file(utm, file_name):
    """Преобразуем файл конфигурации Cisco ASA в json."""
    print('Преобразование файла конфигурации Cisco ASA в json.')

    trans_table = str.maketrans(character_map)
    trans_name = str.maketrans(character_map_for_name)
    err, protocol_names = utm.get_ip_protocol_list()
    if err:
        print(err)
        sys.exit()
    dhcp_enabled = 0
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
                "sessions_limit_threshold": -1,
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
                            iface['zone_id'] = zones[value]['name']
                            iface['mtu'] = iface_mtu[value]
                            
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
                "descriprion": "",
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
                "descriprion": "",
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
                _, data = utm.get_interfaces_list()
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
            proto = ''
            match item:
                case ['protocol-object', protocol]:
                    if protocol.isdigit():
                        protocol = ip_proto.get(protocol, None)
                    if protocol and protocol in ip_protocol_list:
                        proto = protocol
                    else:
                        print(f"\033[33mСервис {item} в {name} не конвертирован.\n\tНельзя задать протокол {protocol} в UG NGFW.\033[0m")
                        continue
                case ['description', *content]:
                    service['description'] = " ".join(content)

            service['protocols'].append(
                {
                    "proto": proto,
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

#    json_string = json.dumps([x for x in zones.values()], indent=4, ensure_ascii=False)
#    print(json_string, "\n")
            
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
        if err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\t{params[key]} - \033[32mUpdated!\033[0m')

def import_ui(utm):
    """Импортировать настройки интерфейса"""
    print('Импорт "Настройки интерфейса" веб-консоли раздела "Настройки":')

    result = utm._server.v1.content.ssl.profiles.list(utm._auth_token, 0, 100, {})
    list_ssl_profiles = {x['name']: x['id'] for x in result['items']}

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
            if err == 2:
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
    if err == 2:
        print(f"\033[31m{result}\033[0m")
    else:
        print(f'\tНастройки NTP обновлены.')

def import_IP_lists(utm):
    """Импортировать списки IP адресов"""
    print('Импорт списков IP-адресов раздела "Библиотеки":')

    result = utm._server.v2.nlists.list(utm._auth_token, 'network', 0, 5000, {})
    list_IP = {x['name']: x['id'] for x in result['items']}

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
                if err == 1:
                    print(result, end= ' - ')
                    result = list_IP[ip_list['name']]
                    err1, result1 = utm.update_nlist(result, ip_list)
                    if err1 != 0:
                        print("\n", f"\033[31m{result1}\033[0m")
                    else:
                        print("\033[32mUpdated!\033[0;0m")
                elif err == 2:
                    print(f"\033[31m{result}\033[0m")
                    continue
                else:
                    list_IP[ip_list['name']] = result
                    print(f'\tДобавлен список IP-адресов: "{ip_list["name"]}".')
                if content:
                    err2, result2 = utm.add_nlist_items(result, content)
                    if err2 in (1, 3):
                        print(result2)
                    elif err2 == 2:
                        print(f"\033[31m{result2}\033[0m")
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

    result = utm._server.v2.nlists.list(utm._auth_token, 'url', 0, 5000, {})
    list_url = {x['name']: x['id'] for x in result['items']}

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
                if err == 1:
                    print(result, end= ' - ')
                    result = list_url[url_list['name']]
                    err1, result1 = utm.update_nlist(result, url_list)
                    if err1 != 0:
                        print("\n", f'\033[31m{result1}\033[0m')
                    else:
                        print("\033[32mOk!\033[0;0m")
                elif err == 2:
                    print(f"\033[31m{result}\033[0m")
                    continue
                else:
                    list_url[url_list['name']] = result
                    print(f'\t\tСписок URL: "{url_list["name"]}" добавлен.')
                if content:
                    for item in content:
                        print(f"\t\tURL '{item['value']}' добавляется в список.")
                        err2, result2 = utm.add_nlist_item(result, item)
                        if err2 == 2:
                            print(f"\033[31m\t\tURL '{item['value']}' не добавлен.\033[0m")
                            print(f"\033[31m{result2}\033[0m")
                    print(f'\t\tСодержимое списка "{url_list["name"]}" обновлено.')
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

    result = utm._server.v1.libraries.services.list(utm._auth_token, 0, 5000, {}, [])
    utm_services = {x['name']: x['id'] for x in result['items']}

    for item in services:
        err, result = utm.add_service(item)
        if err == 1:
            print(result, end= ' - ')
            try:
                err1, result1 = utm.update_service(utm_services[item['name']], item)
            except KeyError as keyerr:
                print(f"\n\t\t\033[31mService {keyerr} not updated.\n\t\tУстановите последнее обновление на UTM и повторите попытку.\033[0m")
            else:
                if err1 != 0:
                    print(result1)
                else:
                    print("\033[32mOk!\033[0;0m")
        elif err == 2:
            print(result)
        else:
            utm_services[item['name']] = result
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

    result = utm._server.v2.nlists.list(utm._auth_token, 'timerestrictiongroup', 0, 1000, {})
    list_of_calendars = {x['name']: x['id'] for x in result['items']}

    for item in data:
        content = item.pop('content')
        err, result = utm.add_nlist(item)
        if err == 1:
            print(result, end= ' - ')
            result = list_of_calendars[item['name']]
            err1, result1 = utm.update_nlist(result, item)
            if err1 != 0:
                print("\n", f"\033[31m{result1}\033[0m")
            else:
                print("\033[32mOk!\033[0;0m")
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
            continue
        else:
            list_of_calendars[item['name']] = result
            print(f'\tДобавлен элемент календаря: "{item["name"]}".')
        for x in content:
            err2, result2 = utm.add_nlist_item(result, x)
            if err2 == 2:
                print(f"\033[31m{result2}\033[0m")
        print(f'\t\tСодержимое списка "{item["name"]}" обновлено.')

def import_zones(utm):
    """Импортировать зоны на UTM"""
    print('Импорт списка "Зоны" раздела "Сеть":')

    _, result = utm.get_zones_list()
    utm_zones = {x['name']: x['id'] for x in result}

    try:
        with open("data/Network/Zones/config_zones.json", "r") as fd:
            zones = json.load(fd)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок "Зоны" не импортирован!\n\tНе найден файл "data/Network/Zones/config_zones.json" с сохранённой конфигурацией!\033[0;0m')
        return

    for item in zones:
        err, result = utm.add_zone(item)
        if err == 1:
            print(result, end= ' - ')
            err1, result1 = utm.update_zone(utm_zones[item['name']], item)
            if err1 != 0:
                print(result1)
            else:
                print("\033[32mOk!\033[0;0m")
        elif err == 2:
            print(result)
        else:
            utm_zones[item['name']] = result
            print(f"\tЗона '{item['name']}' добавлена.")
    print('\033[36;1mВнимание:\033[0m \033[36mНеобходимо настроить каждую зону. Включить нужный сервис в контроле доступа,')
    print('поменять по необходимости параметры защиты от DoS и настроить защиту от спуфинга.\033[0m')

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
        print(f'\t\033[31mСписок "Зоны" не импортирован!\n\tНе найден файл "data/Network/Interfaces/config_interfaces.json" с сохранённой конфигурацией!\033[0;0m')
        return

    management_port = ''
    utm_vlans = {}
    interfaces_list = {}

    _, result = utm.get_zones_list()
    utm_zones = {x['name']: x['id'] for x in result}
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
                item['zone_id'] = utm_zones[item['zone_id']]
            except KeyError as err:
                print(f'\t\033[33mЗона {err} для интерфейса "{item["name"]}" не найдена.\n\tСоздайте зону {err} и присвойте этому VLAN.\033[0m')
                item['zone_id'] = 0

        item.pop('kind')
        err, result = utm.add_interface_vlan(item)
        if err == 2:
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

    _, result = utm.get_gateways_list()
    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}

    for item in data:
        if not item['is_automatic']:
            if item['name'] in gateways_list:
                print(f'\tШлюз "{item["name"]}" уже существует', end= ' - ')
                err, result = utm.update_gateway(gateways_list[item['name']], item)
                if err == 2:
                    print("\n", f"\033[31m{result}\033[0m")
                else:
                    print("\033[32mUpdated!\033[0;0m")
            else:
                err, result = utm.add_gateway(item)
                if err == 2:
                    print(f"\033[31m{result}\033[0m")
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

    _, data = utm.get_interfaces_list()
    dst_ports = [x['name'] for x in data if not x['name'].startswith('tunnel')]

    _, data = utm.get_dhcp_list()
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
        print(f"\033[31m{result}\033[0m") if err else print(f'\tSubnet "{item["name"]}" добавлен.')

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
        if err == 1:
            print(result)
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
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

    dns_rules = [x['name'] for x in utm._server.v1.dns.rules.list(utm._auth_token, 0, 1000, {})['items']]
    for item in data:
        if item['name'] in dns_rules:
            print(f'\tПравило DNS прокси "{item["name"]}" уже существует.')
        else:
            err, result = utm.add_dns_rule(item)
            if err == 1:
                print(result)
            elif err == 2:
                print(f"\033[31m{result}\033[0m")
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

    virt_routers = {x['name']: x['id'] for x in utm.get_routers_list()}

    for item in data:
        if item['name'] in virt_routers:
            err, result = utm.update_routers_rule(virt_routers[item['name']], item)
            if err == 2:
                print(f'\033[31m{result}\033[0m')
            else:
                print(f'\tВиртуальный маршрутизатор "{item["name"]}" - \033[32mUpdated!\033[0m')
        else:
            err, result = utm.add_routers_rule(item)
            if err == 2:
                print(f'\033[31m{result}\033[0m')
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
        err, result = utm.add_auth_server('radius', item)
        if err == 1:
            print(result)
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
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
        err, result = utm.add_auth_server('tacacs', item)
        if err == 1:
            print(result)
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
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

    for item in data:
        item['keytab_exists'] = False
        item.pop("cc", None)
        err, result = utm.add_auth_server('ldap', item)
        if err == 1:
            print(result)
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            print(f'\tСервер авторизации LDAP "{item["name"]}" добавлен.')
            print(f'\t\033[36mПри необходимости, включить "{item["name"]}", ввести пароль и импортировать keytab файл.\033[0m')

def import_users(utm):
    """Импортировать список локальных пользователей"""
    print('Импорт списка локальных пользователей раздела "Пользователи и устройства":')
    try:
        with open("data/UsersAndDevices/Users/config_users.json", "r") as fh:
            users = json.load(fh)
    except FileNotFoundError as err:
        print(f'\t\033[31mСписок локальных пользователей не импортирован!\n\tНе найден файл "data/UsersAndDevices/Users/config_users.json" с сохранённой конфигурацией!\033[0;0m')
        return

    _, result = utm.get_users_list()
    users_list = {x['auth_login'] for x in result}

    for item in users:
        if item['auth_login'] in users_list:
            print(f'\tПользователь "{item["name"]}" уже существует.')
            continue
        err, result = utm.add_user(item)
        if err == 1:
            print(f'\t{result}')
        elif err == 2:
            print(f'\033[31m{result}\033[0m')
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

    _, result = utm.get_users_list()
    users_list = {x['auth_login']: x['guid'] for x in result}

    _, result = utm.get_groups_list()
    list_groups = {x['name']: x['guid'] for x in result}

    for item in groups:
        users = item.pop('users')
        err, result = utm.add_group(item)
        if err == 1:
            print(result, end= ' - ')
            item['guid'] = list_groups[item['name']]
            err1, result1 = utm.update_group(item)
            if err1 != 0:
                print("\n", f"\033[31m{result1}\033[0m")
            else:
                print("\033[32mOk!\033[0;0m")
        elif err == 2:
            print(f"\033[31m{result}\033[0m")
        else:
            list_groups[item['name']] = result
            print(f'\tЛокальная группа "{item["name"]}" добавлена.')

        domain_users = []
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1:
                domain_users.append(user_array)
            else:
                err2, result2 = utm.add_user_in_group(list_groups[item['name']], users_list[user_name])
                if err2 != 0:
                    print(f"\033[31m{result2}\033[0m")
                else:
                    print(f'\t\tПользователь "{user_name}" добавлен в группу "{item["name"]}".')
        for user in domain_users:
            domain, name = user[1][1:len(user[1])-1].split('\\')
            err, result = utm.get_ldap_user_guid(domain, name)
            if err:
                print(f"\033[31m{result}\033[0m")
                break
            elif not result:
                print(f'\t\033[31mНет LDAP-коннектора для домена "{domain}" или в домене нет пользователя {name}.')
                print('\tИмпортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.\033[0m')
                break
            err2, result2 = utm.add_user_in_group(list_groups[item['name']], result)
            if err2 != 0:
                print(f"\033[31m{result2}\033[0m")
            else:
                print(f'\t\tПользователь "{name}@{domain}" добавлен в группу "{item["name"]}".')

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
    print('\tСтатические маршруты           - "Сеть/Виртуальные маршрутизаторы/Статические маршруты"\033[0m')

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
                utm._connect()
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
                if not server_ip:
                    server_ip = input("\033[36m\nВведите IP-адрес UTM:\033[0m ")
                    login = input("\033[36mВведите логин администратора UTM:\033[0m ")
                    password = stdiomask.getpass("\033[36mВведите пароль:\033[0m ")
                utm = UtmXmlRpc(server_ip, login, password)
                utm._connect()
                print()
                ldap, radius, tacacs, _, _ = utm.get_auth_servers()
                utm.auth_servers = {x['name']: x['id'] for x in [*ldap, *radius, *tacacs]}

#                try:
#                    import_IP_lists(utm)
#                    import_url_lists(utm)
#                    import_services(utm)
#                    import_time_restricted_lists(utm)
#                    import_ui(utm)
#                    import_ntp(utm)
#                    import_settings(utm)
#                    import_zones(utm)
#                    import_interfaces(utm)
#                    import_gateways_list(utm)
#                    import_dhcp_subnets(utm)
#                    import_dns_servers(utm)
#                    import_dns_rules(utm)
#                    import_virt_routes(utm)
#                    import_radius_server(utm)
#                    import_tacacs_server(utm)
                import_ldap_server(utm)
                import_users(utm)
                import_local_groups(utm)
#                except Exception as err:
#                    print(f'\n\033[31mОшибка: {err}\033[0m')
#                    utm.logout()
#                    sys.exit(1)
#                else:
                utm.logout()
                print("\n\033[32mИмпорт конфигурации Cisco ASA на NGFW UserGate завершён.\033[0m\n")
                while True:
                    input_value = input("\nНажмите пробел для возврата в меню: ")
                    if input_value == " ":
#                        utm.logout()
                        break

    except KeyboardInterrupt:
        print("\nПрограмма принудительно завершена пользователем.")
        sys.exit()

if __name__ == '__main__':
    main()
