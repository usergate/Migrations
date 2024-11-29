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
# Версия 3.7 29.11.2024
#

import os, sys, json, uuid
import ipaddress, chardet
import copy, time
import common_func as func
from datetime import datetime as dt
from PyQt6.QtCore import QThread, pyqtSignal
from services import zone_services, trans_table, trans_filename, trans_userlogin, ug_services, ip_proto


class ConvertFortigateConfig(QThread):
    """Преобразуем файл конфигурации Fortigate в формат UserGate NGFW."""
    stepChanged = pyqtSignal(str)

    def __init__(self, current_fg_path, current_ug_path):
        super().__init__()
        self.current_fg_path = current_fg_path
        self.current_ug_path = current_ug_path
        self.zones = set()
        self.services = {}
        self.service_groups = set()
        self.ip_lists = set()
        self.url_lists = {}
        self.local_users = {}
        self.local_groups = set()
        self.time_restrictions = set()
        self.vrf = {
            'name': 'default',
            'descriprion': '',
            'interfaces': [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }
        self.vendor = 'Fortigate'
        self.error = 0

    def run(self):
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации Fortigate в формат UserGate NGFW.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        convert_config_file(self, self.current_fg_path)
#        return
        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации Fortigate в формат UserGate NGFW прервана.')
        else:
            json_file = os.path.join(self.current_fg_path, 'config.json')
            err, data = func.read_json_file(self, json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации Fortigate в формат UserGate NGFW прервана.\n')
            else:
                convert_ntp_settings(self, self.current_ug_path, data)
                convert_dns_servers(self, self.current_ug_path, data)
                convert_vpn_interfaces(self, self.current_ug_path, data['config system interface'])
                convert_zone_settings(self, self.current_ug_path, data)
                convert_dhcp_settings(self, self.current_ug_path, data)
                convert_notification_profile(self, self.current_ug_path, data)
                convert_services(self, self.current_ug_path, data)
                convert_service_groups(self, self.current_ug_path, data)
                convert_url_lists(self, self.current_ug_path, data)
                convert_ip_lists(self, self.current_ug_path, data)
                convert_virtual_ip(self, self.current_ug_path, data)
                convert_groups_iplists(self, self.current_ug_path, data)
                convert_time_sets(self, self.current_ug_path, data)
                convert_shapers_list(self, self.current_ug_path, data)
                convert_shapers_rules(self, self.current_ug_path, data)
                convert_auth_servers(self, self.current_ug_path, data)
                convert_local_users(self, self.current_ug_path, data)
                convert_user_groups(self, self.current_ug_path, data)
                convert_web_portal_resources(self, self.current_ug_path, data)
                convert_dnat_rule(self, self.current_ug_path, data)
                convert_loadbalancing_rule(self, self.current_ug_path, data)
                convert_firewall_policy(self, self.current_ug_path, data)
                convert_gateways_list(self, self.current_ug_path, data)
                convert_static_routes(self, self.current_ug_path, data)
                convert_bgp_routes(self, self.current_ug_path, data)

                if self.error:
                    self.stepChanged.emit('iORANGE|Конвертация конфигурации Fortigate в формат UserGate NGFW прошла с ошибками.\n')
                else:
                    self.stepChanged.emit('iGREEN|Конвертация конфигурации Fortigate в формат UserGate NGFW прошла успешно.\n')


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
    bad_cert_block = {'config global',
                      'config dashboard',
                      'config certificate ca',
                      'config dlp rule',
                      'config dlp sensor',
                      'config firewall ssh local-key',
                      'config firewall ssh local-ca',
                      'config gui console',
                      'config vpn certificate ca',
                      'config vpn certificate local',
                      'config certificate local',
                      'config log disk setting',
                      'config web-proxy explicit',
                      'config report chart',
                      'config report dataset',
                      'config report layout',
                      'config report style',
                      'config report summary',
                      'config report theme',
                      'config system admin',
                      'config system accprofile',
                      'config system auto-install',
                      'config system ha',
                      'config system snmp sysinfo',
                      'config system replacemsg-group',
                      'config system replacemsg-image',
                      'config system replacemsg admin admin-disclaimer-text',
                      'config system replacemsg admin pre_admin-disclaimer-text',
                      'config system replacemsg admin post_admin-disclaimer-text',
                      'config system replacemsg alertmail alertmail-virus',
                      'config system replacemsg alertmail alertmail-block',
                      'config system replacemsg alertmail alertmail-nids-event',
                      'config system replacemsg alertmail alertmail-crit-event',
                      'config system replacemsg alertmail alertmail-disk-full',
                      'config system replacemsg auth auth-block-notification-page',
                      'config system replacemsg auth auth-cert-passwd-page',
                      'config system replacemsg auth auth-disclaimer-page-1',
                      'config system replacemsg auth auth-disclaimer-page-2',
                      'config system replacemsg auth auth-disclaimer-page-3',
                      'config system replacemsg auth auth-email-token-page',
                      'config system replacemsg auth auth-email-harvesting-page',
                      'config system replacemsg auth auth-email-failed-page',
                      'config system replacemsg auth auth-fortitoken-page',
                      'config system replacemsg auth auth-guest-email-page',
                      'config system replacemsg auth auth-guest-print-page',
                      'config system replacemsg auth auth-reject-page',
                      'config system replacemsg auth auth-login-page',
                      'config system replacemsg auth auth-login-failed-page',
                      'config system replacemsg auth auth-challenge-page',
                      'config system replacemsg auth auth-keepalive-page',
                      'config system replacemsg auth auth-next-fortitoken-page',
                      'config system replacemsg auth auth-token-login-page',
                      'config system replacemsg auth auth-token-login-failed-page',
                      'config system replacemsg auth auth-password-page',
                      'config system replacemsg auth auth-portal-page',
                      'config system replacemsg auth auth-quarantine-page',
                      'config system replacemsg auth auth-qtn-reject-page',
                      'config system replacemsg auth auth-saml-page',
                      'config system replacemsg auth auth-sms-token-page',
                      'config system replacemsg auth auth-success-msg',
                      'config system replacemsg auth auth-success-page',
                      'config system replacemsg device-detection-portal device-detection-failure',
                      'config system replacemsg ec endpt-download-ftcl',
                      'config system replacemsg ec endpt-download-portal',
                      'config system replacemsg ec endpt-download-portal-mac',
                      'config system replacemsg ec endpt-download-portal-ios',
                      'config system replacemsg ec endpt-download-portal-aos',
                      'config system replacemsg ec endpt-download-portal-other',
                      'config system replacemsg ec endpt-ftcl-incompat',
                      'config system replacemsg ec endpt-recommendation-portal',
                      'config system replacemsg ec endpt-remedy-av-3rdp',
                      'config system replacemsg ec endpt-remedy-inst',
                      'config system replacemsg ec endpt-remedy-ftcl-autofix',
                      'config system replacemsg ec endpt-remedy-os-ver',
                      'config system replacemsg ec endpt-remedy-reg',
                      'config system replacemsg ec endpt-remedy-sig-ids',
                      'config system replacemsg ec endpt-remedy-ver',
                      'config system replacemsg ec endpt-remedy-vuln',
                      'config system replacemsg ec endpt-quarantine-portal',
                      'config system replacemsg ec endpt-warning-portal',
                      'config system replacemsg ec endpt-warning-portal-mac',
                      'config system replacemsg icap icap-req-resp',
                      'config system replacemsg im im-file-xfer-block',
                      'config system replacemsg im im-file-xfer-name',
                      'config system replacemsg im im-file-xfer-infected',
                      'config system replacemsg im im-file-xfer-size',
                      'config system replacemsg im im-dlp',
                      'config system replacemsg im im-dlp-ban',
                      'config system replacemsg im im-voice-chat-block',
                      'config system replacemsg im im-photo-share-block',
                      'config system replacemsg im im-long-chat-block',
                      'config system replacemsg mail partial',
                      'config system replacemsg mail email-av-fail',
                      'config system replacemsg mail email-block',
                      'config system replacemsg mail email-decompress-limit',
                      'config system replacemsg mail email-virus',
                      'config system replacemsg mail email-dlp',
                      'config system replacemsg mail email-dlp-subject',
                      'config system replacemsg mail email-dlp-ban',
                      'config system replacemsg mail email-dlp-ban-sender',
                      'config system replacemsg mail email-filesize',
                      'config system replacemsg mail smtp-block',
                      'config system replacemsg mail smtp-decompress-limit',
                      'config system replacemsg mail smtp-virus',
                      'config system replacemsg mail smtp-filesize',
                      'config system replacemsg http bannedword',
                      'config system replacemsg http http-archive-block',
                      'config system replacemsg http http-block',
                      'config system replacemsg http http-virus',
                      'config system replacemsg http http-filesize',
                      'config system replacemsg http http-dlp',
                      'config system replacemsg http http-dlp-ban',
                      'config system replacemsg http http-client-block',
                      'config system replacemsg http http-client-archive-block',
                      'config system replacemsg http http-client-virus',
                      'config system replacemsg http http-client-filesize',
                      'config system replacemsg http http-client-bannedword',
                      'config system replacemsg http http-post-block',
                      'config system replacemsg http url-block',
                      'config system replacemsg http urlfilter-err',
                      'config system replacemsg http infcache-block',
                      'config system replacemsg http http-contenttypeblock',
                      'config system replacemsg http https-invalid-cert-block',
                      'config system replacemsg http https-untrusted-cert-block',
                      'config system replacemsg http https-blacklisted-cert-block',
                      'config system replacemsg http switching-protocols-block',
                      'config system replacemsg http http-antiphish-block',
                      'config system replacemsg ftp ftp-av-fail',
                      'config system replacemsg ftp ftp-explicit-banner',
                      'config system replacemsg ftp ftp-dl-archive-block',
                      'config system replacemsg ftp ftp-dl-infected',
                      'config system replacemsg ftp ftp-dl-blocked',
                      'config system replacemsg ftp ftp-dl-filesize',
                      'config system replacemsg ftp ftp-dl-dlp',
                      'config system replacemsg ftp ftp-dl-dlp-ban',
                      'config system replacemsg fortiguard-wf ftgd-block',
                      'config system replacemsg fortiguard-wf ftgd-ovrd',
                      'config system replacemsg fortiguard-wf ftgd-quota',
                      'config system replacemsg fortiguard-wf ftgd-warning',
                      'config system replacemsg fortiguard-wf http-err',
                      'config system replacemsg nac-quar nac-quar-virus',
                      'config system replacemsg nac-quar nac-quar-dos',
                      'config system replacemsg nac-quar nac-quar-ips',
                      'config system replacemsg nac-quar nac-quar-dlp',
                      'config system replacemsg nac-quar nac-quar-admin',
                      'config system replacemsg nac-quar nac-quar-app',
                      'config system replacemsg nntp nntp-av-fail',
                      'config system replacemsg nntp nntp-dl-infected',
                      'config system replacemsg nntp nntp-dl-blocked',
                      'config system replacemsg nntp nntp-dl-filesize',
                      'config system replacemsg nntp nntp-dlp',
                      'config system replacemsg nntp nntp-dlp-subject',
                      'config system replacemsg nntp nntp-dlp-ban',
                      'config system replacemsg nntp email-decompress-limit',
                      'config system replacemsg sslvpn hostcheck-error',
                      'config system replacemsg sslvpn sslvpn-header',
                      'config system replacemsg sslvpn sslvpn-login',
                      'config system replacemsg sslvpn sslvpn-limit',
                      'config system replacemsg sslvpn sslvpn-provision-user',
                      'config system replacemsg sslvpn sslvpn-provision-user-sms',
                      'config system replacemsg spam ipblocklist',
                      'config system replacemsg spam smtp-spam-dnsbl',
                      'config system replacemsg spam smtp-spam-feip',
                      'config system replacemsg spam smtp-spam-helo',
                      'config system replacemsg spam smtp-spam-emailblack',
                      'config system replacemsg spam smtp-spam-mimeheader',
                      'config system replacemsg spam reversedns',
                      'config system replacemsg spam smtp-spam-bannedword',
                      'config system replacemsg spam smtp-spam-ase',
                      'config system replacemsg spam submit',
                      'config system replacemsg traffic-quota per-ip-shaper-block',
                      'config system replacemsg utm appblk-html',
                      'config system replacemsg utm archive-block-html',
                      'config system replacemsg utm archive-block-text',
                      'config system replacemsg utm banned-word-html',
                      'config system replacemsg utm banned-word-text',
                      'config system replacemsg utm block-html',
                      'config system replacemsg utm block-text',
                      'config system replacemsg utm client-file-size-html',
                      'config system replacemsg utm client-virus-html',
                      'config system replacemsg utm decompress-limit-text',
                      'config system replacemsg utm dlp-html',
                      'config system replacemsg utm dlp-text',
                      'config system replacemsg utm dlp-subject-text',
                      'config system replacemsg utm exe-text',
                      'config system replacemsg utm file-av-fail-text',
                      'config system replacemsg utm file-filter-html',
                      'config system replacemsg utm file-filter-text',
                      'config system replacemsg utm file-size-html',
                      'config system replacemsg utm file-size-text',
                      'config system replacemsg utm internal-error-text',
                      'config system replacemsg utm ipsblk-html',
                      'config system replacemsg utm ipsfail-html',
                      'config system replacemsg utm outbreak-prevention-html',
                      'config system replacemsg utm outbreak-prevention-text',
                      'config system replacemsg utm transfer-av-fail-text',
                      'config system replacemsg utm transfer-size-text',
                      'config system replacemsg utm virus-html',
                      'config system replacemsg utm virus-text',
                      'config system replacemsg utm waf-html',
                      'config system replacemsg webproxy deny',
                      'config system replacemsg webproxy user-limit',
                      'config system replacemsg webproxy auth-challenge',
                      'config system replacemsg webproxy auth-login-fail',
                      'config system replacemsg webproxy auth-group-info-fail',
                      'config system replacemsg webproxy auth-ip-blackout',
                      'config system replacemsg webproxy auth-authorization-fail',
                      'config system replacemsg webproxy http-err',
                      }
    fg_config_file = os.path.join(path, config_file)

    config_fortigate = {}
    with open(fg_config_file, "r") as fh:
        config_block = []
        for line in fh:
            if line.startswith('#'):
                continue
            x = line.rstrip('\n').replace('" "', ',').replace('"', '')
            if x.startswith('config'):
                key = x
                config_block = []
                continue
            if x == 'end':
                config_fortigate[key] = config_block
                config_block = []
                continue
            config_block.append(x)

    for item in bad_cert_block:
        config_fortigate.pop(item, None)

# Это оставлено для тестирования.
#    with open(os.path.join(path, 'tmp_fort.json'), 'w') as fh:
#        json.dump(config_fortigate, fh, indent=4, ensure_ascii=False)

    for key, value in config_fortigate.items():
        content = [x.strip().split() for x in value]
        if content:
            config_fortigate[key] = make_conf_block(content)

    json_file = os.path.join(path, 'config.json')
    with open(json_file, 'w') as fh:
        json.dump(config_fortigate, fh, indent=4, ensure_ascii=False)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка экспорта конфигурации Fortigate в формат json.')
    else:
        parent.stepChanged.emit(f'GREEN|    Конфигурация Fortigate в формате json выгружена в файл "{json_file}".')


def make_conf_block(content):
    block = {}
    while len(content):
        x = content.pop(0)
        if not x:
            continue
        match x[0]:
            case 'set':
                block[x[1]] = ' '.join(x[2:])
            case 'edit':
                n = 1
                edit_key = ' '.join(x[1:])
                edit_block = {}
                while n:
                    y = content.pop(0)
                    if not y:
                        continue
                    match y[0]:
                        case 'set':
                            edit_block[y[1]] = ' '.join(y[2:])
                        case 'next':
                            n -= 1
                        case 'config':
                            cn = 1
                            conf_key = ' '.join(y[1:])
                            conf_block = []
                            while cn:
                                z = content.pop(0)
                                match z[0]:
                                    case 'config':
                                        cn += 1
                                    case 'end':
                                        cn -= 1
                                conf_block.append(z)
                            edit_block[conf_key] = make_conf_block(conf_block)
                block[edit_key] = edit_block
            case 'config':
                cn = 1
                conf_key = ' '.join(x[1:])
                conf_block = []
                while cn:
                    z = content.pop(0)
                    match z[0]:
                        case 'config':
                            cn += 1
                        case 'end':
                            cn -= 1
                    conf_block.append(z)
                block[conf_key] = make_conf_block(conf_block)
    return block


def convert_ntp_settings(parent, path, data):
    """Конвертируем настройки NTP"""
    parent.stepChanged.emit('BLUE|Конвертация настроек NTP.')

    if 'config system ntp' in data and data['config system ntp'].get('ntpserver', None):
        ntp_info = data['config system ntp']
        section_path = os.path.join(path, 'UserGate')
        current_path = os.path.join(section_path, 'GeneralSettings')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

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
            parent.stepChanged.emit(f'GREEN|    Настройки NTP выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')


def convert_dns_servers(parent, path, data):
    """Заполняем список системных DNS"""
    parent.stepChanged.emit('BLUE|Конвертация настроек DNS.')
    dns_servers = []
    dns_rules = []

    if 'config system dns' in data:
        for key, value in data['config system dns'].items():
            if key in {'primary', 'secondary'}:
                if value and value != '0.0.0.0':
                    dns_servers.append({'dns': value, 'is_bad': False})

    """Создаём правило DNS прокси Сеть->DNS->DNS-прокси->Правила DNS"""
    if 'config user domain-controller' in data:
        for key, value in data['config user domain-controller'].items():
            dns_rules.append({
                'name': key,
                'description': 'Портировано с Fortigate',
                'enabled': True,
                'domains': [f'*.{value["domain-name"]}'],
                'dns_servers': [value['ip-address']],
            })

    if dns_servers or dns_rules:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'DNS')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        if dns_servers:
            json_file = os.path.join(current_path, 'config_dns_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".')
        if dns_rules:
            json_file = os.path.join(current_path, 'config_dns_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(dns_rules, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Правила DNS в DNS-прокси выгружены в файл "{json_file}".')
        parent.stepChanged.emit('GREEN|    Настройки DNS конвертированы.')
    else:
        parent.stepChanged.emit(f'GRAY|    Нет настроек DNS для экспорта.')


def convert_vpn_interfaces(parent, path, interfaces):
    """Конвертируем интерфейсы VLAN."""
    parent.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')

    ifaces = []
    for ifname, ifblock in interfaces.items():
        if 'role' in ifblock:
            parent.zones.add(ifblock['role'])
        if 'vlanid' in ifblock:
            iface = {
                'name': ifname,
                'kind': 'vlan',
                'enabled': False if ifblock.get('status', 'up') == 'down' else True,
                'description': f'Портировано с Fortigate.\n{ifname} {ifblock.get("description", "")}',
                'zone_id': ifblock.get('role', 0),
                'master': False,
                'netflow_profile': 'undefined',
                'lldp_profile': 'undefined',
                'ipv4': [],
                'ifalias': ifblock.get('alias', ''),
                'flow_control': False,
                'mode': 'manual',
                'mtu': 1500,
                'tap': False,
                'dhcp_relay': {
                    'enabled': False,
                    'host_ipv4': '',
                    'servers': []
                },
                'vlan_id': int(ifblock.get('vlanid', 0)),
                'link': ifblock.get('interface', '')
            }
            if ('ip' in ifblock and ifblock['ip']):
                ip, mask = ifblock['ip'].split(' ')
                iface['ipv4'] = [func.pack_ip_address(ip, mask)]
                iface['mode'] = 'static'
            ifaces.append(iface)

    if ifaces:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Interfaces')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_interfaces.json')
        with open(json_file, 'w') as fh:
            json.dump(ifaces, fh, indent=4, ensure_ascii=False)

        parent.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')


def convert_zone_settings(parent, path, data):
    """Конвертируем зоны"""
    parent.stepChanged.emit('BLUE|Конвертация Зон.')
    new_zone = {
        'name': '',
        'description': '',
        'dos_profiles': [
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
    }

    zones = []
    if parent.zones:
        for zone_name in parent.zones:
            new_zone['name'] = zone_name
            new_zone['description'] = 'Портировано с Fortigate.'
            zones.append(copy.deepcopy(new_zone))
    if 'config system zone' in data:
        for key, value in data.get('config system zone', {}).items():
            zone_name = func.get_restricted_name(key)
            parent.zones.add(zone_name)
            new_zone['name'] = zone_name
            new_zone['description'] = f'Портировано с Fortigate.\n{value.get("comment", "")}.'
            zones.append(copy.deepcopy(new_zone))
        
    if zones:
        section_path = os.path.join(path, 'Network')
        current_path = os.path.join(section_path, 'Zones')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_zones.json')
        with open(json_file, 'w') as fh:
            json.dump(zones, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки зон выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет зон для экспорта.')


def convert_dhcp_settings(parent, path, data):
    """Конвертируем настройки DHCP"""
    if 'config system dhcp server' in data:
        parent.stepChanged.emit('BLUE|Конвертация настроек DHCP.')

        dhcp_subnets = []
        for key, item in data['config system dhcp server'].items():
            dhcp = {
                'name': f'{item["interface"]}-{key}',
                'enabled': False,
                'description': 'Портировано с Fortigate.',
                'start_ip': '',
                'end_ip': '',
                'lease_time': item.get('lease-time', 3600),
                'domain': 'example.com',
                'gateway': item.get('default-gateway', '10.10.10.10'),
                'boot_filename':  '',
                'boot_server_ip': '',
                'iface_id': 'port0',
                'netmask': item.get('netmask', '255.255.255.0'),
                'nameservers': [],
                'ignored_macs': [],
                'hosts': [],
                'options': []
            }
            for value in item['ip-range'].values():
                dhcp['start_ip'] = value['start-ip']
                dhcp['end_ip'] = value['end-ip']
                break
            dhcp_subnets.append(dhcp)

        if dhcp_subnets:
            section_path = os.path.join(path, 'Network')
            current_path = os.path.join(section_path, 'DHCP')
            err, msg = func.create_dir(current_path, delete='no')
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            json_file = os.path.join(current_path, 'config_dhcp_subnets.json')
            with open(json_file, 'w') as fh:
                json.dump(dhcp_subnets, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
            parent.stepChanged.emit('LBLUE|    После импорта DHCP в каждом правиле укажите домен, сервера DNS и необходимые DHCP опции.')
        else:
            parent.stepChanged.emit('GRAY|    Нет настроек DHCP для экспорта.')


def convert_notification_profile(parent, path, data):
    """Конвертируем почтовый адрес и профиль оповещения"""
    if 'config system email-server' in data:
        parent.stepChanged.emit('BLUE|Конвертация почтового адреса и профиля оповещения.')
        section_path = os.path.join(path, 'Libraries')

        email_info = data['config system email-server']
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
                'description': 'Портировано с Fortigate',
                'host': email_info['server'],
                'port': int(email_info.get('port', 25)),
                'security': 'ssl' if ('security' in email_info and email_info['security'] == 'smtps') else 'none',
                'authentication': False,
                'login': 'example',
                'password': ''
            }]

            json_file = os.path.join(current_path, 'config_notification_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(notification, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Профиль оповещения SMTP выгружен в файл "{json_file}".')
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
                'description': 'Портировано с Fortigate',
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
            parent.stepChanged.emit(f'GREEN|    Почтовый адрес выгружен в группу почтовых адресов "System email-server" в файле "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет почтового адреса для экспорта.')


def convert_any_service(proto, name):
    """Конвертируем objects не имеющие портов в список сервисов"""
    service = {
        'name': name,
        'description': f'Портировано с Fortigate.\n{name} packet',
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
    services = {}

    if 'config system session-helper' in data:
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
                    'description': 'Портировано с Fortigate.',
                    'protocols': [protocol]
                }

    services_proto = {'110': 'pop3', '995': 'pop3s', '25': 'smtp', '465': 'smtps'}

    for key, value in data.get('config firewall service custom', {}).items():
        protocols = []
        if 'tcp-portrange' in value:
            for port in value['tcp-portrange'].replace(':', ' ').strip().split():
                try:
                    aa = [int(x) for x in port.split('-')]
                except ValueError as err:
                    parent.stepChanged.emit(f'bRED|    Сервис {key} содержит не допустмое значение прорта: "{port}".')
                    continue
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
                try:
                    aa = [int(x) for x in port.split('-')]
                except ValueError as err:
                    parent.stepChanged.emit(f'bRED|    Сервис {key} содержит не допустмое значение прорта: "{port}".')
                    continue
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

        service_name = func.get_restricted_name(key.strip())
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
                        'description': f"Портировано с Fortigate.\n{value['comment'] if 'comment' in value else value.get('category', '')}",
                        'protocols': protocols
                    }
    if services:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'Services')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
        parent.services = services

        parent.stepChanged.emit(f'GREEN|    Сервисы выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет сетевых сервисов для экспорта.')


def convert_service_groups(parent, path, data):
    """Конвертируем группы сервисов"""
    if 'config firewall service group' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация групп сервисов.')
    services_groups = []

    for key, value in data['config firewall service group'].items():
        srv_group = {
            'name': func.get_restricted_name(key.strip()),
            'description': f'Портировано с Fortigate.\n{value.get("comment", "")}.',
            'type': 'servicegroup',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {},
            'content': []
        }
        for item in value['member'].split(','):
            service = copy.deepcopy(parent.services.get(item, None))
            if service:
                for x in service['protocols']:
                    x.pop('source_port', None)
                    x.pop('app_proto', None)
                    x.pop('alg', None)
                srv_group['content'].append(service)

        services_groups.append(srv_group)
        parent.service_groups.add(key)

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

    n = 0
    file_names = set()
    for list_name, value in data.get('config firewall address', {}).items():
        ip_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        if 'subnet' in value:
            ip, mask = value['subnet'].split()
            try:
                subnet = ipaddress.ip_network(f'{ip}/{mask}')
            except ValueError:
                subnet = ipaddress.ip_network(f'{ip}/32')
            ip_list['content'] = [{'value': f'{ip}/{subnet.prefixlen}'}]
        elif 'type' in value and value['type'] == 'iprange':
            ip_list['content'] = [{'value': f'{value.get("start-ip", "0.0.0.1")}-{value.get("end-ip", "255.255.255.255")}'}]
        else:
            continue

        if ip_list['content']:
            n += 1
            parent.ip_lists.add(ip_list['name'])

            file_name = ip_list['name'].translate(trans_filename)
#            if file_name in file_names:
            while file_name in file_names:
                file_name = f'{file_name}-2'
            file_names.add(file_name)

            json_file = os.path.join(current_path, f'{file_name}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|       {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)

    for list_name, value in data.get('config firewall multicast-address', {}).items():
        ip_list = {
            'name': 'Multicast - ' + func.get_restricted_name(list_name),
            'description': 'Портировано с Fortigate.',
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        if value["start-ip"] == value["end-ip"]:
            ip_list['content'] = [{'value': value["start-ip"]}]
        else:
            ip_list['content'] = [{'value': f'{value["start-ip"]}-{value["end-ip"]}'}]

        if ip_list['content']:
            parent.ip_lists.add(ip_list['name'])
            n += 1

            json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|       {n} - Список ip-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)

    for list_name, value in data.get('config firewall addrgrp', {}).items():
        ip_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        for item in value['member'].split(','):
            item = func.get_restricted_name(item)
            if item in parent.ip_lists:
                ip_list['content'].append({'list': item})
            elif item in parent.url_lists:
                continue
            else:
                try:
                    ipaddress.ip_address(item)   # проверяем что это IP-адрес или получаем ValueError
                    ip_list['content'].append({'value': item})
                except ValueError:
                    parent.stepChanged.emit(f'bRED|    Для списка "{list_name}" не найден список ip-адресов "{item}". Такого списка нет в списках IP-адресов.')

        if ip_list['content']:
            parent.ip_lists.add(ip_list['name'])
            n += 1

            json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       {n} - Список ip-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)

    parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


def convert_virtual_ip(parent, path, data):
    """Конвертируем object 'config firewall vip' в IP-лист"""
    if 'config firewall vip' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация firewall virtual IP.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    for list_name, value in data['config firewall vip'].items():
        ip_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': [{'value': value['extip']}]
        }
        parent.ip_lists.add(ip_list['name'])
 
        json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(ip_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Создан список IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')
        time.sleep(0.1)

    parent.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


def convert_groups_iplists(parent, path, data):
    """Конвертируем object 'config firewall vipgrp' в список ip-адресов"""
    if 'config firewall vipgrp' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация списков групп ip-адресов.')
    section_path = os.path.join(path, 'Libraries')
    current_path = os.path.join(section_path, 'IPAddresses')
    err, msg = func.create_dir(current_path, delete='no')
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    for list_name, value in data['config firewall vipgrp'].items():
        ip_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'network',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
            'content': []
        }
        for item in value['member'].split(','):
            item = func.get_restricted_name(item)
            if item in parent.ip_lists:
                ip_list['content'].append({'list': item})
            else:
                try:
                    ipaddress.ip_address(item)   # проверяем что это IP-адрес или получаем ValueError
                    ip_list['content'].append({'value': item})
                except ValueError:
                    print('ERROR convert_groups_iplists - ', item)
#                    pass
        if ip_list['content']:
            parent.ip_lists.add(ip_list['name'])
 
            json_file = os.path.join(current_path, f'{ip_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Создан список групп IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')
            time.sleep(0.1)

    parent.stepChanged.emit(f'GREEN|    Списки групп IP-адресов выгружены в каталог "{current_path}".')


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

    n = 0
    for key, value in data.get('config wanopt content-delivery-network-rule', {}).items():
        _, pattern = key.split(':')
        if pattern == '//':
            list_name = 'All URLs (default)'
        else:
            list_name = pattern.replace('/', '')

        url_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': []
        }
        if 'host-domain-name-suffix' not in value and list_name != 'All URLs (default)':
            parent.stepChanged.emit(f'rNOTE|       Запись "{key}" не конвертирована так как не имеет host-domain-name-suffix.')
            continue

        suffixes = work_with_rules(value['rules']) if 'rules' in value else []

        url_list['content'] = []
        for domain_name in value.get('host-domain-name-suffix', '').split(','):
            if suffixes:
                url_list['content'].extend([{'value': f'{domain_name}/{x}' if domain_name else x} for x in suffixes])
            else:
                url_list['content'].extend([{'value': domain_name}])

        if url_list['content']:
            n += 1
            parent.url_lists[url_list['name']] = url_list['content']

            json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)

    for list_name, value in data.get('config firewall address', {}).items():
        if 'type' in value and value['type'] == 'fqdn':
            url_list = {
                'name': func.get_restricted_name(list_name),
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': [{'value': value['fqdn']}]
            }
            if url_list['content']:
                n += 1
                parent.url_lists[url_list['name']] = url_list['content']

                json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                parent.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
                time.sleep(0.01)

    for list_name, value in data.get('config firewall addrgrp', {}).items():
        url_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': []
        }
        for url in value['member'].split(','):
            url = func.get_restricted_name(url)
            if url in parent.url_lists:
                url_list['content'].extend(parent.url_lists[url])

        if url_list['content']:
            n += 1
            parent.url_lists[url_list['name']] = url_list['content']

            json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)

    for list_name, value in data.get('config firewall wildcard-fqdn custom', {}).items():
        url_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': [{'value': value['wildcard-fqdn']}]
        }
        if url_list['name'] in parent.url_lists:
            url_list['name'] = f'{url_list["name"]} - wildcard-fqdn'

        parent.url_lists[url_list['name']] = url_list['content']
        n += 1

        json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
        with open(json_file, 'w') as fh:
            json.dump(url_list, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
        time.sleep(0.01)

    for list_name, value in data.get('config firewall wildcard-fqdn group', {}).items():
        url_list = {
            'name': func.get_restricted_name(list_name),
            'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
            'type': 'url',
            'url': '',
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'list_compile_type': 'case_insensitive'},
            'content': []
        }
        for url in value['member'].split(','):
            url = func.get_restricted_name(url)
            if url in parent.url_lists:
                url_list['content'].extend(parent.url_lists[url])
            wildcard_url_name = f'{url} - wildcard-fqdn'
            if wildcard_url_name in parent.url_lists:
                url_list['content'].extend(parent.url_lists[wildcard_url_name])

        if url_list['content']:
            n += 1
            parent.url_lists[url_list['name']] = url_list['content']

            json_file = os.path.join(current_path, f'{url_list["name"].translate(trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')
            time.sleep(0.01)

    parent.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')


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


def convert_time_sets(parent, path, data):
    """Конвертируем time set (календари)"""
    parent.stepChanged.emit('BLUE|Конвертация календарей.')
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

    if 'config firewall schedule onetime' in data:
        for key, value in data['config firewall schedule onetime'].items():
            if value:
                time_set = {
                    'name': func.get_restricted_name(key),
                    'description': 'Портировано с Fortigate',
                    'type': 'timerestrictiongroup',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {},
                    'content': []
                }
                content = {
                    'name': func.get_restricted_name(key),
#                    'type': 'range',
                    'type': 'span',
                }
                if 'start' in value and 'end' in value:
                    start = value['start'].split()
                    end = value['end'].split()
                    content['time_to'] = end[0]
                    content['time_from'] = start[0]
                    content['fixed_date_to'] = f'{end[1].replace("/", "-")}T00:00:00'
                    content['fixed_date_from'] = f'{start[1].replace("/", "-")}T00:00:00'
                elif 'start' not in value:
                    time_to, fixed_date_to = value['end'].split()
#                    content['type'] = 'span'
                    content['time_to'] = time_to
                    content['fixed_date_to'] = f'{fixed_date_to.replace("/", "-")}T00:00:00'
                elif 'end' not in value:
                    time_from, fixed_date_from = value['start'].split()
#                    content['type'] = 'span'
                    content['time_from'] = time_from
                    content['fixed_date_from'] = f'{fixed_date_from.replace("/", "-")}T00:00:00'
                time_set['content'].append(content)

                timerestrictiongroup.append(time_set)
                parent.time_restrictions.add(key)

    if 'config firewall schedule recurring' in data:
        for key, value in data['config firewall schedule recurring'].items():
            if value:
                schedule = {
                    'name': func.get_restricted_name(key.strip()),
                    'description': 'Портировано с Fortigate',
                    'type': 'timerestrictiongroup',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {},
                    'content': [
                        {
                            'name': func.get_restricted_name(key.strip()),
                            'type': 'weekly',
                            'days': [week[day] for day in value['day'].split()]
                        }
                    ]
                }
                if 'start' in value:
                    schedule['content'][0]['time_from'] = value['start']
                    schedule['content'][0]['time_to'] = value['end']
                timerestrictiongroup.append(schedule)
                parent.time_restrictions.add(key)

    if timerestrictiongroup:
        section_path = os.path.join(path, 'Libraries')
        current_path = os.path.join(section_path, 'TimeSets')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_calendars.json')
        with open(json_file, 'w') as fh:
            json.dump(timerestrictiongroup, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


def convert_shapers_list(parent, path, data):
    """Конвертируем полосы пропускания"""
    parent.stepChanged.emit('BLUE|Конвертация полос пропускания.')
    
    if 'config firewall shaper traffic-shaper' in data:
        shapers = []
        for key, value in data['config firewall shaper traffic-shaper'].items():
            rate = int(value.get('maximum-bandwidth', 'guaranteed-bandwidth'))
            if 'bandwidth-unit' in value:
                if value['bandwidth-unit'] == 'mbps':
                    rate = rate*1024
                if value['bandwidth-unit'] == 'gbps':
                    rate = rate*1024*1024
            shapers.append({
                'name': key,
                'description': 'Портировано с Fortigate.',
                'rate': rate,
                'dscp': 0
            })

        if shapers:
            section_path = os.path.join(path, 'Libraries')
            current_path = os.path.join(section_path, 'BandwidthPools')
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            json_file = os.path.join(current_path, 'config_shaper_list.json')
            with open(json_file, 'w') as fh:
                json.dump(shapers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Полосы пропускания выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')


def convert_shapers_rules(parent, path, data):
    """Конвертируем правила пропускной способности"""
    parent.stepChanged.emit('BLUE|Конвертация правил пропускной способности.')
    
    if 'config firewall shaping-policy' in data:
        shaping_rules = []
        for key, value in data['config firewall shaping-policy'].items():
            rule = {
                'name': '',
                'description': f'Портировано с Fortigate.\n{value.get("comments", "")}',
                'scenario_rule_id': False,
                'src_zones': [],
                'dst_zones': [],
                'src_ips': [],
                'dst_ips': [],
                'users': [],
                'services': [],
                'apps': [],
                'pool': '',
                'enabled': True,
                'time_restrictions': [],
                'limit': True,
                'limit_value': '3/h',
                'limit_bust': 5,
                'log': False,
                'log_session_start': False,
                'src_zones_negate': False,
                'dst_zones_negate': False,
                'src_ips_negate': False,
                'dst_ips_negate': False,
                'services_negate': False,
                'apps_negate': False,
                'rule_error': 0
            }
            if 'name' not in value or not value['name'] or value['name'].isspace():
                rule_name = str(uuid.uuid4()).split('-')[4]
            else:
                rule_name = f'{key}-{value["name"]}'

            if value.get('traffic-shaper', None):
                rule['name'] = rule_name
                rule['pool'] = value['traffic-shaper']
                get_ips(parent, path, value.get('srcaddr', ''), value.get('dstaddr', ''), rule)
                get_services(parent, value.get('service', ''), rule)

                if rule['rule_error']:
                    rule['name'] = f'ERROR - {rule["name"]}'
                    rule['enabled'] = False
                rule.pop('rule_error', None)
                shaping_rules.append(copy.deepcopy(rule))

            if value.get('traffic-shaper-reverse', None):
                rule['name'] = f'{rule_name} (Reverse)'
                rule['rule_error'] = 0
                rule['pool'] = value['traffic-shaper-reverse']
                get_ips(parent, path, value.get('dstaddr', ''), value.get('srcaddr', ''), rule)
                get_services(parent, value.get('service', ''), rule)

                if rule['rule_error']:
                    rule['name'] = f'ERROR - {rule["name"]}'
                    rule['enabled'] = False
                rule.pop('rule_error', None)
                shaping_rules.append(copy.deepcopy(rule))

        if shaping_rules:
            section_path = os.path.join(path, 'NetworkPolicies')
            current_path = os.path.join(section_path, 'TrafficShaping')
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            json_file = os.path.join(current_path, 'config_shaper_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(shaping_rules, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')


def convert_auth_servers(parent, path, data):
    """Конвертируем сервера авторизации"""
    parent.stepChanged.emit('BLUE|Конвертация серверов аутентификации.')
    ldap_servers = []
    radius_servers = []

    if 'config user ldap' in data:
        for key, value in data['config user ldap'].items():
            if value['dn']:
                tmp_dn1 = [x.split('=') for x in value['dn'].split(',')]
                tmp_dn2 = [b for a, b in tmp_dn1 if a in ['dc', 'DC']]
                dn = '.'.join(tmp_dn2)
            ldap_servers.append({
                'name': f'{func.get_restricted_name(key.strip())} - AD Auth server',
                'description': 'LDAP-коннектор импортирован с Fortigate.',
                'enabled': False,
                'ssl': True if value.get('secure', False) == 'ldaps' else False,
                'address': value['server'],
                'bind_dn': value['username'].replace('\\', '', 1),
                'password': '',
                'domains': [dn],
                'roots': [value['dn']] if value['dn'] else [],
                'keytab_exists': False
            })

    if 'config user radius' in data:
        for key, value in data['config user radius'].items():
            radius_servers.append({
                'name': f'{func.get_restricted_name(key.strip())} - Radius Auth server',
                'description': 'Radius auth server импортирован с Fortigate.',
                'enabled': False,
                'addresses': [
                    {'host': value['server'], 'port': 1812}
                ]
            })
            parent.local_users[key] = {
                'name': key,
                'enabled': True,
                'auth_login': key.strip().translate(trans_userlogin),
                'is_ldap': False,
                'static_ip_addresses': [],
                'ldap_dn': '',
                'emails': [],
                'phones': [],
                'first_name': '',
                'last_name': '',
                'groups': [],
            }

    if ldap_servers or radius_servers:
        section_path = os.path.join(path, 'UsersAndDevices')
        current_path = os.path.join(section_path, 'AuthServers')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        if ldap_servers:
            json_file = os.path.join(current_path, 'config_ldap_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации LDAP выгружены в файл "{json_file}".')
        if radius_servers:
            json_file = os.path.join(current_path, 'config_radius_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации RADIUS выгружены в файл "{json_file}".')

        parent.stepChanged.emit(f'GREEN|    Настройки серверов аутентификации конвертированы.')
    else:
        parent.stepChanged.emit('GRAY|    Нет серверов аутентификации для экспорта.')


def convert_local_users(parent, path, data):
    """Конвертируем локальных пользователей"""
    if 'config user local' in data:
        parent.stepChanged.emit('BLUE|Конвертация локальных пользователей.')
        section_path = os.path.join(path, 'UsersAndDevices')
        current_path = os.path.join(section_path, 'Users')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        for key, value in data['config user local'].items():
            if value['type'] == 'password':
                parent.local_users[key] = {
                    'name': key,
                    'enabled': False if value.get('status', None) == 'disable' else True,
                    'auth_login': key.strip().translate(trans_userlogin),
                    'is_ldap': False,
                    'static_ip_addresses': [],
                    'ldap_dn': '',
                    'emails': [value['email-to']] if value.get('email-to', None) else [],
                    'phones': [],
                    'first_name': '',
                    'last_name': '',
                    'groups': [],
                }

        for key, value in data['config user group'].items():
            users_in_group = [x for x in value['member'].split(',') if x in parent.local_users] if 'member' in value else []
            for user in users_in_group:
                parent.local_users[user]['groups'].append(key)

        json_file = os.path.join(current_path, 'config_users.json')
        with open(json_file, 'w') as fh:
            json.dump([x for x in parent.local_users.values()], fh, indent=4, ensure_ascii=False)

        out_message = f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".'
        parent.stepChanged.emit('GRAY|    Нет локальных пользователей для экспорта.' if not parent.local_users else out_message)


def convert_user_groups(parent, path, data):
    """Конвертируем локальные группы пользователей"""
    if 'config user group' in data:
        parent.stepChanged.emit('BLUE|Конвертация локальных групп пользователей.')
        section_path = os.path.join(path, 'UsersAndDevices')
        current_path = os.path.join(section_path, 'Groups')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        groups = []
        for key, value in data['config user group'].items():
            groups.append({
                'name': key,
                'description': 'Портировано с Fortigate.',
                'is_ldap': False,
                'is_transient': False,
                'users': [x for x in value['member'].split(',') if x in parent.local_users] if 'member' in value else []
            })
            parent.local_groups.add(key)

        json_file = os.path.join(current_path, 'config_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(groups, fh, indent=4, ensure_ascii=False)

        out_message = f'GREEN|    Список локальных групп пользователей выгружен в файл "{json_file}".'
        parent.stepChanged.emit('GRAY|    Нет локальных групп пользователей для экспорта.' if not groups else out_message)


def convert_web_portal_resources(parent, path, data):
    """Конвертируем ресурсы веб-портала"""
    if 'config vpn ssl web user-bookmark' in data:
        parent.stepChanged.emit('BLUE|Конвертация ресурсов веб-портала.')
        section_path = os.path.join(path, 'GlobalPortal')
        current_path = os.path.join(section_path, 'WebPortal')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        resources = []
        for key, value in data['config vpn ssl web user-bookmark'].items():
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
                            'description': 'Портировано с Fortigate',
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


def convert_dnat_rule(parent, path, data):
    """Конвертируем object 'config firewall vip' в правила DNAT или Port-форвардинга"""
    if 'config firewall vip' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация правил DNAT/Порт-форвардинга.')

    rules = []
    ips_for_rules = set()
    for key, value in data['config firewall vip'].items():
        if value and 'type' not in value:
            if 'mappedip' in value:
                services = []
                port_mappings = []
                if value['extip'] in ips_for_rules:
                    list_id = value['extip']
                else:
                    list_id = func.create_ip_list(parent, path, ips=[value['extip']], name=value['extip'])
                    ips_for_rules.add(list_id)
                if value['mappedip'] not in ips_for_rules:
                    ips_for_rules.add(func.create_ip_list(parent, path, ips=[value['mappedip']]))
                if 'service' in value:
                    services = [['service' if x in parent.services else 'list_id', x] for x in value['service'].split()]
                elif 'mappedport' in value:
                    try:
                        port_mappings = [{
                            'proto': value['protocol'] if 'protocol' in value else 'tcp',
                            'src_port': int(value['extport']),
                            'dst_port': int(value['mappedport'])
                        }]
                    except ValueError:
                        port_mappings = []
                rule = {
                    'name': f'Rule {func.get_restricted_name(key)}',
                    'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                    'action': 'port_mapping' if port_mappings else 'dnat',
                    'position': 'last',
                    'zone_in': get_zones(parent, value.get('extintf', '')),
                    'zone_out': [],
                    'source_ip': [],
                    'dest_ip': [['list_id', list_id]],
                    'service': services,
                    'target_ip': value['mappedip'],
                    'gateway': '',
                    'enabled': True,
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
                time.sleep(0.01)
    parent.ip_lists.update(ips_for_rules)

    if rules:
        section_path = os.path.join(path, 'NetworkPolicies')
        current_path = os.path.join(section_path, 'NATandRouting')
        err, msg = func.create_dir(current_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_nat_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Павила DNAT/Порт-форвардинга выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил DNAT/Порт-форвардинга для экспорта.')


def convert_loadbalancing_rule(parent, path, data):
    """Конвертируем object 'config firewall vip' в правила балансировки нагрузки"""
    if 'config firewall vip' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация правил балансировки нагрузки.')

    rules = []
    ssl_certificate = False
    for key, value in data['config firewall vip'].items():
        if value and value.get('type', None) == 'server-load-balance':
            if 'ssl-certificate' in value:
                ssl_certificate = True
            hosts = []
            ip_list_ips = []
            for server in value['realservers'].values():
                hosts.append({
                    'ip_address': server['ip'],
                    'port': int(server['port']),
                    'weight': 50,
                    'mode': 'masq',
                    'snat': True
                })
                ip_list_ips.append(server['ip'])
            parent.ip_lists.add(func.create_ip_list(parent, path, ips=ip_list_ips, name=key))

            rule = {
                'name': f'Rule {func.get_restricted_name(key.strip())}',
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
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
                'src_zones': get_zones(parent, value.get('extintf', '')),
                'src_zones_nagate': False,
                'src_ips': [],
                'src_ips_nagate': False
            }
            rules.append(rule)
            parent.stepChanged.emit(f'BLACK|    Создано правило балансировки нагрузки "{rule["name"]}".')
            time.sleep(0.01)

    if rules:
        section_path = os.path.join(path, 'NetworkPolicies')
        current_path = os.path.join(section_path, 'LoadBalancing')
        err, msg = func.create_dir(current_path, delete='no')
        if err:
            parent.stepChanged.emit(f'RED|    {msg}.')
            parent.error = 1
            return

        json_file = os.path.join(current_path, 'config_loadbalancing_tcpudp.json')
        with open(json_file, 'w') as fh:
            json.dump(rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Павила балансировки нагрузки выгружены в файл "{json_file}".')

        if ssl_certificate:
            parent.stepChanged.emit(f'LBLUE|    В правилах Fortigate использовались сертификаты, после импорта конфигурации удалите соответсвующие правила балансировки нагрузки и')
            parent.stepChanged.emit(f'LBLUE|    создайте правила reverse-прокси, предварительно загрузив необходимые сертификаты.')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил балансировки нагрузки для экспорта.')


def convert_firewall_policy(parent, path, data):
    """Конвертируем object 'config firewall policy' в правила МЭ"""
    if 'config firewall policy' not in data:
        return
    parent.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
    parent.stepChanged.emit(f'LBLUE|    После импорта правил МЭ, необходимо в каждом правиле указать зону источника и зону назначения.')
    parent.stepChanged.emit(f'LBLUE|    Создайте необходимое количество зон и присвойте зону каждому интерфейсу.')
    section_path = os.path.join(path, 'NetworkPolicies')
    current_path = os.path.join(section_path, 'Firewall')
    err, msg = func.create_dir(current_path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}.')
        parent.error = 1
        return

    n = 0
    rules = []
    for key, value in data['config firewall policy'].items():
        rule = {
            'name': func.get_restricted_name(value.get("name", key)),
            'description': f"Портировано с Fortigate.\nFortigate UUID: {value.get('uuid', 'Отсутствует')}\n{value.get('comments', '')}",
            'action': value['action'] if value.get('action', None) else 'drop',
            'position': 'last',
            'scenario_rule_id': False,     # При импорте заменяется на UID или "0". 
            'src_zones': get_zones(parent, value.get('srcintf', '')),
            'dst_zones': get_zones(parent, value.get('dstintf', '')),
            'src_ips': [],
            'dst_ips': [],
            'services': [],
            'apps': [],
            'users': [],
            'enabled': False if ('status' in value and value['status'] == 'disable') else True,
            'limit': True,
            'limit_value': '3/h',
            'limit_burst': 5,
            'log': True if 'logtraffic' in value else False,
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
            'rule_error': 0,
        }
        if 'groups' in value:
            get_users_and_groups(parent, value['groups'], rule)
        elif 'users' in value:
            get_users_and_groups(parent, value['users'], rule)
        if 'fsso-groups' in value:
            domain = []
            group_name = ''
            for item in [x.split('=') for x in value['fsso-groups'].split(',')]:
                if item[0].upper() == 'CN':
                    group_name = item[1]
                elif item[0].upper() == 'DC':
                    domain.append(item[1])
            rule['users'].append(['group', f"{'.'.join(domain)}\\{group_name}"])
        get_ips(parent, path, value.get('srcaddr', ''), value.get('dstaddr', ''), rule)
        get_services(parent, value.get('service', ''), rule)
        get_time_restrictions(parent, value['schedule'], rule)
        if rule['rule_error']:
            rule['name'] = f'ERROR - {rule["name"]}'
            rule['enabled'] = False
        else:
            rule['name'] = f'Rule - {rule["name"]}'
        rule.pop('rule_error', None)
        rules.append(rule)
        n += 1
        parent.stepChanged.emit(f'BLACK|    {n} - Создано правило МЭ "{rule["name"]}".')
        time.sleep(0.01)

    if rules:
        json_file = os.path.join(current_path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(rules, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Павила межсетевого экрана выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


def convert_gateways_list(parent, path, data):
    """Конвертируем список шлюзов"""
    parent.stepChanged.emit('BLUE|Конвертация списка шлюзов.')

    if 'config router static' in data:
        gateways = set()
        list_gateways = []
        for value in data['config router static'].values():
            if 'dst' not in value and 'gateway' in value:
                if value['gateway'] not in gateways:
                    list_gateways.append({
                        'name': value['gateway'],
                        'enabled': True,
                        'description': 'Портировано с Fortigate.',
                        'ipv4': value['gateway'],
                        'vrf': 'default',
                        'weight': int(value.get('distance', 1)),
                        'multigate': False,
                        'default': False,
                        'iface': 'undefined',
                        'is_automatic': False
                    })
                    gateways.add(value['gateway'])

        if list_gateways:
            section_path = os.path.join(path, 'Network')
            current_path = os.path.join(section_path, 'Gateways')
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            json_file = os.path.join(current_path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(list_gateways, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет списка шлюзов для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет списка шлюзов для экспорта.')


def convert_static_routes(parent, path, data):
    """Конвертируем статические маршруты в VRF по умолчанию"""
    parent.stepChanged.emit('BLUE|Конвертация статических маршрутов в VRF по умолчанию.')
    if 'config router static' in data:
        for value in data['config router static'].values():
            if 'dst' in value and 'gateway' in value:
                dst_network = func.pack_ip_address(*value['dst'].split())
                route = {
                    'name': f'Route for {dst_network}',
                    'description': 'Портировано с Fortigate.',
                    'enabled': False if value.get('status', None) == 'disable' else True,
                    'dest': dst_network,
                    'gateway': value['gateway'],
                    'ifname': 'undefined',
                    'kind': 'unicast',
                    'metric': int(value.get('distance', 1))
                }
                parent.vrf['routes'].append(route)

        if parent.vrf['routes']:
            section_path = os.path.join(path, 'Network')
            current_path = os.path.join(section_path, 'VRF')
            err, msg = func.create_dir(current_path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([parent.vrf], fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')
    else:
        parent.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


def convert_bgp_routes(parent, path, data):
    """Конвертируем настройки BGP в VRF по умолчанию"""
    parent.stepChanged.emit('BLUE|Конвертация настроек BGP в VRF по умолчанию.')
    filters = []
    filter_keys = {}
    filter_keys['empty'] = []
    routemaps = []
    routemaps_keys = {}
    routemaps_keys['empty'] = []

    if 'config router prefix-list' in data:
        for key, value in data['config router prefix-list'].items():
            filter_keys[key] = []
            filter_items_permit = []
            filter_items_deny = []
            for item in value['rule'].values():
                prefix = func.pack_ip_address(*item['prefix'].split())
                if 'le' in item:
                    prefix = f'{prefix}:{item.get("ge", "")}:{item["le"]}'
                if item.get('action', None) == 'deny':
                    filter_items_deny.append(prefix)
                else:
                    filter_items_permit.append(prefix)
            if filter_items_permit:
                filter_name = f'{key} (permit)'
                filters.append({
                    'name': filter_name,
                    'description': '',
                    'action': 'permit',
                    'filter_by': 'ip',
                    'filter_items': filter_items_permit
                })
                filter_keys[key].append(filter_name)
            if filter_items_deny:
                filter_name = f'{key} (deny)'
                filters.append({
                    'name': filter_name,
                    'description': '',
                    'action': 'deny',
                    'filter_by': 'ip',
                    'filter_items': filter_items_deny
                })
                filter_keys[key].append(filter_name)
    if 'config router route-map' in data:
        for key, value in data['config router route-map'].items():
            routemaps_keys[key] = []
            action = None
            for item in value['rule'].values():
                action = 'permit' if item.get('match-ip-address', None) == 'allow' else 'deny'
            if action:
                routemaps.append({
                    'name': key,
                    'description': '',
                    'action': action,
                    'match_by': 'ip',
                    'next_hop': '',
                    'metric': 10,
                    'weight': 10,
                    'preference': 10,
                    'as_prepend': '',
                    'community': '',
                    'additive': False,
                    'match_items': []
                })
                routemaps_keys[key].append(key)

    bgp = data['config router bgp']
    if 'router-id' in bgp:
        neighbors = []
        try:
            if 'neighbor' in bgp:
                for key, value in bgp['neighbor'].items():
                    neighbors.append({
                        'enabled': True,
                        'description': '',
                        'host': key,
                        'remote_asn': int(value['remote-as']),
                        'weight': 10,
                        'next_hop_self': False,
                        'ebgp_multihop': False,
                        'route_reflector_client': True if value.get('route-reflector-client', None) == 'enable' else False,
                        'multihop_ttl': 10,
                        'soft_reconfiguration': False,
                        'default_originate': False,
                        'send_community': False,
                        'password': False,
                        'filter_in': filter_keys[value.get('prefix-list-in', 'empty')],
                        'filter_out': filter_keys[value.get('prefix-list-out', 'empty')],
                        'routemap_in': routemaps_keys[value.get('route-map-in', 'empty')],
                        'routemap_out': routemaps_keys[value.get('route-map-out', 'empty')],
                        'allowas_in': False,
                        'allowas_in_number': 3,
                        'bfd_profile': -1
                    })
            elif 'neighbor-range' in bgp:
                for item in bgp['neighbor-range'].values():
                    neighbor_group = bgp['neighbor-group'][item['neighbor-group']]
                    neighbors.append({
                        'enabled': True,
                        'description': neighbor_group.get('description', ''),
                        'host': item['prefix'].split()[0],
                        'remote_asn': int(neighbor_group['remote-as']),
                        'weight': int(neighbor_group.get('weight', 10)),
                        'next_hop_self': True if neighbor_group.get('next-hop-self', False) == 'enable' else False,
                        'ebgp_multihop': True if neighbor_group.get('ebgp-enforce-multihop', False) == 'enable' else False,
                        'route_reflector_client': True if neighbor_group.get('route-reflector-client', None) == 'enable' else False,
                        'multihop_ttl': 10,
                        'soft_reconfiguration': False,
                        'default_originate': False,
                        'send_community': True if neighbor_group.get('send-community', False) == 'standard' else False,
                        'password': False,
                        'filter_in': filter_keys[neighbor_group.get('prefix-list-in', 'empty')],
                        'filter_out': filter_keys[neighbor_group.get('prefix-list-out', 'empty')],
                        'routemap_in': routemaps_keys[neighbor_group.get('route-map-in', 'empty')],
                        'routemap_out': routemaps_keys[neighbor_group.get('route-map-out', 'empty')],
                        'allowas_in': False,
                        'allowas_in_number': 3,
                        'bfd_profile': -1
                    })
            if 'network' in bgp and bgp['network']:
                config_network = [func.pack_ip_address(*x['prefix'].split()) for x in bgp['network'].values()]
            else:
                config_network = []

            parent.vrf['bgp'] = {
                'enabled': False,
                'router_id': bgp['router-id'],
                'as_number': int(bgp['as']),
                'multiple_path': False,
                'redistribute': ['connected'] if bgp['redistribute connected'].get('status', None) == 'enable' else [],
                'networks': config_network,
                'routemaps': routemaps,
                'filters': filters,
                'neighbors': neighbors
            }
        except (KeyError, ValueError) as err:
            parent.stepChanged.emit(f'bRED|    Произошла ошибка при экспорте настроек BGP: {err}.')
        else:
            section_path = os.path.join(path, 'Network')
            current_path = os.path.join(section_path, 'VRF')
            err, msg = func.create_dir(current_path, delete='no')
            if err:
                parent.stepChanged.emit(f'RED|    {msg}.')
                parent.error = 1
                return

            json_file = os.path.join(current_path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump([parent.vrf], fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Настройки BGP выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет настроек BGP для экспорта.')


############################################# Служебные функции ###################################################
def get_ips(parent, path, src_ips, dst_ips, rule):
    """
    Получить имена списков IP-адресов и URL-листов.
    Если списки не найдены, то они создаются или пропускаются, если невозможно создать."""
    if src_ips:
        new_rule_ips = []
        for item in src_ips.split(','):
            if item == 'all':
                continue
            item = func.get_restricted_name(item)
            if item in parent.ip_lists:
                new_rule_ips.append(['list_id', item])
            elif item in parent.url_lists:
                new_rule_ips.append(['urllist_id', item])
            else:
                try:
                    ipaddress.ip_address(item)   # проверяем что это IP-адрес или получаем ValueError
                    new_rule_ips.append(['list_id', func.create_ip_list(parent, path, ips=[item], name=item)])
                except ValueError as err:
                    parent.stepChanged.emit(f'RED|    Error! Не найден src-адрес "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найден src-адрес "{item}".'
                    rule['rule_error'] = 1
        rule['src_ips'] = new_rule_ips
    if dst_ips:
        new_rule_ips = []
        for item in dst_ips.split(','):
            if item == 'all':
                continue
            item = func.get_restricted_name(item)
            if item in parent.ip_lists:
                new_rule_ips.append(['list_id', item])
            elif item in parent.url_lists:
                new_rule_ips.append(['urllist_id', item])
            else:
                try:
                    ipaddress.ip_address(item)   # проверяем что это IP-адрес или получаем ValueError
                    new_rule_ips.append(['list_id', func.create_ip_list(parent, path, ips=[item], name=item)])
                except ValueError as err:
                    parent.stepChanged.emit(f'RED|    Error! Не найден dst-адрес "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                    rule['description'] = f'{rule["description"]}\nError! Не найден dst-адрес "{item}".'
                    rule['rule_error'] = 1
        rule['dst_ips'] = new_rule_ips

def get_services(parent, rule_services, rule):
    """Получить список сервисов"""
    new_service_list = []
    if rule_services:
        for service in rule_services.split(','):
            if service.upper() == 'ALL':
                continue
            if service in parent.services:
                new_service_list.append(['service', ug_services.get(service, service)])
            elif service in parent.service_groups:
                new_service_list.append(['list_id', service])
            else:
                parent.stepChanged.emit(f'RED|    Error! Не найден сервис "{service}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                rule['description'] = f'{rule["description"]}\nError! Не найден сервис "{service}".'
                rule['rule_error'] = 1
        rule['services'] = new_service_list

def get_zones(parent, intf):
    """Получить список зон для правила"""
    new_zones = []
    if intf:
        for item in intf.split(','):
            if item == 'any':
                continue
            item = func.get_restricted_name(item.strip())
            if item in parent.zones:
                new_zones.append(item)
    return new_zones

def get_users_and_groups(parent, users, rule):
    """Получить имена групп и пользователей."""
    new_users_list = []
    for item in users.split(','):
        if item in parent.local_users:
            new_users_list.append(['user', item])
        elif item in parent.local_groups:
            new_users_list.append(['group', item])
        else:
            parent.stepChanged.emit(f'RED|    Error! Не найден локальный пользователь/группа "{item}" для правила "{rule["name"]}".')
            rule['description'] = f'{rule["description"]}\nError! Не найден локальный пользователь/группа "{item}".'
            rule['rule_error'] = 1
    rule['users'] =  new_users_list

def get_time_restrictions(parent, time_restrictions, rule):
    """Получить значение календаря."""
    new_schedule = []
    for item in time_restrictions.split(','):
        if item == 'always':
            continue
        if item in parent.time_restrictions:
            new_schedule.append(item)
        else:
            parent.stepChanged.emit(f'bRED|    Error! Не найден календарь "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
            rule['description'] = f'{rule["description"]}\nError! Не найден календарь "{item}".'
            rule['rule_error'] = 1
    rule['time_restrictions'] = new_schedule


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
