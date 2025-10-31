#!/usr/bin/python3
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
# Модуль преобразования конфигурации с Fortigate в формат UserGate.
# Версия 4.5 31.10.2025
#

import os, sys, json, copy
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import MyConv
from services import zone_services, ug_services, ip_proto, GEOIP_CODE


class ConvertFortigateConfig(QThread, MyConv):
    """Преобразуем файл конфигурации Fortigate в формат UserGate."""
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
        self.stepChanged.emit(f'GREEN|{"Конвертация конфигурации Fortigate в формат UserGate.":>110}')
        self.stepChanged.emit(f'ORANGE|{"="*110}')
        self.convert_config_file()
#        return

        if self.error:
            self.stepChanged.emit('iRED|Конвертация конфигурации Fortigate в формат UserGate прервана.')
        else:
            json_file = os.path.join(self.current_fg_path, 'config.json')
            err, data = self.read_json_file(json_file)
            if err:
                self.stepChanged.emit('iRED|Конвертация конфигурации Fortigate в формат UserGate прервана.\n')
            else:
                self.convert_ntp_settings(data)
                self.convert_dns_servers(data)
                self.convert_zone_settings(data)
                self.convert_vpn_interfaces(data)
                self.convert_dhcp_settings(data)
                self.convert_notification_profile(data)
                self.convert_services(data)
                self.convert_service_groups(data)
                self.convert_url_lists(data)
                self.convert_ip_lists(data)
                self.convert_virtual_ip(data)
                self.convert_groups_iplists(data)
                self.convert_time_sets(data)
                self.convert_shapers_list(data)
                self.convert_shapers_rules(data)
                self.convert_auth_servers(data)
                self.convert_local_users(data)
                self.convert_user_groups(data)
                self.convert_web_portal_resources(data)
                self.convert_dnat_rule(data)
                self.convert_loadbalancing_rule(data)
                self.convert_firewall_policy(data)
                self.convert_gateways_list(data)
                self.convert_static_routes(data)
                self.convert_bgp_routes(data)

                if self.error:
                    self.stepChanged.emit('iORANGE|Конвертация конфигурации Fortigate в формат UserGate прошла с ошибками.\n')
                else:
                    self.stepChanged.emit('iGREEN|Конвертация конфигурации Fortigate в формат UserGate прошла успешно.\n')


    def convert_config_file(self):
        """Преобразуем файл конфигурации Fortigate в формат json."""
        self.stepChanged.emit('BLUE|Конвертация файла конфигурации Fortigate в формат json.')
        if not os.path.isdir(self.current_fg_path):
            self.stepChanged.emit('RED|    Не найден каталог с конфигурацией Fortigate.')
            self.error = 1
            return

        data = {}
        fg_config_file = os.path.join(self.current_fg_path, 'fortigate.cfg')

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

        config_fortigate = {}
        try:
            with open(fg_config_file, "r") as fh:
                config_block = []
                for line in fh:
                    if line.startswith('#'):
                        continue
#                    x = line.rstrip('\n').replace(',', '_').replace('" "', ',').replace('"', '')
                    x = line.rstrip('\n').replace('" "', ';').replace('"', '')
                    if x.startswith('config'):
                        key = x
                        config_block = []
                        continue
                    if x == 'end':
                        config_fortigate[key] = config_block
                        config_block = []
                        key = 'Duble end'
                        continue
                    config_block.append(x)
        except FileNotFoundError:
            self.stepChanged.emit(f'RED|    Не найден файл "{fg_config_file}" с конфигурацией Fortigate.')
            self.error = 1
            return

        for item in bad_cert_block:
            config_fortigate.pop(item, None)

#        Это оставлено для тестирования.
#        with open(os.path.join(self.current_fg_path, 'tmp_fort.json'), 'w') as fh:
#            json.dump(config_fortigate, fh, indent=4, ensure_ascii=False)

        for key, value in config_fortigate.items():
            content = [x.strip().split() for x in value]
            if content:
                config_fortigate[key] = self.make_conf_block(content)
            else:
                config_fortigate[key] = {}

        json_file = os.path.join(self.current_fg_path, 'config.json')
        with open(json_file, 'w') as fh:
            json.dump(config_fortigate, fh, indent=4, ensure_ascii=False)

        self.stepChanged.emit(f'GREEN|    Конфигурация Fortigate в формате json выгружена в файл "{json_file}".')


    def make_conf_block(self, content):
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
                                edit_block[conf_key] = self.make_conf_block(conf_block)
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
                    block[conf_key] = self.make_conf_block(conf_block)
        return block


    def convert_ntp_settings(self, data):
        """Конвертируем настройки NTP"""
        self.stepChanged.emit('BLUE|Конвертация настроек NTP.')

        if 'config system ntp' in data and data['config system ntp'].get('ntpserver', None):
            current_path = os.path.join(self.current_ug_path, 'UserGate', 'GeneralSettings')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            ntp_info = data['config system ntp']
            ntp_server = {
                'ntp_servers': [],
                'ntp_enabled': True if ntp_info.get('server-mode', 'enable') == 'enable' else False,
                'ntp_synced': True if ntp_info.get('ntpsync', 'enable') == 'enable' else False
            }
            for i, value in ntp_info['ntpserver'].items():
                ntp_server['ntp_servers'].append(value['server'])
                if int(i) == 2:
                    break
            if ntp_server['ntp_servers']:
                json_file = os.path.join(current_path, 'config_ntp.json')
                with open(json_file, 'w') as fh:
                    json.dump(ntp_server, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Настройки NTP выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов NTP для экспорта.')


    def convert_dns_servers(self, data):
        """Заполняем список системных DNS"""
        self.stepChanged.emit('BLUE|Конвертация настроек DNS.')
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
            current_path = os.path.join(self.current_ug_path, 'Network', 'DNS')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            if dns_servers:
                json_file = os.path.join(current_path, 'config_dns_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(dns_servers, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки серверов DNS выгружены в файл "{json_file}".')
            if dns_rules:
                json_file = os.path.join(current_path, 'config_dns_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(dns_rules, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Правила DNS в DNS-прокси выгружены в файл "{json_file}".')
            self.stepChanged.emit('GREEN|    Настройки DNS конвертированы.')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек DNS для экспорта.')


    def convert_zone_settings(self, data):
        """Конвертируем зоны"""
        self.stepChanged.emit('BLUE|Конвертация Зон.')
        error = 0
        new_zone = {
            'name': '',
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
        if 'config system interface' in data:
            for key, value in data['config system interface'].items():
                if (zone_name := value.get('role', False)):
                    error, zone_name = self.get_transformed_name(zone_name, err=error, descr='Имя зоны')
                    self.zones.add(zone_name)
                    new_zone['name'] = zone_name
                    new_zone['description'] = 'Портировано с Fortigate.'
                    zones.append(copy.deepcopy(new_zone))
        if 'config system zone' in data:
            for key, value in data['config system zone'].items():
                error, zone_name = self.get_transformed_name(key, err=error, descr='Имя зоны')
                self.zones.add(zone_name)
                new_zone['name'] = zone_name
                new_zone['description'] = f'Портировано с Fortigate.\n{value.get("comment", "")}.'
                zones.append(copy.deepcopy(new_zone))
                if (tmp_ifaces := value.get('interface', False)):
                    tmp_ifaces = tmp_ifaces.split(';')
                    for iface in tmp_ifaces:
                        data['config system interface'][iface.strip()]['role'] = zone_name
        
        if zones:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Zones')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_zones.json')
            with open(json_file, 'w') as fh:
                json.dump(zones, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация зон прошла с ошибками. Зоны выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Настройки зон выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет зон для экспорта.')


    def convert_vpn_interfaces(self, data):
        """Конвертируем интерфейсы VLAN."""
        self.stepChanged.emit('BLUE|Конвертация интерфейсов VLAN.')
        if 'config system interface' not in data:
            self.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')
            return

        error = 0
        ifaces = []
        for ifname, ifblock in data['config system interface'].items():
            zone_name = ifblock.get('role', 0)
            if zone_name:
                error, zone_name = self.get_transformed_name(zone_name, err=error, descr='Имя зоны')
                self.zones.add(zone_name)
            if 'vlanid' in ifblock:
                iface = {
                    'name': ifname,
                    'kind': 'vlan',
                    'enabled': False if ifblock.get('status', 'up') == 'down' else True,
                    'description': f'Портировано с Fortigate.\n{ifname} {ifblock.get("description", "")}',
                    'zone_id': zone_name,
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
                    'link': ''
                }
                if ('ip' in ifblock and ifblock['ip']):
                    ip, mask = ifblock['ip'].split(' ')
                    err, result = self.pack_ip_address(ip, mask)
                    if err:
                        self.stepChanged.emit(f'RED|    Error: Интерфейс "{iface["name"]}" не конвертирован так как имеет не корректное значение IP-адреса.\n    {result}')
                        error = 1
                        continue
                    iface['ipv4'] = [result]
                    iface['mode'] = 'static'
                ifaces.append(iface)

        if ifaces:
            current_path = os.path.join(self.current_ug_path, 'Network', 'Interfaces')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_interfaces.json')
            with open(json_file, 'w') as fh:
                json.dump(ifaces, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Произошла ошибка при конвертации VLAN. Интерфейсы VLAN выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Интерфейсы VLAN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет интерфейсов VLAN для экспорта.')


    def convert_dhcp_settings(self, data):
        """Конвертируем настройки DHCP"""
        if 'config system dhcp server' in data:
            self.stepChanged.emit('BLUE|Конвертация настроек DHCP.')

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
                current_path = os.path.join(self.current_ug_path, 'Network', 'DHCP')
                err, msg = self.create_dir(current_path, delete='no')
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_dhcp_subnets.json')
                with open(json_file, 'w') as fh:
                    json.dump(dhcp_subnets, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
                self.stepChanged.emit('LBLUE|    После импорта DHCP в каждом правиле укажите домен, сервера DNS и необходимые DHCP опции.')
            else:
                self.stepChanged.emit('GRAY|    Нет настроек DHCP для экспорта.')


    def convert_notification_profile(self, data):
        """Конвертируем почтовый адрес и профиль оповещения"""
        if 'config system email-server' in data:
            self.stepChanged.emit('BLUE|Конвертация почтового адреса и профиля оповещения.')

            email_info = data['config system email-server']
            if 'server' in email_info:
                current_path = os.path.join(self.current_ug_path, 'Libraries', 'NotificationProfiles')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
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
                self.stepChanged.emit(f'GREEN|    Профиль оповещения SMTP выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет профиля оповещения для экспорта.')

            if 'reply-to' in email_info:
                current_path = os.path.join(self.current_ug_path, 'Libraries', 'Emails')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
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
                self.stepChanged.emit(f'GREEN|    Почтовый адрес выгружен в группу почтовых адресов "System email-server" в файле "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет почтового адреса для экспорта.')


    @staticmethod
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


    def convert_services(self, data):
        """Конвертируем сетевые сервисы."""
        self.stepChanged.emit('BLUE|Конвертация сетевых сервисов.')
        services = {}
        error = 0

        if 'config system session-helper' in data:
            for key, value in data['config system session-helper'].items():
                protocol = {
                    'proto': ip_proto[value['protocol']],
                    'port': value['port'],
                    'app_proto': '',
                    'source_port': '',
                    'alg': ''
                }
                error, service_name = self.get_transformed_name(value['name'], err=error, descr='Имя сервиса')
                if service_name in services:
                    services[service_name]['protocols'].append(protocol)
                else:
                    services[service_name] = {
                        'name': ug_services.get(service_name, service_name),
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
                        self.stepChanged.emit(f'RED|    Error: Сервис {key} содержит не допустмое значение прорта: "{port}".')
                        error = 1
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
                        self.stepChanged.emit(f'RED|    Error: Сервис {key} содержит не допустмое значение прорта: "{port}".')
                        error = 1
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

            error, service_name = self.get_transformed_name(key.strip(), err=error, descr='Имя сервиса')
            if service_name in services:
                services[service_name]['protocols'].extend(protocols)
            else:
                if service_name == 'ALL':
                    continue
                if service_name == 'ALL_TCP':
                    services[service_name] = self.convert_any_service('tcp', 'ALL_TCP')
                elif service_name == 'ALL_UDP':
                    services[service_name] = self.convert_any_service('udp', 'ALL_UDP')
                else:
                    if 'protocol' in value and value['protocol'] == 'ICMP':
                        services[service_name] = self.convert_any_service('icmp', service_name)
                    elif 'protocol' in value and value['protocol'] == 'ICMP6':
                        services[service_name] = self.convert_any_service('ipv6-icmp', service_name)
                    elif 'protocol-number' in value:
                        try:
                            proto = ip_proto[value['protocol-number']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: Протокол "{service_name}" номер протокола: "{err}" не поддерживается UG NGFW.')
                            error = 1
                        else:
                            services[service_name] = self.convert_any_service(proto, ug_services.get(service_name, service_name))
                    else:
                        services[service_name] = {
                            'name': ug_services.get(service_name, service_name),
                            'description': f"Портировано с Fortigate.\n{value['comment'] if 'comment' in value else value.get('category', '')}",
                            'protocols': protocols
                        }
        if services:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'Services')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_list.json')
            with open(json_file, 'w') as fh:
                json.dump(list(services.values()), fh, indent=4, ensure_ascii=False)
            self.services = services

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация сервисов прошла с ошибками. Сервисы выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Сервисы выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет сетевых сервисов для экспорта.')


    def convert_service_groups(self, data):
        """Конвертируем группы сервисов"""
        if 'config firewall service group' not in data:
            return
        self.stepChanged.emit('BLUE|Конвертация групп сервисов.')
        services_groups = []
        error = 0

        for key, value in data['config firewall service group'].items():
            error, group_name = self.get_transformed_name(key.strip(), err=error, descr='Имя группы сервисов')
            srv_group = {
                'name': group_name,
                'description': f'Портировано с Fortigate.\n{value.get("comment", "")}.',
                'type': 'servicegroup',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {},
                'content': []
            }
            for item in value['member'].split(';'):
                service = copy.deepcopy(self.services.get(item, None))
                if service:
                    for x in service['protocols']:
                        x.pop('source_port', None)
                        x.pop('app_proto', None)
                        x.pop('alg', None)
                    srv_group['content'].append(service)

            services_groups.append(srv_group)
#            self.service_groups.add(key)
            self.service_groups.add(group_name)

        if services_groups:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'ServicesGroups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit('RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_services_groups_list.json')
            with open(json_file, "w") as fh:
                json.dump(services_groups, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация групп сервисов прошла с ошибками. Группы сервисов выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Группы сервисов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')


    def convert_ip_lists(self, data):
        """Конвертируем списки IP-адресов"""
        self.stepChanged.emit('BLUE|Конвертация списков IP-адресов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        file_names = set()
        for list_name, value in data.get('config firewall address', {}).items():
            error, iplist_name = self.get_transformed_name(list_name, err=error, descr='Имя списка IP-адресов')
            ip_list = {
                'name': iplist_name,
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
                err, ip_address =  self.pack_ip_address(ip, mask)
                if err:
                    self.stepChanged.emit(f'RED|    Error: В списке IP-адресов "{list_name}" не корректный IP-адрес "{value["subnet"]}".')
                    ip_address = f'{ip_address}/32'
                    error = 1
                ip_list['content'] = [{'value': ip_address}]
            elif 'type' in value and value['type'] == 'iprange':
                ip_list['content'] = [{'value': f'{value.get("start-ip", "0.0.0.1")}-{value.get("end-ip", "255.255.255.255")}'}]
            else:
                continue

            if ip_list['content']:
                n += 1
                self.ip_lists.add(ip_list['name'])
                file_name = ip_list['name'].translate(self.trans_filename)
#                if file_name in file_names:
                while file_name in file_names:
                    file_name = f'{file_name}-2'
                file_names.add(file_name)

                json_file = os.path.join(current_path, f'{file_name}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       {n} - Список IP-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

        for list_name, value in data.get('config firewall multicast-address', {}).items():
            error, iplist_name = self.get_transformed_name(f'Multicast - {list_name}', err=error, descr='Имя списка IP-адресов')
            ip_list = {
                'name': iplist_name,
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
                self.ip_lists.add(ip_list['name'])
                n += 1

                json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       {n} - Список ip-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

        for list_name, value in data.get('config firewall addrgrp', {}).items():
            error, iplist_name = self.get_transformed_name(list_name, err=error, descr='Имя списка IP-адресов')
            ip_list = {
                'name': iplist_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': []
            }
            for item in value['member'].split(';'):
                error, item = self.get_transformed_name(item, err=error, descr='Имя списка IP-адресов')
                if item in self.ip_lists:
                    ip_list['content'].append({'list': item})
                elif item in self.url_lists:
                    continue
                else:
                    if self.check_ip(item):
                        ip_list['content'].append({'value': item})
                    else:
                        self.stepChanged.emit(f'RED|    Error: Для списка "{list_name}" не найден список ip-адресов "{item}". Такого списка нет в списках IP-адресов.')
                        error = 1

            if ip_list['content']:
                self.ip_lists.add(ip_list['name'])
                n += 1

                json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список ip-адресов "{ip_list["name"]}" выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков IP-адресов прошла с ошибками. Списки IP-адресов выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


    def convert_virtual_ip(self, data):
        """Конвертируем object 'config firewall vip' в IP-лист"""
        if 'config firewall vip' not in data:
            return
        self.stepChanged.emit('BLUE|Конвертация firewall virtual IP.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        for list_name, value in data['config firewall vip'].items():
            error, iplist_name = self.get_transformed_name(list_name, err=error, descr='Имя списка IP-адресов')
            ip_list = {
                'name': iplist_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': [{'value': value['extip']}]
            }
            self.ip_lists.add(ip_list['name'])
 
            json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(ip_list, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Создан список IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков IP-адресов прошла с ошибками. Списки IP-адресов выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки IP-адресов выгружены в каталог "{current_path}".')


    def convert_groups_iplists(self, data):
        """Конвертируем object 'config firewall vipgrp' в список ip-адресов"""
        if 'config firewall vipgrp' not in data:
            return
        self.stepChanged.emit('BLUE|Конвертация списков групп ip-адресов.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'IPAddresses')
        err, msg = self.create_dir(current_path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        for list_name, value in data['config firewall vipgrp'].items():
            error, iplist_name = self.get_transformed_name(list_name, err=error, descr='Имя списка групп IP-адресов')
            ip_list = {
                'name': iplist_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'network',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'threat_level': 3},
                'content': []
            }
            for item in value['member'].split(';'):
                error, item = self.get_transformed_name(item, err=error, descr='Имя списка IP-адресов')
                if item in self.ip_lists:
                    ip_list['content'].append({'list': item})
                else:
                    if self.check_ip(item):
                        ip_list['content'].append({'value': item})
                    else:
                        self.stepChanged.emit(f'RED|    Error: Для списка "{list_name}" не найден список ip-адресов "{item}". Такого списка нет в списках IP-адресов.')
                        error = 1

            if ip_list['content']:
                self.ip_lists.add(ip_list['name'])
 
                json_file = os.path.join(current_path, f'{ip_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(ip_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Создан список групп IP-адресов "{ip_list["name"]}" и выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков групп IP-адресов прошла с ошибками. Группы IP-адресов выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки групп IP-адресов выгружены в каталог "{current_path}".')


    def convert_url_lists(self, data):
        """Конвертируем списки URL"""
        self.stepChanged.emit('BLUE|Конвертация списков URL.')
        current_path = os.path.join(self.current_ug_path, 'Libraries', 'URLLists')
        err, msg = self.create_dir(current_path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        n = 0
        for key, value in data.get('config wanopt content-delivery-network-rule', {}).items():
            _, pattern = key.split(':')
            if pattern == '//':
                list_name = 'All URLs (default)'
            else:
                list_name = pattern.replace('/', '')

            error, list_name = self.get_transformed_name(list_name, err=error, descr='Имя списка URL')
            url_list = {
                'name': list_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': []
            }
            if 'host-domain-name-suffix' not in value and list_name != 'All URLs (default)':
                self.stepChanged.emit(f'RED|       Error: Запись "{key}" не конвертирована так как не имеет host-domain-name-suffix.')
                error = 1
                continue

            suffixes = self.work_with_rules(value['rules']) if 'rules' in value else []

            url_list['content'] = []
            for domain_name in value.get('host-domain-name-suffix', '').split(';'):
                if suffixes:
                    url_list['content'].extend([{'value': f'{domain_name}/{x}' if domain_name else x} for x in suffixes])
                else:
                    url_list['content'].extend([{'value': domain_name}])

            if url_list['content']:
                n += 1
                self.url_lists[url_list['name']] = url_list['content']

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        for list_name, value in data.get('config firewall address', {}).items():
            if 'type' in value and value['type'] in ('fqdn', 'wildcard-fqdn'):
                error, list_name = self.get_transformed_name(list_name, err=error, descr='Имя списка URL')
                url_list = {
                    'name': list_name,
                    'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                    'type': 'url',
                    'url': '',
                    'list_type_update': 'static',
                    'schedule': 'disabled',
                    'attributes': {'list_compile_type': 'case_insensitive'},
                    'content': [{'value': value['fqdn'] if 'fqdn' in value else value['wildcard-fqdn']}]
                }
                if url_list['content']:
                    n += 1
                    self.url_lists[url_list['name']] = url_list['content']

                    json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                    with open(json_file, 'w') as fh:
                        json.dump(url_list, fh, indent=4, ensure_ascii=False)
                    self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        for list_name, value in data.get('config firewall addrgrp', {}).items():
            error, list_name = self.get_transformed_name(list_name, err=error, descr='Имя списка URL')
            url_list = {
                'name': list_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': []
            }
            for url in value['member'].split(';'):
                error, url = self.get_transformed_name(url, err=error, descr='Имя списка URL')
                if url in self.url_lists:
                    url_list['content'].extend(self.url_lists[url])

            if url_list['content']:
                n += 1
                self.url_lists[url_list['name']] = url_list['content']

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        for list_name, value in data.get('config firewall wildcard-fqdn custom', {}).items():
            error, list_name = self.get_transformed_name(list_name, err=error, descr='Имя списка URL')
            url_list = {
                'name': list_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': [{'value': value['wildcard-fqdn']}]
            }
            if url_list['name'] in self.url_lists:
                url_list['name'] = f'{url_list["name"]} - wildcard-fqdn'

            self.url_lists[url_list['name']] = url_list['content']
            n += 1

            json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
            with open(json_file, 'w') as fh:
                json.dump(url_list, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        for list_name, value in data.get('config firewall wildcard-fqdn group', {}).items():
            error, list_name = self.get_transformed_name(list_name, err=error, descr='Имя списка URL')
            url_list = {
                'name': list_name,
                'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                'type': 'url',
                'url': '',
                'list_type_update': 'static',
                'schedule': 'disabled',
                'attributes': {'list_compile_type': 'case_insensitive'},
                'content': []
            }
            for url in value['member'].split(';'):
                error, url = self.get_transformed_name(url, err=error, descr='Имя списка URL')
                if url in self.url_lists:
                    url_list['content'].extend(self.url_lists[url])
                wildcard_url_name = f'{url} - wildcard-fqdn'
                if wildcard_url_name in self.url_lists:
                    url_list['content'].extend(self.url_lists[wildcard_url_name])

            if url_list['content']:
                n += 1
                self.url_lists[url_list['name']] = url_list['content']

                json_file = os.path.join(current_path, f'{url_list["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(url_list, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       {n} - Список URL "{url_list["name"]}" выгружен в файл "{json_file}".')

        if error:
            self.stepChanged.emit(f'ORANGE|    Конвертация списков URL прошла с ошибками. Списки URL выгружены в каталог "{current_path}".')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Списки URL выгружены в каталог "{current_path}".')


    @staticmethod
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


    def convert_time_sets(self, data):
        """Конвертируем time set (календари)"""
        self.stepChanged.emit('BLUE|Конвертация календарей.')
        week = {
            'monday': 1,
            'tuesday': 2,
            'wednesday': 3,
            'thursday': 4,
            'friday': 5,
            'saturday': 6,
            'sunday': 7
        }
        timerestrictiongroup = []
        error = 0

        if 'config firewall schedule onetime' in data:
            for key, value in data['config firewall schedule onetime'].items():
                if value:
                    error, schedule_name = self.get_transformed_name(key, err=error, descr='Имя календаря')
                    time_set = {
                        'name': schedule_name,
                        'description': 'Портировано с Fortigate',
                        'type': 'timerestrictiongroup',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {},
                        'content': []
                    }
                    content = {
                        'name': schedule_name,
#                        'type': 'range',
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
#                        content['type'] = 'span'
                        content['time_to'] = time_to
                        content['fixed_date_to'] = f'{fixed_date_to.replace("/", "-")}T00:00:00'
                    elif 'end' not in value:
                        time_from, fixed_date_from = value['start'].split()
#                        content['type'] = 'span'
                        content['time_from'] = time_from
                        content['fixed_date_from'] = f'{fixed_date_from.replace("/", "-")}T00:00:00'
                    time_set['content'].append(content)

                    timerestrictiongroup.append(time_set)
                    self.time_restrictions.add(time_set['name'])

        if 'config firewall schedule recurring' in data:
            for key, value in data['config firewall schedule recurring'].items():
                if value:
                    error, schedule_name = self.get_transformed_name(key, err=error, descr='Имя календаря')
                    schedule = {
                        'name': schedule_name,
                        'description': 'Портировано с Fortigate',
                        'type': 'timerestrictiongroup',
                        'url': '',
                        'list_type_update': 'static',
                        'schedule': 'disabled',
                        'attributes': {},
                        'content': []
                    }
                    if 'day' in value and value['day'] != 'none':
                        content = {
                            'type': 'weekly',
                            'name': schedule_name,
                            'days': [week[day] for day in value['day'].split()]
                        }
                    else:
                        content = {
                            'type': 'daily',
                            'name': schedule_name,
                        }
                    if 'start' in value:
                        content['time_from'] = value['start']
                        content['time_to'] = value['end']
                    schedule['content'].append(content)

                    timerestrictiongroup.append(schedule)
                    self.time_restrictions.add(schedule['name'])

        if timerestrictiongroup:
            current_path = os.path.join(self.current_ug_path, 'Libraries', 'TimeSets')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_calendars.json')
            with open(json_file, 'w') as fh:
                json.dump(timerestrictiongroup, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация календарей прошла с ошибками. Список календарей выгружен в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Список календарей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


    def convert_shapers_list(self, data):
        """Конвертируем полосы пропускания"""
        self.stepChanged.emit('BLUE|Конвертация полос пропускания.')
        error = 0
    
        if 'config firewall shaper traffic-shaper' in data:
            shapers = []
            for key, value in data['config firewall shaper traffic-shaper'].items():
                rate = int(value.get('maximum-bandwidth', 'guaranteed-bandwidth'))
                if 'bandwidth-unit' in value:
                    if value['bandwidth-unit'] == 'mbps':
                        rate = rate*1024
                    if value['bandwidth-unit'] == 'gbps':
                        rate = rate*1024*1024
                error, shaper_name = self.get_transformed_name(key, err=error, descr='Имя календаря')
                shapers.append({
                    'name': shaper_name,
                    'description': 'Портировано с Fortigate.',
                    'rate': rate,
                    'dscp': 0
                })

            if shapers:
                current_path = os.path.join(self.current_ug_path, 'Libraries', 'BandwidthPools')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_shaper_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(shapers, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Полосы пропускания выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    Полосы пропускания выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')


    def convert_shapers_rules(self, data):
        """Конвертируем правила пропускной способности"""
        self.stepChanged.emit('BLUE|Конвертация правил пропускной способности.')
        error = 0
    
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
                    rule_name = self.get_new_uuid()
                else:
                    error, rule_name = self.get_transformed_name(f'{key}-{value["name"]}', err=error, descr='Имя правила')

                if value.get('traffic-shaper', None):
                    rule['name'] = rule_name
                    rule['pool'] = value['traffic-shaper']
                    self.get_ips(value.get('srcaddr', ''), value.get('dstaddr', ''), rule)
                    self.get_services(value.get('service', ''), rule)

                    if rule['rule_error']:
                        rule['name'] = f'ERROR - {rule["name"]}'
                        rule['enabled'] = False
                    if rule.pop('rule_error', None):
                        error = 1
                    shaping_rules.append(copy.deepcopy(rule))

                if value.get('traffic-shaper-reverse', None):
                    rule['name'] = f'{rule_name} (Reverse)'
                    rule['rule_error'] = 0
                    rule['pool'] = value['traffic-shaper-reverse']
                    self.get_ips(value.get('dstaddr', ''), value.get('srcaddr', ''), rule)
                    self.get_services(value.get('service', ''), rule)

                    if rule['rule_error']:
                        rule['name'] = f'ERROR - {rule["name"]}'
                        rule['enabled'] = False
                    if rule.pop('rule_error', None):
                        error = 1
                    shaping_rules.append(copy.deepcopy(rule))

            if shaping_rules:
                current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'TrafficShaping')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_shaper_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(shaping_rules, fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Правила пропускной способности выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')


    def convert_auth_servers(self, data):
        """Конвертируем сервера авторизации"""
        self.stepChanged.emit('BLUE|Конвертация серверов аутентификации.')
        ldap_servers = []
        radius_servers = []
        error = 0

        if 'config user ldap' in data:
            for key, value in data['config user ldap'].items():
                if value['dn']:
                    tmp_dn1 = [x.split('=') for x in value['dn'].split(',')]
                    tmp_dn2 = [b for a, b in tmp_dn1 if a in ['dc', 'DC']]
                    dn = '.'.join(tmp_dn2)
                error, rule_name = self.get_transformed_name(f'{key.strip()} - AD Auth server', err=error, descr='Имя календаря')
                ldap_servers.append({
                    'name': rule_name,
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
                error, rule_name = self.get_transformed_name(f'{key.strip()} - Radius Auth server', err=error, descr='Имя календаря')
                radius_servers.append({
                    'name': rule_name,
                    'description': 'Radius auth server импортирован с Fortigate.',
                    'enabled': False,
                    'addresses': [
                        {'host': value['server'], 'port': 1812}
                    ]
                })
                auth_login = self.get_transformed_userlogin(key)
                self.local_users[key] = {
                    'name': key,
                    'enabled': True,
                    'auth_login': auth_login,
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
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'AuthServers')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            if ldap_servers:
                json_file = os.path.join(current_path, 'config_ldap_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(ldap_servers, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации LDAP выгружены в файл "{json_file}".')
            if radius_servers:
                json_file = os.path.join(current_path, 'config_radius_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(radius_servers, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Настройки серверов аутентификации RADIUS выгружены в файл "{json_file}".')

            if error:
                self.stepChanged.emit('ORANGE|    Конвертация прошла с ошибками. Настройки серверов аутентификации конвертированы.')
                self.error = 1
            else:
                self.stepChanged.emit('GREEN|    Настройки серверов аутентификации конвертированы.')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов аутентификации для экспорта.')


    def convert_local_users(self, data):
        """Конвертируем локальных пользователей"""
        self.stepChanged.emit('BLUE|Конвертация локальных пользователей.')

        if 'config user local' in data:
            for key, value in data['config user local'].items():
                if value['type'] == 'password':
                    auth_login = self.get_transformed_userlogin(key)
                    self.local_users[key] = {
                        'name': key,
                        'enabled': False if value.get('status', None) == 'disable' else True,
                        'auth_login': auth_login,
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
                users_in_group = [x for x in value['member'].split(';') if x in self.local_users] if 'member' in value else []
                for user in users_in_group:
                    self.local_users[user]['groups'].append(key)

        if self.local_users:
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'Users')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}.')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_users.json')
            with open(json_file, 'w') as fh:
                json.dump([x for x in self.local_users.values()], fh, indent=4, ensure_ascii=False)

            self.stepChanged.emit(f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет локальных пользователей для экспорта.')


    def convert_user_groups(self, data):
        """Конвертируем локальные группы пользователей"""
        if 'config user group' in data:
            self.stepChanged.emit('BLUE|Конвертация локальных групп пользователей.')
            current_path = os.path.join(self.current_ug_path, 'UsersAndDevices', 'Groups')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            groups = []
            for key, value in data['config user group'].items():
                groups.append({
                    'name': key,
                    'description': 'Портировано с Fortigate.',
                    'is_ldap': False,
                    'is_transient': False,
                    'users': [x for x in value['member'].split(';') if x in self.local_users] if 'member' in value else []
                })
                self.local_groups.add(key)

            json_file = os.path.join(current_path, 'config_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(groups, fh, indent=4, ensure_ascii=False)

            if groups:
                self.stepChanged.emit(f'GREEN|    Список локальных групп пользователей выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет локальных групп пользователей для экспорта.')


    def convert_web_portal_resources(self, data):
        """Конвертируем ресурсы веб-портала"""
        if 'config vpn ssl web user-bookmark' in data:
            self.stepChanged.emit('BLUE|Конвертация ресурсов веб-портала.')

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
            if resources:
                current_path = os.path.join(self.current_ug_path, 'GlobalPortal', 'WebPortal')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_web_portal.json')
                with open(json_file, 'w') as fh:
                    json.dump(resources, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Список ресурсов веб-портала выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет ресурсов веб-портала для экспорта.')


    def convert_dnat_rule(self, data):
        """Конвертируем object 'config firewall vip' в правила DNAT или Port-форвардинга"""
        if 'config firewall vip' not in data:
            return
        self.stepChanged.emit('BLUE|Конвертация правил DNAT/Порт-форвардинга.')

        n = 0
        error = 0
        rules = []
        ips_for_rules = set()
        for key, value in data['config firewall vip'].items():
            if value and 'type' not in value:
                if 'mappedip' in value:
                    value['mappedip'] = value['mappedip'].split('/')[0]
                    value['extip'] = value['extip'].split('/')[0]
                    services = []
                    port_mappings = []
                    if value['extip'] in ips_for_rules:
                        list_id = value['extip']
                    else:
                        list_id = self.create_ip_list(ips=[value['extip']], name=value['extip'], descr='Портировано с Fortigate.')
                        ips_for_rules.add(list_id)
                    if value['mappedip'] not in ips_for_rules:
                        ips_for_rules.add(self.create_ip_list(ips=[value['mappedip']], descr='Портировано с Fortigate.'))
                    if 'service' in value:
                        services = [['service' if x in self.services else 'list_id', x] for x in value['service'].split()]
                    elif 'mappedport' in value:
                        try:
                            port_mappings = [{
                                'proto': value['protocol'] if 'protocol' in value else 'tcp',
                                'src_port': int(value['extport']),
                                'dst_port': int(value['mappedport'])
                            }]
                        except ValueError:
                            port_mappings = []
                    error, rule_name = self.get_transformed_name(f'Rule {key}', err=error, descr='Имя правила DNAT')
                    rule = {
                        'name': rule_name,
                        'description': f"Портировано с Fortigate.\n{value.get('comment', '')}",
                        'action': 'port_mapping' if port_mappings else 'dnat',
                        'position': 'last',
                        'zone_in': self.get_zones(value.get('extintf', '')),
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
                    n += 1
                    self.stepChanged.emit(f'BLACK|    {n} - Создано правило {rule["action"]} "{rule["name"]}".')

        self.ip_lists.update(ips_for_rules)

        if rules:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'NATandRouting')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_nat_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Павила DNAT/Порт-форвардинга выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил DNAT/Порт-форвардинга для экспорта.')


    def convert_loadbalancing_rule(self, data):
        """Конвертируем object 'config firewall vip' в правила балансировки нагрузки"""
        if 'config firewall vip' not in data:
            return
        self.stepChanged.emit('BLUE|Конвертация правил балансировки нагрузки.')

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
                self.ip_lists.add(self.create_ip_list(ips=ip_list_ips, name=key, descr='Портировано с Fortigate.'))

                _, rule_name = self.get_transformed_name(f'Rule {key.strip()}', descr='Имя правила балансировки нагрузки')
                rule = {
                    'name': rule_name,
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
                    'src_zones': self.get_zones(value.get('extintf', '')),
                    'src_zones_nagate': False,
                    'src_ips': [],
                    'src_ips_nagate': False
                }
                rules.append(rule)
                self.stepChanged.emit(f'BLACK|    Создано правило балансировки нагрузки "{rule["name"]}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'LoadBalancing')
            err, msg = self.create_dir(current_path, delete='no')
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_loadbalancing_tcpudp.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Павила балансировки нагрузки выгружены в файл "{json_file}".')

            if ssl_certificate:
                message = (
                    '    В правилах Fortigate использовались сертификаты, после импорта конфигурации удалите соответсвующие правила\n'
                    '    балансировки нагрузки и создайте правила reverse-прокси, предварительно загрузив необходимые сертификаты.'
                )
                self.stepChanged.emit(f'LBLUE|{message}')
        else:
            self.stepChanged.emit('GRAY|    Нет правил балансировки нагрузки для экспорта.')


    def convert_firewall_policy(self, data):
        """Конвертируем object 'config firewall policy' в правила МЭ"""
        if 'config firewall policy' not in data:
            return
        self.stepChanged.emit('BLUE|Конвертация правил межсетевого экрана.')
        message = (
            '    После импорта правил МЭ, необходимо в каждом правиле указать зону источника и зону назначения.\n'
            '    Создайте необходимое количество зон и присвойте зону каждому интерфейсу.'
        )
        self.stepChanged.emit(f'LBLUE|{message}')

        error = 0
        n = 0
        rules = []
        subset = {'nat', 'ippool', 'poolname'}
        for key, value in data['config firewall policy'].items():

            if subset.issubset(set(value.keys())):
#                print('Имя -', value.get('name', 'Нет имени'), 'nat - ', value['nat'], 'ippool - ', value['ippool'], 'dstaddr - ', value['dstaddr'])
                continue

            error, rule_name = self.get_transformed_name(f'{value.get("name", key)}', err=error, descr='Имя правила МЭ')
            rule = {
                'name': rule_name,
                'description': f"Портировано с Fortigate.\nFortigate UUID: {value.get('uuid', 'Отсутствует')}\n{value.get('comments', '')}",
                'action': value['action'] if value.get('action', None) else 'drop',
                'position': 'last',
                'scenario_rule_id': False,     # При импорте заменяется на UID или "0". 
                'src_zones': self.get_zones(value.get('srcintf', '')),
                'dst_zones': self.get_zones(value.get('dstintf', '')),
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
                'uuid': value.get('uuid', None)
            }
            if 'groups' in value:
                self.get_users_and_groups(value['groups'], rule)
            elif 'users' in value:
                self.get_users_and_groups(value['users'], rule)
            if 'fsso-groups' in value:
                domain = []
                group_name = ''
                for item in [x.split('=') for x in value['fsso-groups'].split(',')]:
                    if item[0].upper() == 'CN':
                        group_name = item[1]
                    elif item[0].upper() == 'DC':
                        domain.append(item[1])
                rule['users'].append(['group', f"{'.'.join(domain)}\\{group_name}"])
            self.get_ips(value.get('srcaddr', ''), value.get('dstaddr', ''), rule)
            self.get_services(value.get('service', ''), rule)
            self.get_time_restrictions(value['schedule'], rule)

            if rule['rule_error']:
                rule['name'] = f'ERROR - {rule["name"]}'
                rule['enabled'] = False
            else:
                rule['name'] = f'Rule - {rule["name"]}'
            error, rule['name'] = self.get_transformed_name(rule['name'], err=error, descr='Имя правила МЭ', default_name=key)
            if rule['name'] == key:
                rule['description'] = f'{rule["description"]}\nИсходное имя правила заменено, так как оно не корректно.'
            if rule.pop('rule_error', None):
                error = 1
            rule.pop('uuid', None)

            rules.append(rule)
            n += 1
            self.stepChanged.emit(f'BLACK|    {n} - Создано правило МЭ "{rule["name"]}".')

        if rules:
            current_path = os.path.join(self.current_ug_path, 'NetworkPolicies', 'Firewall')
            err, msg = self.create_dir(current_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(current_path, 'config_firewall_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(rules, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Павила межсетевого экрана выгружены в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Павила межсетевого экрана выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


    def convert_gateways_list(self, data):
        """Конвертируем список шлюзов"""
        self.stepChanged.emit('BLUE|Конвертация списка шлюзов.')

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
                current_path = os.path.join(self.current_ug_path, 'Network', 'Gateways')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_gateways.json')
                with open(json_file, 'w') as fh:
                    json.dump(list_gateways, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Список шлюзов выгружен в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет списка шлюзов для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет списка шлюзов для экспорта.')


    def convert_static_routes(self, data):
        """Конвертируем статические маршруты в VRF по умолчанию"""
        self.stepChanged.emit('BLUE|Конвертация статических маршрутов в VRF по умолчанию.')
        error = 0
        if 'config router static' in data:
            for value in data['config router static'].values():
                if 'dst' in value and 'gateway' in value:
                    err, dst_network = self.pack_ip_address(*value['dst'].split())
                    if err:
                        self.stepChanged.emit(f'RED|    Error: Статический маршрут "{key} - {value["dst"]}" не конвертирован. В dst указан не корректный IP-адрес [dst_network].')
                        error = 1
                        continue
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
                    self.vrf['routes'].append(route)

            if self.vrf['routes']:
                current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
                err, msg = self.create_dir(current_path)
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_vrf.json')
                with open(json_file, 'w') as fh:
                    json.dump([self.vrf], fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Конвертация прошла с ошибками. Статические маршруты выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    Статические маршруты выгружены в файл "{json_file}".')
            else:
                self.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')
        else:
            self.stepChanged.emit('GRAY|    Нет статических маршрутов для экспорта.')


    def convert_bgp_routes(self, data):
        """Конвертируем настройки BGP в VRF по умолчанию"""
        if 'config router bgp' not in data:
            return

        self.stepChanged.emit('BLUE|Конвертация настроек BGP в VRF по умолчанию.')
        error = 0
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
                    err, prefix = self.pack_ip_address(*item['prefix'].split())
                    if err:
                        self.stepChanged.emit(f'RED|    Error: router prefix-list "{key} - {item["prefix"]}" не конвертирован. Указан не корректный IP-адрес [prefix].')
                        error = 1
                        continue
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
                config_network = []
                if 'network' in bgp and bgp['network']:
                    for x in bgp['network'].values():
                        err, prefix = self.pack_ip_address(*x['prefix'].split())
                        if err:
                            self.stepChanged.emit(f'RED|    Error: BGP network "{x["prefix"]}" не конвертирован. Указан не корректный IP-адрес [prefix].')
                            error = 1
                            continue
                        config_network.append(prefix)
                self.vrf['bgp'] = {
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
                self.stepChanged.emit(f'RED|    Error: Произошла ошибка при экспорте настроек BGP: {err}.')
                self.error = 1
            else:
                current_path = os.path.join(self.current_ug_path, 'Network', 'VRF')
                err, msg = self.create_dir(current_path, delete='no')
                if err:
                    self.stepChanged.emit(f'RED|    {msg}')
                    self.error = 1
                    return

                json_file = os.path.join(current_path, 'config_vrf.json')
                with open(json_file, 'w') as fh:
                    json.dump([self.vrf], fh, indent=4, ensure_ascii=False)

                if error:
                    self.stepChanged.emit(f'ORANGE|    Конвертация BGP прошла с ошибками. Настройки BGP выгружены в файл "{json_file}".')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'GREEN|    Настройки BGP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек BGP для экспорта.')


############################################# Служебные функции ###################################################
    def get_ips(self, src_ips, dst_ips, rule):
        """
        Получить имена списков IP-адресов и URL-листов.
        Если списки не найдены, то они создаются или пропускаются, если невозможно создать."""
        if src_ips:
            new_rule_ips = []
            for item in src_ips.split(';'):
                if item in ('all', '0.0.0.0'):
                    continue
                if item in GEOIP_CODE:
                    new_rule_ips.append(['geoip_code', GEOIP_CODE[item]])
                    continue
                err, item = self.get_transformed_name(item, descr='Имя списка IP-адресов')
                if err:
                    self.stepChanged.emit(f'RED|       Error: Правило "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                if item in self.ip_lists:
                    new_rule_ips.append(['list_id', item])
                elif item in self.url_lists:
                    new_rule_ips.append(['urllist_id', item])
                else:
                    if self.check_ip(item):
                        new_rule_ips.append(['list_id', self.create_ip_list(ips=[item], name=item, descr='Портировано с Fortigate.')])
                    else:
                        self.stepChanged.emit(f'RED|    Error: Не найден src-адрес "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                        rule['description'] = f'{rule["description"]}\nError: Не найден src-адрес "{item}".'
                        rule['rule_error'] = 1
            rule['src_ips'] = new_rule_ips
        if dst_ips:
            new_rule_ips = []
            for item in dst_ips.split(';'):
                if item in ('all', '0.0.0.0'):
                    continue
                err, item = self.get_transformed_name(item, descr='Имя списка IP-адресов')
                if err:
                    self.stepChanged.emit(f'RED|       Error: Правило "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                if item in self.ip_lists:
                    new_rule_ips.append(['list_id', item])
                elif item in self.url_lists:
                    new_rule_ips.append(['urllist_id', item])
                else:
                    if self.check_ip(item):
                        new_rule_ips.append(['list_id', self.create_ip_list(ips=[item], name=item, descr='Портировано с Fortigate.')])
                    else:
                        self.stepChanged.emit(f'RED|    Error: Не найден dst-адрес "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                        rule['description'] = f'{rule["description"]}\nError! Не найден dst-адрес "{item}".'
                        rule['rule_error'] = 1
            rule['dst_ips'] = new_rule_ips


    def get_services(self, rule_services, rule):
        """Получить список сервисов"""
        new_service_list = []
        if rule_services:
            for service in rule_services.split(';'):
                if service.upper() in ('ALL', 'ANY'):
                    continue
                _, service = self.get_transformed_name(service, descr='Имя ceрвиса', mode=0)
                if service in self.services:
                    new_service_list.append(['service', ug_services.get(service, service)])
                elif service in self.service_groups:
                    new_service_list.append(['list_id', service])
                else:
                    self.stepChanged.emit(f'RED|    Error: Не найден сервис "{service}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                    rule['description'] = f'{rule["description"]}\nError! Не найден сервис "{service}".'
                    rule['rule_error'] = 1
            rule['services'] = new_service_list


    def get_zones(self, intf):
        """Получить список зон для правила"""
        new_zones = []
        if intf:
            for item in intf.split(';'):
                if item == 'any':
                    continue
                err, item = self.get_transformed_name(item.strip(), descr='Имя зоны')
                if item in self.zones:
                    new_zones.append(item)
        return new_zones


    def get_users_and_groups(self, users, rule):
        """Получить имена групп и пользователей."""
        new_users_list = []
        for item in users.split(';'):
            if item in self.local_users:
                new_users_list.append(['user', item])
            elif item in self.local_groups:
                new_users_list.append(['group', item])
            else:
                self.stepChanged.emit(f'RED|    Error: Не найден локальный пользователь/группа "{item}" для правила "{rule["name"]}".')
                rule['description'] = f'{rule["description"]}\nError! Не найден локальный пользователь/группа "{item}".'
                rule['rule_error'] = 1
        rule['users'] =  new_users_list


    def get_time_restrictions(self, time_restrictions, rule):
        """Получить значение календаря."""
        new_schedule = []
        for item in time_restrictions.split(';'):
            err, schedule_name = self.get_transformed_name(item, descr='Имя календаря')
            if err:
                self.stepChanged.emit(f'RED|    Error: Преобразовано имя календаря "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
            if schedule_name == 'always':
                continue
            if schedule_name in self.time_restrictions:
                new_schedule.append(schedule_name)
            else:
                self.stepChanged.emit(f'RED|    Error: Не найден календарь "{item}" для правила "{rule["name"]}" uuid: "{rule.get("uuid", "Отсутствует")}".')
                rule['description'] = f'{rule["description"]}\nError! Не найден календарь "{schedule_name}".'
                rule['rule_error'] = 1
        rule['time_restrictions'] = new_schedule


def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
