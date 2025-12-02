#!/usr/bin/env python3
#
# Copyright @ 2021-2023 UserGate Corporation. All rights reserved.
# Author: Aleksei Remnev <aremnev@usergate.com>
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
#-------------------------------------------------------------------------------------------------------- 
# import_functions.py
# Класс импорта разделов конфигурации на NGFW UserGate.
# Версия 3.8   02.12.2025
#

import os, sys, copy, json
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import ReadWriteBinFile, MyMixedService
from services import zone_services, certs_role


class ImportNgfwSelectedPoints(QThread, ReadWriteBinFile, MyMixedService):
    """Импортируем разделы конфигурации на NGFW"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm, config_path, arguments, all_points=None, selected_path=None, selected_points=None):
        super().__init__()
        self.utm = utm
        self.config_path = config_path
        self.all_points = all_points
        self.selected_path = selected_path
        self.selected_points = selected_points

        self.ngfw_ifaces = arguments['iface_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.adapter_ports = arguments['adapter_ports']
        self.node_name = arguments['node_name']
        self.error = 0
        self.import_funcs = {
            'Morphology': self.import_morphology_lists,
            'Services': self.import_services_list,
            'ServicesGroups': self.import_services_groups,
            'IPAddresses': self.import_ip_lists,
            'Useragents': self.import_useragent_lists,
            'ContentTypes': self.import_mime_lists,
            'URLLists': self.import_url_lists,
            'TimeSets': self.import_time_restricted_lists,
            'BandwidthPools': self.import_shaper_list,
            'SCADAProfiles': self.import_scada_profiles,
            'ResponcePages': self.import_templates_list,
            'URLCategories': self.import_url_categories,
            'OverURLCategories': self.import_custom_url_category,
            'Applications': self.import_application_signature,
            'ApplicationProfiles': self.import_app_profiles,
            'ApplicationGroups': self.import_application_groups,
            'Emails': self.import_email_groups,
            'Phones': self.import_phone_groups,
            'IPDSSignatures': self.import_custom_idps_signature,
            'IDPSProfiles': self.import_idps_profiles,
            'NotificationProfiles': self.import_notification_profiles,
            'NetflowProfiles': self.import_netflow_profiles,
            'LLDPProfiles': self.import_lldp_profiles,
            'SSLProfiles': self.import_ssl_profiles,
            'SSLForwardingProfiles': self.import_ssl_forward_profiles,
            'HIDObjects': self.import_hip_objects,
            'HIDProfiles': self.import_hip_profiles,
            'BfdProfiles': self.import_bfd_profiles,
            'UserIdAgentSyslogFilters': self.import_useridagent_syslog_filters,
            'Scenarios': self.import_scenarios,
            'Tags': self.import_tags,
            'Zones': self.import_zones,
            'Interfaces': self.import_interfaces,
            'Gateways': self.import_gateways,
            'AuthServers': self.import_auth_servers,
            'MFAProfiles': self.import_2fa_profiles,
            'AuthProfiles': self.import_auth_profiles,
            'CaptiveProfiles': self.import_captive_profiles,
            'CaptivePortal': self.import_captive_portal_rules,
            'Groups': self.import_local_groups,
            'Users': self.import_local_users,
            'TerminalServers': self.import_terminal_servers,
            'UserIDagent': self.import_userid_agent,
            'BYODPolicies': self.import_byod_policy,
            'BYODDevices': self.pass_function,
            'Certificates': self.import_certificates,
            'UserCertificateProfiles': self.import_users_certificate_profiles,
            'GeneralSettings': self.import_general_settings,
            'DeviceManagement': self.pass_function,
            'Administrators': self.import_admins,
            'DNS': self.import_dns_config,
            'DHCP': self.import_dhcp_subnets,
            'VRF': self.import_vrf,
            'WCCP': self.import_wccp_rules,
            'Routes': self.pass_function,
            'OSPF': self.pass_function,
            'BGP': self.pass_function,
            'Firewall': self.import_firewall_rules,
            'NATandRouting': self.import_nat_rules,
            'ICAPServers': self.import_icap_servers,
            'ReverseProxyServers': self.import_reverseproxy_servers,
            'LoadBalancing': self.import_loadbalancing_rules,
            'TrafficShaping': self.import_shaper_rules,
            'ContentFiltering': self.import_content_rules,
            'SafeBrowsing': self.import_safebrowsing_rules,
            'TunnelInspection': self.import_tunnel_inspection_rules,
            'SSLInspection': self.import_ssldecrypt_rules,
            'SSHInspection': self.import_sshdecrypt_rules,
            'IntrusionPrevention': self.import_idps_rules,
            'MailSecurity': self.import_mailsecurity,
            'ICAPRules': self.import_icap_rules,
            'DoSProfiles': self.import_dos_profiles,
            'DoSRules': self.import_dos_rules,
            'SCADARules': self.import_scada_rules,
            'CustomWafLayers': self.import_waf_custom_layers,
            'SystemWafRules': self.pass_function,
            'WAFprofiles': self.import_waf_profiles,
            'WebPortal': self.import_proxyportal_rules,
            'ReverseProxyRules': self.import_reverseproxy_rules,
            'UpstreamProxiesServers': self.import_upstream_proxies_servers,
            'UpstreamProxiesProfiles': self.import_upstream_proxies_profiles,
            'UpstreamProxiesRules': self.import_upstream_proxies_rules,
            'ServerSecurityProfiles': self.import_vpnserver_security_profiles,
            'ClientSecurityProfiles': self.import_vpnclient_security_profiles,
            'SecurityProfiles': self.import_vpn_security_profiles,
            'VPNNetworks': self.import_vpn_networks,
            'ServerRules': self.import_vpn_server_rules,
            'ClientRules': self.import_vpn_client_rules,
            'AlertRules': self.import_notification_alert_rules,
            'SNMPSecurityProfiles': self.import_snmp_security_profiles,
            'SNMP': self.import_snmp_rules,
            'SNMPParameters': self.import_snmp_settings,
        }


    def run(self):
        """Импортируем разделы конфигурации"""
        # Читаем бинарный файл библиотечных данных
        err, self.ngfw_data = self.read_bin_file()
        if err:
            self.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван! Не удалось прочитать служебные данные.')
            return

        if self.all_points:
            """Импортируем всё в пакетном режиме"""
            path_dict = {}
            for item in self.all_points:
                top_level_path = os.path.join(self.config_path, item['path'])
                for point in item['points']:
                    path_dict[point] = os.path.join(top_level_path, point)
            for key, value in self.import_funcs.items():
                if key in path_dict:
                    value(path_dict[key])
        else:
            """Импортируем определённые разделы конфигурации"""
            for point in self.selected_points:
                current_path = os.path.join(self.selected_path, point)
                if point in self.import_funcs:
                    self.import_funcs[point](current_path)
                else:
                    self.error = 1
                    self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')

        # Сохраняем бинарный файл библиотечных данных после изменений в процессе работы
        if self.write_bin_file(self.ngfw_data):
            self.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван! Не удалось записать служебные данные.')
            return

        if self.error:
            self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Импорт конфигурации завершён.\n')


    #------------------------------------------ UserGate -------------------------------------------
    def import_certificates(self, path):
        """
        Импортируем сертификаты. Правила импорта приведены в разделе документации 'Импорт сертификатов'.
        """
        self.stepChanged.emit('BLUE|Импорт сертификатов в раздел "UserGate/Сертификаты".')

        if not os.path.isdir(path):
            return
        certificates = {entry.name: entry.path for entry in os.scandir(path) if entry.is_dir()}
        if not certificates:
            self.stepChanged.emit('GRAY|    Нет сертификатов для импорта.')
            return
        error = 0
        new_cert_exists = False
    
        for cert_name, cert_path in certificates.items():
            files = [entry.name for entry in os.scandir(cert_path) if entry.is_file()]

            json_file = os.path.join(cert_path, 'certificate_list.json')
            err, data = self.read_json_file(json_file, mode=1)
            if err:
                continue

            cert_data = None
            if 'cert.pem' in files:
                with open(os.path.join(cert_path, 'cert.pem'), mode='rb') as fh:
                    cert_data = fh.read()
            elif 'cert.der' in files:
                with open(os.path.join(cert_path, 'cert.der'), mode='rb') as fh:
                    cert_data = fh.read()

            key_data = None
            if 'key.der' in files:
                with open(os.path.join(cert_path, 'key.der'), mode='rb') as fh:
                    key_data = fh.read()
            elif 'key.pem' in files:
                with open(os.path.join(cert_path, 'key.pem'), mode='rb') as fh:
                    key_data = fh.read()

            if data['name'] in self.ngfw_data['certs']:
                self.stepChanged.emit(f'uGRAY|    Сертификат "{cert_name}" уже существует.')
            else:
                if not cert_data:
                    self.stepChanged.emit(f'BLACK|    Сертификат "{cert_name}": Не найден файл "cert.pem" или "cert.der" для импорта. Будет сгенерирован новый сертификат.')
                    data.pop('user_guid', None)
                    data.pop('subject', None)
                    data.pop('has_private_key', None)
                    data.pop('has_cert', None)
                    data.pop('has_csr', None)
                    data.pop('has_cert_chain', None)
                    data.pop('not_before', None)
                    data.pop('not_after', None)
                    data.pop('ca', None)
                    data.pop('keyUsage', None)
                    data.update(data.pop('issuer', None))

                    err, result = self.utm.new_certificate(data)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result}')
                        error = 1
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}')
                    else:
                        self.ngfw_data['certs'][cert_name] = result
                        self.stepChanged.emit(f'BLACK|       Создан новый сертификат "{cert_name}".')

                    if data['role'] in self.ngfw_data['cert_roles']:
                        self.stepChanged.emit(f'NOTE|          Сертификат "{cert_name}": Роль не назначена. Роль "{certs_role.get(data["role"], data["role"])}" уже используется в другом сертификате.')
                    else:
                        err, result = self.utm.update_certificate(self.ngfw_data['certs'][data['name']], {'role': data['role']})
                        if err:
                            self.stepChanged.emit(f'RED|       {result} [Cертификат "{cert_name}"]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|          Для сертификата "{cert_name}" установлена роль "{certs_role.get(data["role"], data["role"])}".')
                            self.ngfw_data['cert_roles'].add(data['role'])
                            new_cert_exists = True
                elif key_data or data['role'] in ("proxy_ca_chain", "proxy_ca_chain_root"):
                    if data['role'] in self.ngfw_data['cert_roles']:
                        self.stepChanged.emit(f'NOTE|    Сертификат "{cert_name}": Роль не будет назначена так как роль "{certs_role.get(data["role"], data["role"])}" уже используется в другом сертификате.')
                        data['role'] = 'none'
                    err, result = self.utm.add_certificate(data, cert_data, private_key=key_data)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Cертификат "{cert_name}" не импортирован]')
                        error = 1
                    else:
                        self.ngfw_data['certs'][cert_name] = result
                        self.ngfw_data['cert_roles'].add(data['role'])
                        self.stepChanged.emit(f'BLACK|    Сертификат "{cert_name}" импортирован. Установлена роль "{certs_role.get(data["role"], data["role"])}".')
                else:
                    self.stepChanged.emit(f'bRED|    Warning: Сертификат "{cert_name}" не импортирован так как не имеет приватного ключа.')
        if new_cert_exists:
            self.stepChanged.emit('NOTE|    ВНИМАНИЕ: Были созданы новые сертификаты. Необходимо заново импортировать их на клиентские устройства')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте сертификатов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт сертификатов завершён.')


    def import_general_settings(self, path):
        """Импортируем раздел 'UserGate/Настройки'"""
        self.import_ui(path)
        self.import_ntp_settings(path)
        self.import_proxy_port(path)
        self.import_modules(path)
        if 5 < self.utm.float_version < 7.1:
            self.stepChanged.emit('BLUE|Импорт SNMP Engine ID в раздел "UserGate/Настройки/Модули/SNMP Engine ID".')
            engine_path = os.path.join(self.config_path, 'Notifications/SNMPParameters')
            self.import_snmp_engine(engine_path)
        self.import_cache_settings(path)
        self.import_proxy_exceptions(path)
        self.import_web_portal_settings(path)
        self.import_upstream_proxy_settings(path)


    def import_ui(self, path):
        """Импортируем раздел 'UserGate/Настройки/Настройки интерфейса'"""
        json_file = os.path.join(path, 'config_settings_ui.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')

        params = {
            'ui_timezone': 'Часовой пояс',
            'ui_language': 'Язык интерфейса по умолчанию',
            'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
            'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/аутентификации',
            'api_session_lifetime': 'Таймер автоматическогозакрытия сессии',
            'endpoint_ssl_profile_id': 'Профиль SSL конечного устройства',
            'endpoint_certificate_id': 'Сертификат конечного устройства',
        }
        error = 0

        data.pop('webui_auth_mode', None)
        if self.utm.float_version < 7.1:
            data.pop('api_session_lifetime', None)
            data.pop('endpoint_ssl_profile_id', None)
            data.pop('endpoint_certificate_id', None)
        if self.utm.float_version == 5.0:
            data.pop('web_console_ssl_profile_id', None)
            data.pop('response_pages_ssl_profile_id', None)
        for key, value in data.items():
            if key in params:
                if key == 'web_console_ssl_profile_id':
                    try:
                        value = self.ngfw_data['ssl_profiles'][value]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                if key == 'response_pages_ssl_profile_id':
                    try:
                        value = self.ngfw_data['ssl_profiles'][value]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                if key == 'endpoint_ssl_profile_id':
                    try:
                        value = self.ngfw_data['ssl_profiles'][value]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                if key == 'endpoint_certificate_id':
                    try:
                        value = self.ngfw_data['certs'][value]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден сертификат "{err}" для "{params[key]}". Загрузите сертификаты и повторите попытку.')
                        error = 1
                        continue

            err, result = self.utm.set_settings_param(key, value)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{data[key]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Ошибка импорта настроек интерфейса.')
        else:
            self.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Настройки интерфейса".')


    def import_ntp_settings(self, path):
        """Импортируем настройки NTP"""
        json_file = os.path.join(path, 'config_ntp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')

        data.pop('utc_time', None)
        data.pop('ntp_synced', None)
        err, result = self.utm.add_ntp_config(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Ошибка импорта настроек NTP.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импорт настроек NTP завершён.')


    def import_proxy_port(self, path):
        """Импортируем раздел UserGate/Настройки/Модули/HTTP(S)-прокси порт"""
        json_file = os.path.join(path, 'config_proxy_port.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули/HTTP(S)-прокси порт".')

        err, result = self.utm.set_proxy_port(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Ошибка импорта HTTP(S)-прокси порта.')
            self.error = 1
        else:
            self.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт установлен в значение "{data}"')


    def import_modules(self, path):
        """Импортируем раздел 'UserGate/Настройки/Модули'"""
        json_file = os.path.join(path, 'config_settings_modules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули".')
        error = 0

        params = {
            'auth_captive': 'Домен Auth captive-портала',
            'logout_captive': 'Домен Logout captive-портала',
            'cert_captive': 'Домен Cert captive-портала',
            'block_page_domain': 'Домен страницы блокировки',
            'ftpclient_captive': 'FTP поверх HTTP домен',
            'ftp_proxy_enabled': 'FTP поверх HTTP',
            'tunnel_inspection_zone_config': 'Зона для инспектируемых туннелей',
            'lldp_config': 'Настройка LLDP'
        }
        if self.utm.float_version < 7.4:
            data.pop('cert_captive', None)
        if self.utm.float_version < 7.1:
            data.pop('tunnel_inspection_zone_config', None)
            data.pop('lldp_config', None)
        else:
            if 'tunnel_inspection_zone_config' in data:
                zone_name = data['tunnel_inspection_zone_config']['target_zone']
                data['tunnel_inspection_zone_config']['target_zone'] = self.ngfw_data['zones'].get(zone_name, 8)

        for key, value in data.items():
            err, result = self.utm.set_settings_param(key, value)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{value}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Ошибка импорта настроек модулей.')
        else:
            self.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Модули".')


    def import_cache_settings(self, path):
        """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
        json_file = os.path.join(path, 'config_proxy_settings.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP".')
        error = 0

        if self.utm.float_version < 7:
            data.pop('add_via_enabled', None)
            data.pop('add_forwarded_enabled', None)
            data.pop('smode_enabled', None)
            data.pop('module_l7_enabled', None)
            data.pop('module_idps_enabled', None)
            data.pop('module_sip_enabled', None)
            data.pop('module_h323_enabled', None)
            data.pop('module_sunrpc_enabled', None)
            data.pop('module_ftp_alg_enabled', None)
            data.pop('module_tftp_enabled', None)
            data.pop('legacy_ssl_enabled', None)
            data.pop('http_connection_timeout', None)
            data.pop('http_loading_timeout', None)
            data.pop('icap_wait_timeout', None)
        if self.utm.float_version == 7.0:
            data.pop('module_tftp_enabled', None)
        for key, value in data.items():
            err, result = self.utm.set_settings_param(key, value)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Параметр "{key}" установлен в значение "{value}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Ошибка импорта настроек кэширования HTTP.')
        else:
            self.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Настройки кэширования HTTP".')


    def import_proxy_exceptions(self, path):
        """Импортируем раздел UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования"""
        json_file = os.path.join(path, 'config_proxy_exceptions.json')
        err, exceptions = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования".')
        error = 0

        err, nlist = self.utm.get_nlist_list('httpcwl')
        for item in exceptions:
            err, result = self.utm.add_nlist_item(nlist['id'], item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
            elif err == 2:
                self.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
            else:
                self.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Ошибка импорта исключений кэширования HTTP.')
        else:
            self.stepChanged.emit('GREEN|    Исключения кэширования HTTP импортированы".')


    def import_web_portal_settings(self, path):
        """Импортируем раздел 'UserGate/Настройки/Веб-портал'"""
        json_file = os.path.join(path, 'config_web_portal.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Веб-портал".')
        error = 0
        error_message = '    Произошла ошибка при импорте настроек Веб-портала.'

        if 'list_templates' not in self.ngfw_data:
            if self.get_templates_list():                           # Устанавливаем атрибут self.ngfw_data['list_templates']
                self.stepChanged.emit(f'ORANGE|{error_message}')
                return
        list_templates = self.ngfw_data['list_templates']

        if self.utm.float_version >= 7.1:
            if 'client_certificate_profiles' not in self.ngfw_data:
                if self.get_client_certificate_profiles():          # Устанавливаем атрибут self.ngfw_data['client_certificate_profiles']
                    self.stepChanged.emit(f'ORANGE|{error_message}')
                    return
            client_certificate_profiles = self.ngfw_data['client_certificate_profiles']

        if self.utm.float_version >= 6:
            try:
                data['ssl_profile_id'] = self.ngfw_data['ssl_profiles'][data['ssl_profile_id']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.\n{error_message}')
                self.error = 1
                return
        else:
            data.pop('ssl_profile_id', None)

        if self.utm.float_version >= 7.1:
            data['client_certificate_profile_id'] = client_certificate_profiles.get(data['client_certificate_profile_id'], 0)
            if not data['client_certificate_profile_id']:
                data['cert_auth_enabled'] = False
        else:
            data.pop('client_certificate_profile_id', None)

        try:
            data['user_auth_profile_id'] = self.ngfw_data['auth_profiles'][data['user_auth_profile_id']]
        except KeyError as err:
            self.stepChanged.emit(f'RED|    Error: Не найден профиль аутентификации {err}. Загрузите профили аутентификации и повторите попытку.\n{error_message}')
            self.error = 1
            return
        if data['certificate_id']:
            try:
                data['certificate_id'] = self.ngfw_data['certs'][data['certificate_id']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден сертификат {err}. Укажите сертификат вручную или загрузите сертификаты и повторите попытку.')
                data['certificate_id'] = -1
                error = 1
        else:
            data['certificate_id'] = -1

        data['proxy_portal_template_id'] = list_templates.get(data['proxy_portal_template_id'], -1)
        data['proxy_portal_login_template_id'] = list_templates.get(data['proxy_portal_login_template_id'], -1)

        err, result = self.utm.set_proxyportal_config(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1

        if error:
            self.stepChanged.emit(error_message)
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Веб-портал".')


    def import_upstream_proxy_settings(self, path):
        """Импортируем настройки вышестоящего прокси. Только для версии с 7.1 по 7.3."""
        if 7.1 >= self.utm.float_version < 7.4:
            json_file = os.path.join(path, 'upstream_proxy_settings.json')
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                return

            self.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

            err, result = self.utm.set_upstream_proxy_settings(data)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек вышестоящего прокси.')
                self.error = 1
            else:
                self.stepChanged.emit('GREEN|    Импорт настроек вышестоящего прокси завершён.')


    def import_users_certificate_profiles(self, path):
        """Импортируем профили пользовательских сертификатов. Только для версии 7.1 и выше."""
        json_file = os.path.join(path, 'users_certificate_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Профили пользовательских сертификатов".')

        if 'client_certificate_profiles' not in self.ngfw_data:
            if self.get_client_certificate_profiles():          # Устанавливаем атрибут self.ngfw_data['client_certificate_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пользовательских сертификатов!')
                return
        error = 0

        for item in data:
            item['ca_certificates'] = [self.ngfw_data['certs'][x] for x in item['ca_certificates']]

            err, result = self.utm.add_client_certificate_profile(item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
            elif err == 2:
                self.stepChanged.emit(f'GRAY|    {result}')
            else:
                self.stepChanged.emit(f'BLACK|    Импортирован профиль "{item["name"]}".')
                self.ngfw_data['client_certificate_profiles'][item['name']] = result

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пользовательских сертификатов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей пользовательских сертификатов завершён.')


    def import_admins(self, path):
        """Импортируем профили администраторов и список администраторов."""
        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Администраторы".')
        error = 0

        # Импортируем настройки аутентификации.
        json_file = os.path.join(path, 'auth_settings.json')
        err, auth_config = self.read_json_file(json_file, mode=2)
        if err:
            return
        err, result = self.utm.set_admin_config(auth_config)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Настройки аутентификации не импортированы.')
            error = 1
        else:
            self.stepChanged.emit('BLACK|    Импортированы настройки аутентификации.')

        # Импортируем профили администраторов.
        err, result = self.utm.get_admins_profiles()
        if err:
            self.stepChanged.emit('RED|    {result}\n    Произошла ошибка при импорте профили администраторов.')
            self.error = 1
            return
        admin_profiles = {x['name']: x['id'] for x in result}

        json_file = os.path.join(path, 'administrator_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in admin_profiles:
                err, result = self.utm.update_admin_profile(admin_profiles[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Профиль "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Профиль "{item["name"]}" уже существует - Updated!')
            else:
                err, result = self.utm.add_admin_profile(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Профиль администратора "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    admin_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль администратора "{item["name"]}" импортирован.')

        # Импортируем администраторов.
        err, result = self.utm.get_admins()
        if err:
            self.stepChanged.emit('RED|    {result}\n    Произошла ошибка при импорте администраторов.')
            self.error = 1
            return
        admins = {x['login']: x['id'] for x in result}
        admins_exists = False

        json_file = os.path.join(path, 'administrators_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return
        for item in data:
            if item['is_root']:
                continue
            if item['type'] == 'local':
                item['login'] = self.get_transformed_userlogin(item['login'])
                item['password'] = 'Q12345678@'
                item['enabled'] = False
            if item['type'] in ['ldap_user', 'ldap_group']:
                if item['type'] == 'ldap_user':
                    ldap_domain, _, login_name = item['login'].partition("\\")
                else:
                    tmp_arr1 = [x.split('=') for x in item['login'].split(',')]
                    tmp_arr2 = [b for a, b in tmp_arr1 if a in ('dc', 'DC')]
                    ldap_domain = '.'.join(tmp_arr2)
                    login_name = tmp_arr1[0][1] if tmp_arr1[0][0] == 'CN' else None
                if login_name:
                    if item['type'] == 'ldap_user':
                        err, result = self.utm.get_ldap_user_guid(ldap_domain, login_name)
                    else:
                        err, result = self.utm.get_ldap_group_guid(ldap_domain, login_name)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}\n       Администратор "{item["login"]}" не импортирован.')
                        error = 1
                        continue
                    elif not result:
                        self.stepChanged.emit(f'RED|    Error: [Администратор "{item["login"]}" не импортирован] Нет такого пользователя в домене или LDAP-коннектора для домена "{ldap_domain}".')
                        error = 1
                        continue
                    else:
                        item['guid'] = result

            item['profile_id'] = admin_profiles[item['profile_id']]
            if item['type'] == 'auth_profile':
                try:
                    item['user_auth_profile_id'] = self.ngfw_data['auth_profiles'][item['user_auth_profile_id']]
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Администратор "{item["login"]}" не импортирован] Нет найден профиль аутентификации "{item["user_auth_profile_id"]}".')
                    error = 1
                    continue

            if item['login'] in admins:
                self.stepChanged.emit(f'GRAY|    Администратор "{item["login"]}" уже существует.')
            else:
                err, result = self.utm.add_admin(item)
                if err:
                    self.stepChanged.emit('RED|    {result}  [Администратор "{item["login"]}" не импортирован]')
                    error = 1
                else:
                    admins[item['login']] = result
                    self.stepChanged.emit(f'BLACK|    Администратор "{item["login"]}" импортирован.')
                    admins_exists = Fraue
        if admins_exists:
            self.stepChanged.emit('NOTE|    Импортированным локальным администраторам установлен статус "disabled".  Активируйте их и установите пароль.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте раздела "UserGate/Администраторы".')
        else:
            self.stepChanged.emit('GREEN|    Импорт раздела "UserGate/Администраторы" завершён.')


    #----------------------------------------------- Сеть -----------------------------------------------
    def import_zones(self, path):
        """Импортируем зоны на NGFW, если они есть."""
        json_file = os.path.join(path, 'config_zones.json')
        err, zones = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')
        error = 0

        for zone in zones:
            error, zone['name'] = self.get_transformed_name(zone['name'], err=error, descr='Имя зоны')

            current_zone = Zone(self, zone)
            zone['services_access'] = current_zone.services_access
            zone['enable_antispoof'] = current_zone.enable_antispoof
            zone['antispoof_invert'] = current_zone.antispoof_invert
            zone['networks'] = current_zone.networks

            if self.utm.float_version < 7.1:
                zone.pop('sessions_limit_enabled', None)
                zone.pop('sessions_limit_threshold', None)
                zone.pop('sessions_limit_exclusions', None)
            else:
                zone['sessions_limit_enabled'] = current_zone.sessions_limit_enabled
                zone['sessions_limit_exclusions'] = current_zone.sessions_limit_exclusions

            zone['description'] = current_zone.description
            error = current_zone.error

            err, result = self.utm.add_zone(zone)
            if err == 1:
                error = 1
                self.stepChanged.emit(f'RED|    {result}. Зона "{zone["name"]}" не импортирована.')
            elif err == 2:
                self.stepChanged.emit(f'uGRAY|    {result}')
                err, result2 = self.utm.update_zone(self.ngfw_data['zones'][zone['name']], zone)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result2}')
                elif err == 2:
                    self.stepChanged.emit(f'uGRAY|       {result2}')
                else:
                    self.stepChanged.emit(f'BLACK|       Зона "{zone["name"]}" обновлена.')
            else:
                self.ngfw_data['zones'][zone["name"]] = result
                self.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
        else:
            self.stepChanged.emit('GREEN|    Импорт зон завершён.')


    def import_interfaces(self, path):
        if not self.node_name:
            return

        json_file = os.path.join(path, 'config_interfaces.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт интерфейсов "TUNNEL", "VLAN", "BOND", "BRIDGE", "VPN" в раздел "Сеть/Интерфейсы".')
        if isinstance(self.ngfw_vlans, int):
            if self.ngfw_vlans == 1:
                self.stepChanged.emit(self.new_vlans)
                self.error = 1
                return

        # Получаем интерфейсы только нужного узла кластера.
        if self.node_name != 'ALL':     # Конфигурация получена не из universal_converter или из новой версии ug_ngfw_converter.
            data = [item for item in data if item['node_name'] in (self.node_name, 'cluster')]

        kinds = {item['kind'] for item in data}
        if kinds.isdisjoint({'tunnel', 'vlan', 'vpn', 'bond', 'bridge'}):
            self.stepChanged.emit('GRAY|    Нет интерфейсов "TUNNEL", "VLAN", "VPN", "BOND", "BRIDGE" для импорта.')
            return

        err, result = self.utm.get_netflow_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте интерфейсов.')
            self.error = 1
            return
        list_netflow = {x['name']: x['id'] for x in result}
        list_netflow['undefined'] = 'undefined'

        list_lldp = {}
        if self.utm.float_version >= 7:
            err, result = self.utm.get_lldp_profiles_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте интерфейсов.')
                self.error = 1
                return
            list_lldp = {x['name']: x['id'] for x in result}
            list_lldp['undefined'] = 'undefined'

        if 'tunnel' in kinds:
            self.import_ipip_interfaces(data)
        if kinds.intersection({'bond', 'bridge'}):
            self.import_bonds(data, list_netflow, list_lldp)
        if 'vlan' in kinds:
            self.import_vlans(data, list_netflow, list_lldp)
        if 'vpn' in kinds:
            self.import_vpn_interfaces(data, list_netflow, list_lldp)

        # Устанавливаем тэги на интерфейсы
        tag_relations = {}
        if self.utm.float_version >= 7.3:
            for item in data:
                if 'tags' in item and 'id' in item:
                    try:
                        tag_relations[f'{item["id"]}:{self.utm.node_name}'] = item['tags']
                    except KeyError:
                        print(item['name'])
        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'interfaces'):
                error = 1


    def import_ipip_interfaces(self, data):
        """Импортируем интерфесы IP-IP."""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов GRE/IPIP/VXLAN в раздел "Сеть/Интерфейсы".')
        error = 0

        for item in data:
            if 'kind' in item and item['kind'] == 'tunnel' and item['name'].startswith('gre'):
                item.pop('id', None)    # Это должно быть здесь для корректного добавления тэгов.
                if item['name'] in self.ngfw_ifaces:    # Проверяем что на выбранном узле кластера нет такого тоннеля.
                    self.stepChanged.emit(f'GRAY|       Интерфейс "{item["name"]}" уже существует на текущем узле кластера.')
                    continue

                item.pop('master', None)
                item.pop('mac', None)
                item.pop('node_name', None)
                if item.get('config_on_device', False):  # не импортируем если конфиг получен из МС и параметр True.
                    continue

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.ngfw_data['zones'][item['zone_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'bRED|       Error: Для интерфейса "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                err, result = self.utm.add_interface_tunnel(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["tunnel"]["mode"]} - {item["name"]} не импортирован]')
                    error = 1
                elif err == 2:
                    self.stepChanged.emit(f'rNOTE|       {result} [Интерфейс {item["tunnel"]["mode"]} - {item["name"]} не импортирован]')
                else:
                    self.ngfw_ifaces[item['name']] = item['kind']
                    item['id'] = result
                    self.stepChanged.emit(f'BLACK|       Добавлен интерфейс {item["tunnel"]["mode"]} - {item["name"]}.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте интерфейсов GRE/IPIP/VXLAN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов GRE/IPIP/VXLAN завершён.')


    def import_bonds(self, data, list_netflow, list_lldp):
        """Импортируем интерфесы Bond, Bridge. Нельзя использовать интерфейсы Management и slave."""
        self.stepChanged.emit('BLUE|    Импорт агрегированных интерфейсов в раздел "Сеть/Интерфейсы".')
        error = 0
        if not self.adapter_ports:
            self.stepChanged.emit('NOTE|       Нет свободных адаптеров для импорта агрегированных интерфейсов.')
            # Это должно быть здесь для корректного добавления тэгов.
            for item in data:
                if 'kind' in item and item['kind'] in ('bond', 'bridge'):
                    item.pop('id', None)
            return

        for item in data:
            if 'kind' in item and item['kind'] in ('bond', 'bridge'):
                item.pop('id', None)    # Это должно быть здесь для корректного добавления тэгов.
                if item['name'] in self.ngfw_ifaces:    # Проверяем что на выбранном узле кластера нет такого интерфейса.
                    self.stepChanged.emit(f'GRAY|       Интерфейс "{item["name"]}" уже существует на текущем узле кластера.')
                    continue
                item.pop('mac', None)
                item.pop('master', None)
                item.pop('running', None)
                item.pop('node_name', None)
                
                if item['kind'] == 'bond':
                    new_slaves = []
                    for port in item['bonding']['slaves']:
                        if port in self.adapter_ports:
                            self.adapter_ports.remove(port)
                            new_slaves.append(port)
                        else:
                            self.stepChanged.emit(f'bRED|       Warning: [bond "{item["name"]}"] порт "{port}" занят или не существует на NGFW/DCFW.')
                            error = 1
                    if not new_slaves:
                        self.stepChanged.emit(f'RED|       Error: [bond "{item["name"]}"] Нет интерфейсов. Bond не импортирован')
                        error = 1
                        continue
                    item['bonding']['slaves'] = new_slaves
                elif item['kind'] == 'bridge':
                    new_slaves = []
                    for port in item['bridging']['ports']:
                        if port in self.adapter_ports:
                            self.adapter_ports.remove(port)
                            new_slaves.append(port)
                        else:
                            self.stepChanged.emit(f'bRED|       Warning: [bridge "{item["name"]}"] порт "{port}" занят или не существует на NGFW/DCFW.')
                            error = 1
                    if not new_slaves or len(new_slaves) < 2:
                        self.stepChanged.emit(f'RED|       Error: [bridge "{item["name"]}"] Нет свободных интерфейсов. Bridge не импортирован')
                        error = 1
                        continue
                    item['bridging']['ports'] = new_slaves

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.ngfw_data['zones'][item['zone_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: Для интерфейса "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                if self.utm.float_version < 7.1:
                    item.pop('ifalias', None)
                    item.pop('flow_control', None)
                if self.utm.float_version < 7.0:
                    item.pop('lldp_profile', None)
                else:
                    try:
                        item['lldp_profile'] = list_lldp[item['lldp_profile']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|       Error: Для интерфейса "{item["name"]}" не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили lldp.')
                        item['lldp_profile'] = 'undefined'
                        error = 1
                try:
                    item['netflow_profile'] = list_netflow[item['netflow_profile']]
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: Для интерфейса "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                if item['kind'] == 'bond':
#                    item.pop('kind', None)
                    err, result = self.utm.add_interface_bond(item)
                elif item['kind'] == 'bridge':
#                    item.pop('kind', None)
                    err, result = self.utm.add_interface_bridge(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                    error = 1
                elif err == 2:
                    self.stepChanged.emit(f'rNOTE|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                else:
                    self.ngfw_ifaces[item['name']] = item['kind']
                    item['id'] = result
                    self.stepChanged.emit(f'BLACK|       Интерфейс "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте агрегированных интерфейсов.')
        else:
            self.stepChanged.emit('GREEN|       Импорт агрегированных интерфейсов завершён.')


    def import_vlans(self, data, list_netflow, list_lldp):
        """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
        self.stepChanged.emit('BLUE|    Импорт VLAN в раздел "Сеть/Интерфейсы".')
        error = 0
        if isinstance(self.ngfw_vlans, int):
            self.stepChanged.emit(self.new_vlans)
            return

        for item in data:
            if 'kind' in item and item['kind'] == 'vlan':
                item.pop('id', None)    # Это должно быть здесь для корректного добавления тэгов.
                if item["vlan_id"] in self.ngfw_vlans:    # Проверяем что на выбранном узле кластера нет такого VLAN.
                    self.stepChanged.emit(f'GRAY|       VLAN {item["vlan_id"]} уже существует на порту {self.ngfw_vlans[item["vlan_id"]]} на текущем узле кластера.')
                    continue
                current_port = self.new_vlans[item['vlan_id']]['port']
                current_zone = self.new_vlans[item['vlan_id']]['zone']
                if current_port == "Undefined":
                    self.stepChanged.emit(f"rNOTE|       VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                    continue
                item['link'] = current_port
                item['name'] = f'{current_port}.{item["vlan_id"]}'
                item['enabled'] = False      # Отключаем интерфейс. После импорта надо включить руками.
                if item['mode'] == 'keep':   # Если конфиг получен из МС
                    item['mode'] = 'manual'

                item.pop('master', None)      # удаляем readonly поле
                item.pop('mac', None)
                item.pop('node_name', None)

                if item.get('config_on_device', False):  # не импортируем если конфиг получен из МС и настраивается на устройстве.
                    continue

                if current_zone != "Undefined":
                    try:
                        item['zone_id'] = self.ngfw_data['zones'][current_zone]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: Не найдена зона "{err}" для VLAN "{item["name"]}". Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1
                else:
                    item['zone_id'] = 0

                if self.utm.float_version < 7.1:
                    item.pop('ifalias', None)
                    item.pop('flow_control', None)
                if self.utm.float_version < 7.0:
                    item.pop('dhcp_default_gateway', None)
                    item.pop('lldp_profile', None)
                else:
                    try:
                        item['lldp_profile'] = list_lldp[item['lldp_profile']]
                    except KeyError:
                        self.stepChanged.emit(f'bRED|       Для VLAN "{item["name"]}" не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили lldp.')
                        item['lldp_profile'] = 'undefined'
                try:
                    item['netflow_profile'] = list_netflow[item['netflow_profile']]
                except KeyError:
                    self.stepChanged.emit(f'bRED|       Для VLAN "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow.')
                    item['netflow_profile'] = 'undefined'

#                print(json.dumps(item, indent=4), '\n')

                err, result = self.utm.add_interface_vlan(item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    self.ngfw_vlans[item['vlan_id']] = current_port
                    self.ngfw_ifaces[item['name']] = item['kind']
                    item['id'] = result
                    self.stepChanged.emit(f'BLACK|       Интерфейс VLAN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте интерфейса VLAN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов VLAN завершён.')


    def import_vpn_interfaces(self, data, list_netflow, list_lldp):
        """Импортируем интерфейсы VPN"""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов VPN в раздел "Сеть/Интерфейсы".')
        error = 0
    
        for item in data:
            if 'kind' in item and item['kind'] == 'vpn':
                item.pop('id', None)    # Это должно быть здесь для корректного добавления тэгов.
                if item['name'] in self.ngfw_ifaces:    # Проверяем что на кластере нет такого интерфейса.
                    self.stepChanged.emit(f'GRAY|       Кластерный интерфейс VPN {item["name"]} уже существует.')
                    continue

                item['node_name'] = 'cluster'
                item.pop('mac', None)
                item.pop('master', None)
                item.pop('running', None)

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.ngfw_data['zones'][item['zone_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: Для интерфейса "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                if self.utm.float_version < 7.1:
                    item.pop('ifalias', None)
                    item.pop('flow_control', None)
                if self.utm.float_version < 7.0:
                    item.pop('lldp_profile', None)
                else:
                    try:
                        item['lldp_profile'] = list_lldp[item['lldp_profile']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|       Error: Для интерфейса "{item["name"]}" не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили lldp.')
                        item['lldp_profile'] = 'undefined'
                        error = 1
                try:
                    item['netflow_profile'] = list_netflow[item['netflow_profile']]
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: Для интерфейса "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_interface_vpn(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                    error = 1
                elif err == 2:
                    self.stepChanged.emit(f'rNOTE|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                else:
                    self.ngfw_ifaces[item['name']] = item['kind']
                    item['id'] = result
                    self.stepChanged.emit(f'BLACK|       Интерфейс VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте интерфейса VPN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов VPN завершён.')


    def import_gateways(self, path):
        self.import_gateways_list(path)
        self.import_gateway_failover(path)


    def import_gateways_list(self, path):
        """Импортируем список шлюзов"""
        json_file = os.path.join(path, 'config_gateways.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт шлюзов в раздел "Сеть/Шлюзы".')
        self.stepChanged.emit('LBLUE|    После импорта шлюзы будут в не активном состоянии. Необходимо проверить и включить нужные.')
        error = 0

        err, result = self.utm.get_gateways_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте шлюзов.')
            self.error = 1
            return
        gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}
        gateways_read_only = {x.get('name', x['ipv4']): x.get('is_automatic', False) for x in result}

        if self.utm.float_version >= 6:
            err, result = self.utm.get_routes_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте шлюзов.')
                self.error = 1
                return
            vrf_list = [x['name'] for x in result]

        for item in data:
            if self.utm.float_version >= 6:
                if item['vrf'] not in vrf_list:
                    err, result = self.add_empty_vrf(item['vrf'])
                    if err:
                        message = f'Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.'
                        self.stepChanged.emit(f'RED|    {result}\n    {message}')
                        item['vrf'] = 'default'
                        item['default'] = False
                    else:
                        self.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}".')
                        self.sleep(3)   # Задержка, т.к. vrf долго применяет конфигурацию.
            else:
                item['iface'] = 'undefined'
                item.pop('is_automatic', None)
                item.pop('vrf', None)
            item.pop('node_name', None)         # удаляем если конфиг получен из МС
            item.pop('mac', None)
            
            if item['name'] in gateways_list:
                if not gateways_read_only[item['name']]:
                    err, result = self.utm.update_gateway(gateways_list[item['name']], item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Шлюз "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" уже существует - Updated!')
                else:
                    self.stepChanged.emit(f'NOTE|    Шлюз "{item["name"]}" - объект только для чтения. Not updated!')
            else:
                item['enabled'] = False
                err, result = self.utm.add_gateway(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Шлюз "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт шлюзов завершён.')


    def import_gateway_failover(self, path):
        """Импортируем настройки проверки сети"""
        json_file = os.path.join(path, 'config_gateway_failover.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек проверки сети раздела "Сеть/Шлюзы/Проверка сети".')

        err, result = self.utm.set_gateway_failover(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при обновлении настроек проверки сети.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Настройки проверки сети обновлены.')


    def import_dhcp_subnets(self, path):
        """Импортируем настойки DHCP"""
        print('\n', self.node_name)
        if not self.node_name:
            return

        self.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
        print('\nself.ngfw_ifaces:', self.ngfw_ifaces)

        print('\nself.ngfw_ports:', self.ngfw_ports)
        print('self.dhcp_settings:', self.dhcp_settings)

        if isinstance(self.ngfw_ports, int):
            self.stepChanged.emit(self.dhcp_settings)
            if self.ngfw_ports == 1:
                self.error = 1
            return
        error = 0

        # Получаем DHCP-subnets текущего узла кластера.
        err, result = self.utm.get_dhcp_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек DHCP.')
            self.error = 1
            return
        ngfw_dhcp_subnets = [x['name'] for x in result if item['node_name'] == self.utm.node_name]

        for item in self.dhcp_settings:
            item.pop('node_name', None)
            if item['iface_id'] == 'Undefined':
                self.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
                continue
            if item['name'] in ngfw_dhcp_subnets:
                self.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как уже существует на этом узле кластера.')
                continue
            if item['iface_id'] not in self.ngfw_ifaces:
                self.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт: {item["iface_id"]} не существует на этом узле кластера.')
                continue

            err, result = self.utm.add_dhcp_subnet(item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}   [subnet "{item["name"]}" не импортирован]')
                error = 1
            elif err == 2:
                self.stepChanged.emit(f'NOTE|    {result}')
            else:
                self.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован.')
                ngfw_dhcp_subnets.append(item['name'])
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP!')
        else:
            self.stepChanged.emit(f'GREEN|    Импорт настроек DHCP на узел кластера "{self.utm.node_name}" завершён.')


    def import_dns_config(self, path):
        """Импортируем настройки DNS"""
        self.import_dns_servers(path)
        self.import_dns_proxy(path)
        self.import_dns_rules(path)
        self.import_dns_static(path)


    def import_dns_servers(self, path):
        """Импортируем список системных DNS серверов"""
        json_file = os.path.join(path, 'config_dns_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт системных DNS серверов раздела "Сеть/DNS/Системные DNS-серверы".')
        error = 0
        for item in data:
            item.pop('id', None)
            item.pop('is_bad', None)
            err, result = self.utm.add_dns_server(item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result} [DNS сервер "{item["dns"]}" не импортирован]')
                error = 1
            elif err == 2:
                self.stepChanged.emit(f'GRAY|    {result}')
            else:
                self.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" импортирован.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте системных DNS-серверов!')
        else:
            self.stepChanged.emit('GREEN|    Импорт системных DNS-серверов завершён.')


    def import_dns_proxy(self, path):
        """Импортируем настройки DNS прокси"""
        json_file = os.path.join(path, 'config_dns_proxy.json')
        err, result = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек DNS-прокси раздела "Сеть/DNS/Настройки DNS-прокси".')
        error = 0
        if self.utm.float_version < 6.0:
            result.pop('dns_receive_timeout', None)
            result.pop('dns_max_attempts', None)
        for key, value in result.items():
            err, result = self.utm.set_settings_param(key, value)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DNS-прокси!')
        else:
            self.stepChanged.emit('GREEN|    Импорт настроек DNS-прокси завершён.')


    def import_dns_rules(self, path):
        """Импортируем список правил DNS прокси"""
        json_file = os.path.join(path, 'config_dns_rules.json')
        err, rules = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил DNS-прокси раздела "Сеть/DNS/Правила DNS".')
        error = 0
        dns_rules = [x['name'] for x in self.utm._server.v1.dns.rules.list(self.utm._auth_token, 0, 1000, {})['items']]

        for item in rules:
            item.pop('position_layer', None)    # Удаляем если экспорт был из шаблона МС.
            if self.utm.float_version >= 6.0:
                item['position'] = 'last'

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in dns_rules:
                self.stepChanged.emit(f'GRAY|    Правило DNS прокси "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_dns_rule(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Правило DNS прокси "{item["name"]}" не импортировано]')
                    error = 1
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    self.stepChanged.emit(f'BLACK|    Правило DNS прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил DNS-прокси!')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил DNS-прокси завершён.')


    def import_dns_static(self, path):
        """Импортируем статические записи DNS прокси"""
        json_file = os.path.join(path, 'config_dns_static.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт статических записей DNS-прокси раздела "Сеть/DNS/Статические записи".')
        error = 0

        for item in data:
            err, result = self.utm.add_dns_static_record(item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result} [Статическая запись DNS "{item["name"]}" не импортирована]')
                error = 1
            elif err == 2:
                self.stepChanged.emit(f'GRAY|    {result}')
            else:
                self.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS-прокси!')
        else:
            self.stepChanged.emit('GREEN|    Импорт статических записей DNS-прокси завершён.')

    
    def import_vrf(self, path):
        """Импортируем список виртуальных маршрутизаторов"""
        json_file = os.path.join(path, 'config_vrf.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
        message = (
            '    Добавляемые маршруты будут в не активном состоянии. Необходимо будет проверить маршрутизацию и включить их.\n'
            '    Если вы используете BGP, по окончании импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.'
        )
        self.stepChanged.emit(f'LBLUE|{message}')
        error = 0

        err, result = self.utm.get_interfaces_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте виртуальных маршрутизаторов.')
            self.error = 1
            return
        ngfw_ifaces = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        err, result = self.utm.get_routes_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте виртуальных маршрутизаторов.')
            self.error = 1
            return
        virt_routes = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        if self.utm.float_version >= 7.1:
            err, result = self.utm.get_bfd_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте виртуальных маршрутизаторов.')
                self.error = 1
                return
            bfd_profiles = {x['name']: x['id'] for x in result}
            bfd_profiles[-1] = -1

        vrfnames = []
        for item in data:
            if item['name'] in vrfnames:
                self.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как VRF с таким именем уже был импортирован выше.')
                continue
            else:
                vrfnames.append(item['name'])
            item.pop('node_name', None)         # удаляем если конфиг получен из МС
        
            new_routes = {}
            for x in item['routes']:
                x['enabled'] = False
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя route')
                if x['name'] in new_routes:
                    self.stepChanged.emit(f'bRED|    Warning: [VRF "{item["name"]}"] Дубликат route "{x["name"]}" удалён.')
                    continue
                if x['ifname'] != 'undefined':
                    if x['ifname'] not in ngfw_ifaces:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс "{x["ifname"]}" удалён из статического маршрута "{x["name"]}" так как отсутствует на NGFW.')
                        x['ifname'] = 'undefined'
                        error = 1
                new_routes[x['name']] = x
            item['routes'] = list(new_routes.values())

            if item['ospf']:
                if not item['ospf']['enabled'] and not item['ospf']['router_id']:
                    item['ospf'] = {}
                else:
                    item['ospf']['enabled'] = False
                    ids = set()
                    new_interfaces = []

                    # Переделываем item['ospf'] для версии 6.1.9
                    if self.utm.float_version < 7.3:
                        item['ospf'].pop('routemaps', None)
                        item['ospf']['metric'] = item['ospf']['default_originate']['metric']
                        item['ospf']['default_originate'] = item['ospf']['default_originate']['enabled']
                        new_redistribute = []
                        for x in item['ospf']['redistribute']:
                            new_redistribute.append(x['kind'])
                        item['ospf']['redistribute'] = new_redistribute

                    for x in item['ospf']['interfaces']:
                        if x['iface_id'] not in ngfw_ifaces:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс OSPF "{x["iface_id"]}" удалён из настроек OSPF так как отсутствует на NGFW.')
                            ids.add(x['id'])
                            error = 1
                            continue
                        if item['name'] != 'default' and x['iface_id'] not in item['interfaces']:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс OSPF "{x["iface_id"]}" удалён из настроек OSPF так как отсутствует в этом VRF.')
                            ids.add(x['id'])
                            error = 1
                        else:
                            if self.utm.float_version < 7.1:
                                x.pop('bfd_profile', None)
                                x.pop('network_type', None)
                                x.pop('is_passive', None)
                            else:
                                x['network_type'] = x.get('network_type', '')
                                x['is_passive'] = x.get('is_passive', False)
                                try:
                                    x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                                except KeyError as err:
                                    self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Для OSPF не найден профиль BFD {err}. Установлено значение по умолчанию.')
                                    x['bfd_profile'] = -1
                                    error = 1
                            new_interfaces.append(x)
                    item['ospf']['interfaces'] = new_interfaces

                    new_areas = []
                    for area in item['ospf']['areas']:
                        if not self.check_ip(area['area_id']):
                            try:
                                area['area_id'] = int(area['area_id'])
                            except ValueError:
                                self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё не валидный идентификатор области.')
                                error = 1
                                continue
                        tmp = set(area['interfaces'])
                        if not (tmp - ids):
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё отсутствуют интерфейсы.')
                            error = 1
                        else:
                            new_areas.append(area)
                    item['ospf']['areas'] = new_areas

            if item['rip']:
                item['rip']['enabled'] = False
            if item['pimsm']:
                item['pimsm']['enabled'] = False
            if item['bgp']:
                item['bgp']['enabled'] = False
                if self.utm.float_version < 7:
                    item['bgp']['as_number'] = str(item['bgp']['as_number'])
                for x in item['bgp']['neighbors']:
                    x['filter_in'] = []
                    x['filter_out'] = []
                    x['routemap_in'] = []
                    x['routemap_out'] = []
                    if self.utm.float_version < 7:
                        x['remote_asn'] = str(x['remote_asn'])
                    if self.utm.float_version < 7.1:
                        x.pop('bfd_profile', None) 
                    else:
                        try:
                            x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                        except KeyError:
                            x['bfd_profile'] = -1
                            self.stepChanged.emit(f'rNOTE|    Не найден профиль BFD для VRF "{item["name"]}". Установлено значение по умолчанию.')

            if item['name'] in virt_routes:
                self.stepChanged.emit(f'GRAY|    Виртуальный маршрутизатор "{item["name"]}" уже существует.')
                err, result = self.utm.update_vrf(virt_routes[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [vrf: "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|       Виртуальный маршрутизатор "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_vrf(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [vrf: "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт виртуальных маршрутизаторов завершён.')


    def import_wccp_rules(self, path):
        """Импортируем список правил WCCP"""
        json_file = os.path.join(path, 'config_wccp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return
        error = 0

        self.stepChanged.emit('BLUE|Импорт правил WCCP в раздел "Сеть/WCCP".')
        err, result = self.utm.get_wccp_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил WCCP.')
            self.error = 1
            return
        wccp_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('cc_network_devices', None)    # Если конфиг экспортирован с МС.
            item.pop('cc_network_devices_negate', None)
            if self.utm.float_version < 7:
                item['ports'] = [str(x) for x in item['ports']]
            if self.utm.float_version == 7.0:
                item['mask_value'] = ""
            if item['routers']:
                routers = []
                for x in item['routers']:
                    if x[0] == 'list_id':
                        try:
                            x[1] = self.ngfw_data['ip_lists'][x[1]]
                        except KeyError as err:
                            self.stepChanged.emit(f'ORANGE|    Warning: Не найден список {err} для правила "{item["name"]}". Загрузите списки IP-адресов и повторите попытку.')
                            continue
                    routers.append(x)
                item['routers'] = routers

            if item['name'] in wccp_rules:
                self.stepChanged.emit(f'NOTE|    Правило WCCP "{item["name"]}" уже существует.')
                if self.utm.float_version >= 6:
                    err, result = self.utm.update_wccp_rule(wccp_rules[item['name']], item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}')
                        error = 1
                    else:
                        self.stepChanged.emit(f'NOTE|       Правило WCCP "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_wccp_rule(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Правило WCCP "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил WCCP завершён.')


    #-------------------------------------- Пользователи и устройства ---------------------------------------------
    def import_local_groups(self, path):
        """Импортируем список локальных групп пользователей"""
        json_file = os.path.join(path, 'config_groups.json')
        err, groups = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
        error = 0

        for item in groups:
            users = item.pop('users')
            # В версии 5 API добавления группы не проверяет что группа уже существует.
            if item['name'] in self.ngfw_data['local_groups']:
                self.stepChanged.emit(f'GRAY|    Группа "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_group(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Локальная группа "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что группа уже существует.
                else:
                    self.ngfw_data['local_groups'][item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Локальная группа "{item["name"]}" импортирована.')

            # В версии 5 в группах нет доменных пользователей.
            if self.utm.float_version <= 6:
                continue
            # Добавляем доменных пользователей в группу.
            for user_name in users:
                user_array = user_name.split(' ')
                if len(user_array) > 1 and ('\\' in user_array[1]):
                    domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                    err1, result1 = self.utm.get_ldap_user_guid(domain, name)
                    if err1:
                        self.stepChanged.emit(f'RED|       {result1} [Не удалось получить GUID пользователя {user_name} из домена {domain}]')
                        error = 1
                        break
                    elif not result1:
                        message = (
                            f'    Нет LDAP-коннектора для домена "{domain}". Доменные пользователи не импортированы в группу "{item["name"]}".\n'
                            f'    Импортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.'
                        )
                        self.stepChanged.emit(f'bRED|{message}')
                        break
                    err2, result2 = self.utm.add_user_in_group(self.ngfw_data['local_groups'][item['name']], result1)
                    if err2:
                        self.stepChanged.emit(f'RED|       {result2}  [Пользователь "{user_name}" не добавлен в группу "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Ошибка импорта локальных групп пользователей!')
        else:
            self.stepChanged.emit('GREEN|    Импорт локальных групп пользователей завершён.')


    def import_local_users(self, path):
        """Импортируем список локальных пользователей"""
        json_file = os.path.join(path, 'config_users.json')
        err, users = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
        error = 0

        for item in users:
            user_groups = item.pop('groups', None)
            # В версии 5 API добавления пользователя не проверяет что он уже существует.
            if item['name'] in self.ngfw_data['local_users']:
                self.stepChanged.emit(f'GRAY|    Пользователь "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_user(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Пользователь "{item["name"]}" не импортирован]')
                    error = 1
                    break
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
                else:
                    self.ngfw_data['local_users'][item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

            # Добавляем пользователя в группу.
            for group in user_groups:
                try:
                    group_guid = self.ngfw_data['local_groups'][group]
                except KeyError as err:
                    self.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
                else:
                    err2, result2 = self.utm.add_user_in_group(group_guid, self.ngfw_data['local_users'][item['name']])
                    if err2:
                        self.stepChanged.emit(f'RED|       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей!')
        else:
            self.stepChanged.emit('GREEN|    Импорт локальных пользователей завершён.')


    def import_auth_servers(self, path):
        """Импортируем список серверов аутентификации"""
        self.import_ldap_servers(path)
        self.import_ntlm_server(path)
        self.import_radius_server(path)
        self.import_tacacs_server(path)
        self.import_saml_server(path)
    

    def import_ldap_servers(self, path):
        """Импортируем список серверов LDAP"""
        json_file = os.path.join(path, 'config_ldap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit('LBLUE|    После импорта необходимо включить LDAP-коннекторы, ввести пароль и импортировать keytab файл.')
        error = 0

        err, result = self.utm.get_ldap_servers()
        if err == 1:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            ldap_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in ldap_servers:
                    self.stepChanged.emit(f'GRAY|    LDAP-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item['keytab_exists'] = False
                    item.pop("cc", None)
                    if self.utm.float_version < 8.0:
                        item.pop("cache_ttl", None)
                    err, result = self.utm.add_auth_server('ldap', item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Сервер аутентификации LDAP "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        ldap_servers[item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Сервер аутентификации LDAP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов LDAP завершён.')


    def import_ntlm_server(self, path):
        """Импортируем список серверов NTLM"""
        json_file = os.path.join(path, 'config_ntlm_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
        error = 0

        err, result = self.utm.get_ntlm_servers()
        if err == 1:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            ntlm_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in ntlm_servers:
                    self.stepChanged.emit(f'GRAY|    NTLM-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    err, result = self.utm.add_auth_server('ntlm', item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Сервер аутентификации NTLM "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        ntlm_servers[item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Сервер аутентификации NTLM "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM!')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов NTLM завершён.')


    def import_radius_server(self, path):
        """Импортируем список серверов RADIUS"""
        json_file = os.path.join(path, 'config_radius_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|    После импорта необходимо включить каждый сервер RADIUS и ввести пароль.')
        error = 0

        err, result = self.utm.get_radius_servers()
        if err == 1:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            radius_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in radius_servers:
                    self.stepChanged.emit(f'GRAY|    RADIUS-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    err, result = self.utm.add_auth_server('radius', item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Сервер аутентификации RADIUS "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        radius_servers[item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS!')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов RADIUS завершён.')


    def import_tacacs_server(self, path):
        """Импортируем список серверов TACACS+"""
        json_file = os.path.join(path, 'config_tacacs_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|    После импорта необходимо включить каждый сервер TACACS и ввести секретный ключ.')
        error = 0

        err, result = self.utm.get_tacacs_servers()
        if err == 1:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            tacacs_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in tacacs_servers:
                    self.stepChanged.emit(f'GRAY|    TACACS-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    err, result = self.utm.add_auth_server('tacacs', item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Сервер аутентификации TACACS+ "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        tacacs_servers[item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+!')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов TACACS+ завершён.')


    def import_saml_server(self, path):
        """Импортируем список серверов SAML"""
        json_file = os.path.join(path, 'config_saml_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|    После импорта необходимо включить каждый сервер SAML и загрузить SAML metadata.')
        error = 0

        err, result = self.utm.get_saml_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            for x in result:
                error, x['name'] = self.get_transformed_name(x['name'], err=error, descr='Имя сервера')
            saml_servers = {x['name']: x['id'] for x in result}

            for item in data:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
                if item['name'] in saml_servers:
                    self.stepChanged.emit(f'GRAY|    SAML-сервер "{item["name"]}" уже существует.')
                else:
                    item['enabled'] = False
                    item.pop("cc", None)
                    try:
                        item['certificate_id'] = self.ngfw_data['certs'][item['certificate_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: Для "{item["name"]}" не найден сертификат "{item["certificate_id"]}".')
                        error = 1
                        item['certificate_id'] = 0

                    err, result = self.utm.add_auth_server('saml', item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [Сервер аутентификации SAML "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        saml_servers[item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Сервер аутентификации SAML "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML!')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов SAML завершён.')


    def import_2fa_profiles(self, path):
        """Импортируем список 2FA профилей"""
        json_file = os.path.join(path, 'config_2fa_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей MFA в раздел "Пользователи и устройства/Профили MFA".')
        error = 0

        if 'notification_profiles' not in self.ngfw_data:
            if self.get_notification_profiles():      # Устанавливаем атрибут self.ngfw_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
                return
        notification_profiles = self.ngfw_data['notification_profiles']

        if 'profiles_2fa' not in self.ngfw_data:
            if self.get_2fa_profiles():     # Устанавливаем self.ngfw_data['profiles_2fa']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
                return
        profiles_2fa = self.ngfw_data['profiles_2fa']

        for item in data:
            if item['name'] in profiles_2fa:
                self.stepChanged.emit(f'GRAY|    Профиль MFA "{item["name"]}" уже существует.')
            else:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля MFA')
                if item['type'] == 'totp':
                    if item['init_notification_profile_id'] not in notification_profiles:
                        self.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                        error = 1
                        continue
                    item['init_notification_profile_id'] = notification_profiles[item['init_notification_profile_id']]
                else:
                    if item['auth_notification_profile_id'] not in notification_profiles:
                        self.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                        error = 1
                        continue
                    item['auth_notification_profile_id'] = notification_profiles[item['auth_notification_profile_id']]

                err, result = self.utm.add_2fa_profile(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    profiles_2fa[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль MFA "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей MFA завершён.')


    def import_auth_profiles(self, path):
        """Импортируем список профилей аутентификации"""
        json_file = os.path.join(path, 'config_auth_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
        error = 0

        err, ldap, radius, tacacs, ntlm, saml = self.utm.get_auth_servers()
        if err:
            self.stepChanged.emit(f'RED|    {ldap}\n    Произошла ошибка при импорте профилей аутентификации.')
            self.error = 1
            return
        auth_servers = {x['name']: x['id'] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

        if 'profiles_2fa' not in self.ngfw_data:
            if self.get_2fa_profiles():     # Устанавливаем self.ngfw_data['profiles_2fa']
                self.stepChanged.emit(f'ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
                return
        profiles_2fa = self.ngfw_data['profiles_2fa']

        auth_type = {
            'ldap': 'ldap_server_id',
            'radius': 'radius_server_id',
            'tacacs_plus': 'tacacs_plus_server_id',
            'ntlm': 'ntlm_server_id',
            'saml_idp': 'saml_idp_server_id'
        }

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля аутентификации')
            if item['2fa_profile_id']:
                try:
                    item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']]
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: Для "{item["name"]}" не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                    item['2fa_profile_id'] = False
                    error = 1

            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    method_server_id = auth_type[auth_method['type']]
                    try:
                        auth_method[method_server_id] = auth_servers[auth_method[method_server_id]]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: Для "{item["name"]}" не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                        auth_method.clear()
                        error = 1

                    if 'saml_idp_server_id' in auth_method and self.utm.float_version < 6:
                        auth_method['saml_idp_server'] = auth_method.pop('saml_idp_server_id', False)

            item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

            if item['name'] in self.ngfw_data['auth_profiles']:
                self.stepChanged.emit(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует.')
                err, result = self.utm.update_auth_profile(self.ngfw_data['auth_profiles'][item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Profile: item["name"]]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль аутентификации "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_auth_profile(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль аутентификации "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    self.ngfw_data['auth_profiles'][item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль аутентификации "{item["name"]}" импортирован.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей аутентификации завершён.')


    def import_captive_profiles(self, path):
        """Импортируем список Captive-профилей"""
        json_file = os.path.join(path, 'config_captive_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт Captive-профилей в раздел "Пользователи и устройства/Captive-профили".')
        error = 0

        if 'list_templates' not in self.ngfw_data:
            if self.get_templates_list():    # Устанавливаем атрибут self.ngfw_data['list_templates']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        list_templates = self.ngfw_data['list_templates']

        if 'notification_profiles' not in self.ngfw_data:
            if self.get_notification_profiles():      # Устанавливаем атрибут self.ngfw_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        notification_profiles = self.ngfw_data['notification_profiles']

        err, result = self.utm.get_captive_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте Captive-профилей.')
            self.error = 1
            return
        captive_profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        if (6 <= self.utm.float_version < 7.1):
            result = self.utm._server.v3.accounts.groups.list(self.utm._auth_token, 0, 1000, {}, [])['items']
            list_groups = {x['name']: x['id'] for x in result}

        if self.utm.float_version >= 7.1:
            if 'client_certificate_profiles' not in self.ngfw_data:
                if self.get_client_certificate_profiles():          # Устанавливаем атрибут self.ngfw_data['client_certificate_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей')
                    return
            client_certificate_profiles = self.ngfw_data['client_certificate_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя Captive-профиля')
            item['captive_template_id'] = list_templates.get(item['captive_template_id'], -1)
            try:
                item['user_auth_profile_id'] = self.ngfw_data['auth_profiles'][item['user_auth_profile_id']]
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
                item['user_auth_profile_id'] = 1
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["user_auth_profile_id"]}".'
                error = 1

            if item['notification_profile_id'] != -1:
                try:
                    item['notification_profile_id'] = notification_profiles[item['notification_profile_id']]
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль оповещения "{item["notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    item['notification_profile_id'] = -1
                    item['description'] = f'{item["description"]}\nError: Не найден профиль оповещения "{item["notification_profile_id"]}".'
                    error = 1
            try:
                if (6 <= self.utm.float_version < 7.1):
                    item['ta_groups'] = [list_groups[name] for name in item['ta_groups']]
                else:
                    item['ta_groups'] = [self.ngfw_data['local_groups'][name] for name in item['ta_groups']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Группа гостевых пользователей {err} не найдена. Загрузите локальные группы и повторите попытку.')
                item['ta_groups'] = []
                item['description'] = f'{item["description"]}\nError: Не найдена группа гостевых пользователей {err}.'
                error = 1

            if item['ta_expiration_date']:
                item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
            else:
                item.pop('ta_expiration_date', None)

            if self.utm.float_version >= 7.1:
                item.pop('use_https_auth', None)
                if item['captive_auth_mode'] != 'aaa':
                    item['client_certificate_profile_id'] = client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
                    if not item['client_certificate_profile_id']:
                        self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Загрузите профили сертификата пользователя и повторите попытку.')
                        item['captive_auth_mode'] = 'aaa'
                        item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                        error = 1
            else:
                item.pop('captive_auth_mode', None)
                item.pop('client_certificate_profile_id', None)

            if item['name'] in captive_profiles:
                self.stepChanged.emit(f'uGRAY|    Captive-профиль "{item["name"]}" уже существует.')
                err, result = self.utm.update_captive_profile(captive_profiles[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Captive-profile: {item["name"]}]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Captive-профиль "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_captive_profile(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Captive-profile "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    captive_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" импортирован.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Captive-профилей завершён.')


    def import_captive_portal_rules(self, path):
        """Импортируем список правил Captive-портала"""
        json_file = os.path.join(path, 'config_captive_portal_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил Captive-портала в раздел "Пользователи и устройства/Captive-портал".')
        error = 0

        err, result = self.utm.get_captive_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил Captive-портала.')
            self.error = 1
            return
        captive_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_captive_portal_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил Captive-портала.')
            self.error = 1
            return
        captive_portal_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя Captive-портала')
            if item['profile_id']:
                try:
                    item['profile_id'] = captive_profiles[item['profile_id']]
                except KeyError:
                    self.stepChanged.emit('RED|    Error: [Captive-portal "{item["name"]}"] Не найден Captive-профиль "{item["profile_id"]}". Загрузите Captive-профили и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден Captive-профиль "{item["profile_id"]}".'
                    item['profile_id'] = 0
                    error = 1
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in captive_portal_rules:
                self.stepChanged.emit(f'uGRAY|    Правило Captive-портала "{item["name"]}" уже существует.')
                err, result = self.utm.update_captive_portal_rule(captive_portal_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Captive-portal "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило Captive-портала "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_captive_portal_rules(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Captive-portal "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    captive_portal_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило Captive-портала "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил Captive-портала завершён.')


    def import_terminal_servers(self, path):
        """Импортируем список терминальных серверов"""
        json_file = os.path.join(path, 'config_terminal_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
        error = 0

        err, result = self.utm.get_terminal_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка терминальных серверов.')
            self.error = 1
            return
        terminal_servers = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in terminal_servers:
                self.stepChanged.emit(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует.')
                err, result = self.utm.update_terminal_server(terminal_servers[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Terminal Server "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Терминальный сервер "{item["name"]}" updated.')
            else:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя терминального сервера')
                err, result = self.utm.add_terminal_server(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    terminal_servers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка терминальных серверов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт терминальных серверов завершён.')


    def import_byod_policy(self, path):
        """Импортируем список Политики BYOD"""
        json_file = os.path.join(path, 'config_byod_policy.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Политики BYOD" в раздел "Пользователи и устройства/Политики BYOD".')
        error = 0

        err, result = self.utm.get_byod_policy()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка "Политики BYOD".')
            self.error = 1
            return
        byod_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item['users'] = self.get_guids_users_and_groups(item)
            if item['name'] in byod_rules:
                self.stepChanged.emit(f'uGRAY|    Политика BYOD "{item["name"]}" уже существует.')
                err, result = self.utm.update_byod_policy(byod_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [BYOD policy "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       BYOD policy "{item["name"]}" updated.')
            else:
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя Политики BYOD')
                err, result = self.utm.add_byod_policy(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [BYOD policy "{item["name"]}" не импортирована]')
                    error = 1
                else:
                    byod_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Политика BYOD "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Политики BYOD".')
        else:
            self.stepChanged.emit('GREEN|    Импорт политик BYOD завершён.')


    def import_userid_agent(self, path):
        """Импортируем настройки UserID агент"""
        self.import_agent_config(path)
        self.import_agent_servers(path)


    def import_agent_config(self, path):
        """Импортируем настройки UserID агент"""
        json_file = os.path.join(path, 'userid_agent_config.json')
        err, result = self.read_json_file(json_file, mode=2)
        if err:
            return

        error = 0
        self.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/UserID агент".')

        if isinstance(result, list):
            # В случае версий 7.2 и выше - берём только первую конфигурацию свойств, так как при экспорте с кластера
            # могут быть конфигурации со всех узлов кластера и не понятно свойства с какого узла импортировать.
            try:
                data = result[0]
            except Exception:       # Будет ошибка если экспортировали конвертером версии 3.1 и ниже.
                self.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте свойства агента UserID. Ошибка файла конфигурации.')
                self.error = 1
                return
        else:
            data = result

        data.pop('name', None)
        if self.utm.float_version != 7.2:
            data['expiration_time'] = 2700
            data.pop('radius_monitoring_interval', None)

        if data['tcp_ca_certificate_id']:
            try:
                data['tcp_ca_certificate_id'] = self.ngfw_data['certs'][data['tcp_ca_certificate_id']]
            except KeyError as err:
                self.stepChanged.emit('RED|    Error: Не найден сертификат "{err}". Загрузите сертификаты и повторите попытку.')
                data.pop('tcp_ca_certificate_id', None)
                error = 1
        else:
            data.pop('tcp_ca_certificate_id', None)

        if data['tcp_server_certificate_id']:
            try:
                data['tcp_server_certificate_id'] = self.ngfw_data['certs'][data['tcp_server_certificate_id']]
            except KeyError as err:
                self.stepChanged.emit('RED|    Error: Не найден сертификат УЦ "{err}". Загрузите сертификаты и повторите попытку.')
                data.pop('tcp_server_certificate_id', None)
                error = 1
        else:
            data.pop('tcp_server_certificate_id', None)

        new_networks = []
        for x in data['ignore_networks']:
            try:
                new_networks.append(['list_id', self.ngfw_data['ip_lists'][x[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
                error = 1
        data['ignore_networks'] = new_networks

        err, result = self.utm.set_useridagent_config(data)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не импортированы]')
            error = 1

        if error:
            self.error = 1
            self.stepChanged.emit(f'ORANGE|    Произошла ошибка при импорте свойства агента UserID.')
        else:
            self.stepChanged.emit('BLACK|    Свойства агента UserID обновлены.')


    def import_agent_servers(self, path):
        """Импортируем настройки AD и свойств отправителя syslog UserID агент"""
        json_file = os.path.join(path, 'userid_agent_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
        error = 0

        err, result = self.utm.get_useridagent_filters()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек UserID агент.')
            self.error = 1
            return
        useridagent_filters = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_useridagent_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек UserID агент.')
            self.error = 1
            return
        useridagent_servers = {x['name']: x['id'] for x in result}


        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя UserID агент')
            if self.utm.float_version < 7.2:
                if item['type'] == 'radius':
                    self.stepChanged.emit(f'NOTE|    Коннектор UserID агент "{item["name"]}" не импортирован так как ваша версия NGFW меньше 7.2.')
                    continue
                item.pop('exporation_time', None)
            try:
                item['auth_profile_id'] = self.ngfw_data['auth_profiles'][item['auth_profile_id']]
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
                item['auth_profile_id'] = 1
                error = 1
            if 'filters' in item:
                new_filters = []
                for filter_name in item['filters']:
                    try:
                        new_filters.append(useridagent_filters[filter_name])
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден Syslog фильтр UserID агента "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
                        error = 1
                item['filters'] = new_filters

            if item['name'] in useridagent_servers:
                self.stepChanged.emit(f'uGRAY|    UserID агент "{item["name"]}" уже существует.')
                err, result = self.utm.update_useridagent_server(useridagent_servers[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       UserID агент "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_useridagent_server(item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [UserID агент "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    useridagent_servers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    UserID агент "{item["name"]}" импортирован.')
            if item['type'] == 'ad':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннетора Microsoft AD.')
            elif item['type'] == 'radius':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннетора RADIUS.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек UserID агент.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Агентов UserID завершён.')


    #---------------------------------------- Политики сети -----------------------------------------
    def import_firewall_rules(self, path):
        """Импортируем список правил межсетевого экрана"""
        json_file = os.path.join(path, 'config_firewall_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

        if self.utm.product != 'dcfw':
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

        if self.utm.float_version >= 7.1:
            err, result = self.utm.get_idps_profiles_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
                self.error = 1
                return
            idps_profiles = {x['name']: x['id'] for x in result}

            err, result = self.utm.get_l7_profiles_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
                self.error = 1
                return
            l7_profiles = {x['name']: x['id'] for x in result}

            if self.utm.product != 'dcfw':
                err, result = self.utm.get_hip_profiles_list()
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
                    self.error = 1
                    return
                hip_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_firewall_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
            self.error = 1
            return
        firewall_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        error = 0
        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)

            if self.utm.product == 'dcfw':
                item['scenario_rule_id'] = False
            else:
                if item['scenario_rule_id']:
                    try:
                        item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило МЭ "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                        item['scenario_rule_id'] = False
                        item['enabled'] = False
                        error = 1
            if self.utm.float_version < 7.1:
                if 'apps' in item:
                    item['apps'] = self.get_apps(item)
                else:
                    item['apps'] = []
                    item['apps_negate'] = False
                item.pop('ips_profile', None)
                item.pop('l7_profile', None)
                item.pop('hip_profiles', None)
                if self.utm.float_version >= 6:
                    item.pop('apps_negate', None)
            else:
                item.pop('apps', None)
                item.pop('apps_negate', None)
                if 'ips_profile' in item and item['ips_profile']:
                    try:
                        item['ips_profile'] = idps_profiles[item['ips_profile']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило МЭ "{item["name"]}"] Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                        item['ips_profile'] = False
                        item['enabled'] = False
                        error = 1
                else:
                    item['ips_profile'] = False
                if 'l7_profile' in item and item['l7_profile']:
                    try:
                        item['l7_profile'] = l7_profiles[item['l7_profile']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило МЭ "{item["name"]}"] Не найден профиль приложений {err}. Загрузите профили приложений и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                        item['l7_profile'] = False
                        item['enabled'] = False
                        error = 1
                else:
                    item['l7_profile'] = False

                if self.utm.product == 'dcfw':
                    item['hip_profile'] = []
                else:
                    if 'hip_profiles' in item:
                        new_hip_profiles = []
                        for hip in item['hip_profiles']:
                            try:
                                new_hip_profiles.append(hip_profiles[hip])
                            except KeyError as err:
                                self.stepChanged.emit(f'RED|    Error: [Правило МЭ "{item["name"]}"] Не найден профиль HIP {err}. Загрузите профили HIP и повторите попытку.')
                                item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                                item['enabled'] = False
                                error = 1
                        item['hip_profiles'] = new_hip_profiles
                    else:
                        item['hip_profile'] = []

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in firewall_rules:
                self.stepChanged.emit(f'uGRAY|    Правило МЭ "{item["name"]}" уже существует.')
                err, result = self.utm.update_firewall_rule(firewall_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило МЭ "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило МЭ "{item["name"]}" updated.')
            else:
                item['position'] = 'last' 
                err, result = self.utm.add_firewall_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило МЭ "{item["name"]}" не импортировано]')
                else:
                    firewall_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило МЭ "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[firewall_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'fw_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил межсетевого экрана завершён.')


    def import_nat_rules(self, path):
        """Импортируем список правил NAT"""
        json_file = os.path.join(path, 'config_nat_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил NAT в раздел "Политики сети/NAT и маршрутизация".')
        error = 0

        if self.utm.product != 'dcfw':
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

        err, result = self.utm.get_gateways_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил NAT.')
            self.error = 1
            return
        ngfw_gateways = {x['name']: f'{x["id"]}:{x["node_name"]}' for x in result if 'name' in x}

        err, result = self.utm.get_traffic_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил NAT.')
            self.error = 1
            return
        nat_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)

            if self.utm.product == 'dcfw':
                item['scenario_rule_id'] = False
            else:
                if item['scenario_rule_id']:
                    try:
                        item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                        item['scenario_rule_id'] = False
                        item['error'] = True
            if self.utm.float_version >= 6:
                item['users'] = self.get_guids_users_and_groups(item)
            else:
                item.pop('users', None)
            item['zone_in'] = self.get_zones_id('src', item['zone_in'], item)
            item['zone_out'] = self.get_zones_id('dst', item['zone_out'], item)
            item['source_ip'] = self.get_ips_id('src', item['source_ip'], item)
            item['dest_ip'] = self.get_ips_id('dst', item['dest_ip'], item)
            item['service'] = self.get_services(item['service'], item)
            item['gateway'] = ngfw_gateways.get(item['gateway'], item['gateway'])
            
            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in nat_rules:
                self.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
                item.pop('position', None)
                err, result = self.utm.update_traffic_rule(nat_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" updated.')
            else:
                item['position'] = 'last' 
                err, result = self.utm.add_traffic_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    nat_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
            if item['action'] == 'route':
                self.stepChanged.emit(f'LBLUE|       [Правило "{item["name"]}"] Проверьте шлюз для правила ПБР. В случае отсутствия, установите вручную.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[nat_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'traffic_rule'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил NAT завершён.')


    def import_loadbalancing_rules(self, path):
        """Импортируем правила балансировки нагрузки"""
        self.stepChanged.emit('BLUE|Импорт правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
        err, tcpudp, icap, reverse = self.utm.get_loadbalancing_rules()
        if err:
            self.stepChanged.emit(f'RED|    {tcpudp}\n    Произошла ошибка при импорте правил балансировки нагрузки.')
            self.error = 1
            return

        self.import_loadbalancing_tcpudp(path, tcpudp)
        if self.utm.product != 'dcfw':
            self.import_loadbalancing_icap(path, icap)
            self.import_loadbalancing_reverse(path, reverse)


    def import_loadbalancing_tcpudp(self, path, tcpudp):
        """Импортируем балансировщики TCP/UDP"""
        json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|    Нет балансировщиков TCP/UDP для импорта.')
            return
        elif err == 1:
            return

        self.stepChanged.emit('BLUE|    Импорт балансировщиков TCP/UDP.')
        tcpudp_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in tcpudp}
        error = 0

        for item in data:
            if self.utm.float_version < 7.1:
                item.pop('src_zones', None)
                item.pop('src_zones_negate', None)
                item.pop('src_ips', None)
                item.pop('src_ips_negate', None)
            else:
                item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
                item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in tcpudp_rules:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
                err, result = self.utm.update_virtualserver_rule(tcpudp_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|          Правило балансировки TCP/UDP "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_virtualserver_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    tcpudp_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки TCP/UDP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте правил балансировки TCP/UDP.')
        else:
            self.stepChanged.emit('GREEN|       Правила балансировки TCP/UDP импортированы.')


    def import_loadbalancing_icap(self, path, icap):
        """Импортируем балансировщики ICAP"""
        json_file = os.path.join(path, 'config_loadbalancing_icap.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|    Нет балансировщиков ICAP для импорта.')
            return
        elif err == 1:
            return

        self.stepChanged.emit('BLUE|    Импорт балансировщиков ICAP.')
        icap_loadbalancing = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in icap}
        error = 0

        if 'icap_servers' not in self.ngfw_data:
            if self.get_icap_servers():      # Устанавливаем атрибут self.ngfw_data['icap_servers']
                self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте правил балансировки ICAP.')
                return
        icap_servers = self.ngfw_data['icap_servers']

        for item in data:
            try:
                item['profiles'] = [icap_servers[x] for x in item['profiles']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|       Error: [Правило "{item["name"]}"] Не найден сервер ICAP {err}. Импортируйте серверы ICAP и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                item['profiles'] = []
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in icap_loadbalancing:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки ICAP "{item["name"]}" уже существует.')
                err, result = self.utm.update_icap_loadbalancing_rule(icap_loadbalancing[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|          Правило балансировки ICAP "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_icap_loadbalancing_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    icap_loadbalancing[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки ICAP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте правил балансировки ICAP.')
        else:
            self.stepChanged.emit('GREEN|       Правила балансировки ICAP импортированы.')


    def import_loadbalancing_reverse(self, path, reverse):
        """Импортируем балансировщики reverse-proxy"""
        json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|    Нет балансировщиков Reverse-proxy для импорта.')
            return
        elif err == 1:
            return

        self.stepChanged.emit('BLUE|    Импорт балансировщиков Reverse-proxy.')
        if 'reverseproxy_servers' not in self.ngfw_data:
            if self.get_reverseproxy_servers():      # Устанавливаем атрибут self.ngfw_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте правил балансировки Reverse-proxy.')
                return
        reverseproxy_servers = self.ngfw_data['reverseproxy_servers']

        reverse_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in reverse}
        error = 0

        for item in data:
            try:
                item['profiles'] = [reverseproxy_servers[x] for x in item['profiles']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|       Error: [Правило "{item["name"]}"] Не найден сервер reverse-proxy {err}. Загрузите серверы reverse-proxy и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сервер reverse-proxy {err}.'
                item['profiles'] = []
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in reverse_rules:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
                err, result = self.utm.update_reverse_loadbalancing_rule(reverse_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|          Правило балансировки reverse-proxy "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_reverse_loadbalancing_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    reverse_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки reverse-proxy "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при импорте правил балансировки Reverse-proxy.')
        else:
            self.stepChanged.emit('GREEN|       Правила балансировки Reverse-proxy импортированы.')


    def import_shaper_rules(self, path):
        """Импортируем список правил пропускной способности"""
        json_file = os.path.join(path, 'config_shaper_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
        error = 0

        if self.utm.product != 'dcfw':
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

        err, result = self.utm.get_shaper_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил пропускной способности.')
            self.error = 1
            return
        shaper_list = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_shaper_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил пропускной способности.')
            self.error = 1
            return
        shaper_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            if self.utm.float_version < 6:
                item.pop('limit', None)
                item.pop('limit_value', None)
                item.pop('limit_burst', None)
                item.pop('log', None)
                item.pop('log_session_start', None)

            if self.utm.product == 'dcfw':
                item['scenario_rule_id'] = False
            else:
                if item['scenario_rule_id']:
                    try:
                        item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                        item['scenario_rule_id'] = False
                        item['error'] = True
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['services'] = self.get_services(item['services'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            item['apps'] = self.get_apps(item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            try:
                item['pool'] = shaper_list[item['pool']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена полоса пропускания "{item["pool"]}". Импортируйте полосы пропускания и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена полоса пропускания "{item["pool"]}".'
                item['pool'] = 1
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in shaper_rules:
                self.stepChanged.emit(f'uGRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
                err, result = self.utm.update_shaper_rule(shaper_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило пропускной способности "{item["name"]}" updated.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_shaper_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    shaper_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[shaper_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'shaper_rule'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил пропускной способности завершён.')


    #-------------------------------------- Политики безопасности -----------------------------------
    def import_content_rules(self, path):
        """Импортируем список правил фильтрации контента"""
        json_file = os.path.join(path, 'config_content_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
        error = 0

        if 'scenarios_rules' not in self.ngfw_data:
            if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
                return
        scenarios_rules = self.ngfw_data['scenarios_rules']

        if 'list_templates' not in self.ngfw_data:
            if self.get_templates_list():    # Устанавливаем атрибут self.ngfw_data['list_templates']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
                return
        list_templates = self.ngfw_data['list_templates']

        err, result = self.utm.get_nlists_list('morphology')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил контентной фильтрации.')
            self.error = 1
            return
        morphology_list = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_nlists_list('useragent')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил контентной фильтрации.')
            self.error = 1
            return
        useragent_list = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_content_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил контентной фильтрации.')
            self.error = 1
            return
        content_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            if self.utm.float_version < 7.1:
                item.pop('layer', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            try:
                item['blockpage_template_id'] = list_templates[item['blockpage_template_id']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
                item['blockpage_template_id'] = -1
                item['error'] = True

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            item['referers'] = self.get_urls_id(item['referers'], item)
            if self.utm.float_version < 6:
                item.pop('referer_categories', None)
                item.pop('users_negate', None)
                item.pop('position_layer', None)
            else:
                item['referer_categories'] = self.get_url_categories_id(item, referer=1)

            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True

            new_morph_categories = []
            for x in item['morph_categories']:
                try:
                    new_morph_categories.append(morphology_list[x])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список морфрлогии {err}. Загрузите списки морфологии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список морфрлогии {err}.'
                    item['error'] = True
            item['morph_categories'] = new_morph_categories

            new_user_agents = []
            for x in item['user_agents']:
                try:
                    new_user_agents.append(['list_id', useragent_list[x[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список UserAgent {err}. Загрузите списки Useragent браузеров и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список UserAgent {err}.'
                    item['error'] = True
            item['user_agents'] = new_user_agents

            new_content_types = []
            for x in item['content_types']:
                try:
                    new_content_types.append(self.ngfw_data['mime'][x])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список типов контента {err}. Загрузите списки Типов контента и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                    item['error'] = True
            item['content_types'] = new_content_types

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in content_rules:
                self.stepChanged.emit(f'uGRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
                err, result = self.utm.update_content_rule(content_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило КФ "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило контентной фильтрации "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_content_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило КФ "{item["name"]}" не импортировано]')
                else:
                    content_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[content_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'content_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил контентной фильтрации завершён.')


    def import_safebrowsing_rules(self, path):
        """Импортируем список правил веб-безопасности"""
        json_file = os.path.join(path, 'config_safebrowsing_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил веб-безопасности в раздел "Политики безопасности/Веб-безопасность".')
        error = 0

        err, result = self.utm.get_safebrowsing_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил веб-безопасности.')
            self.error = 1
            return
        safebrowsing_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            item['url_list_exclusions'] = self.get_urls_id(item['url_list_exclusions'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in safebrowsing_rules:
                self.stepChanged.emit(f'uGRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
                err, result = self.utm.update_safebrowsing_rule(safebrowsing_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило веб-безопасности "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило веб-безопасности "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_safebrowsing_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности "{item["name"]}" не импортировано]')
                else:
                    safebrowsing_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[safebrowsing_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'content_fo_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил веб-безопасности завершён.')


    def import_tunnel_inspection_rules(self, path):
        """Импортируем список правил инспектирования туннелей"""
        json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил инспектирования туннелей в раздел "Политики безопасности/Инспектирование туннелей".')
        error = 0

        err, result = self.utm.get_tunnel_inspection_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования туннелей.')
            self.error = 1
            return
        tunnel_inspect_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in tunnel_inspect_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования туннелей "{item["name"]}" уже существует.')
                err, result = self.utm.update_tunnel_inspection_rule(tunnel_inspect_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило инспектирования туннелей "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило инспектирования туннелей "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_tunnel_inspection_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей "{item["name"]}" не импортировано]')
                else:
                    tunnel_inspect_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[tunnel_inspect_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'tunnel_inspection_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования туннелей завершён.')


    def import_ssldecrypt_rules(self, path):
        """Импортируем список правил инспектирования SSL"""
        json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
        error = 0

        ssl_forward_profiles = {}
        if self.utm.float_version >= 7:
            err, rules = self.utm.get_ssl_forward_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSL.')
                self.error = 1
                return
            ssl_forward_profiles = {x['name']: x['id'] for x in rules}
            ssl_forward_profiles[-1] = -1

        err, result = self.utm.get_ssldecrypt_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSL.')
            self.error = 1
            return
        ssldecrypt_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['users'] = self.get_guids_users_and_groups(item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            if self.utm.float_version < 6:
                item.pop('ssl_profile_id', None)
            else:
                try:
                    item['ssl_profile_id'] = self.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err} для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                    item['ssl_profile_id'] = self.ngfw_data['ssl_profiles']['Default SSL profile']
                    item['error'] = True
            if self.utm.float_version < 7:
                item.pop('ssl_forward_profile_id', None)
                if item['action'] == 'decrypt_forward':
                    item['action'] = 'decrypt'
            else:
                try:
                    item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль пересылки SSL {err} для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
                    item['ssl_forward_profile_id'] = -1
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in ssldecrypt_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
                err, result = self.utm.update_ssldecrypt_rule(ssldecrypt_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSL "{item["name"]}"]')
                    continue
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило инспектирования SSL "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_ssldecrypt_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
                    continue
                else:
                    ssldecrypt_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[ssldecrypt_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'content_https_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования SSL завершён.')


    def import_sshdecrypt_rules(self, path):
        """Импортируем список правил инспектирования SSH"""
        json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил инспектирования SSH в раздел "Политики безопасности/Инспектирование SSH".')
        error = 0

        err, rules = self.utm.get_sshdecrypt_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSH.')
            self.error = 1
            return
        sshdecrypt_rules = {x['name']: x['id'] for x in rules}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            if self.utm.float_version < 7.1:
                item.pop('layer', None)
            item['users'] = self.get_guids_users_and_groups(item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            item['protocols'] = self.get_services(item['protocols'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in sshdecrypt_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
                err, result = self.utm.update_sshdecrypt_rule(sshdecrypt_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSH "{item["name"]}"]')
                    continue
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило инспектирования SSH "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_sshdecrypt_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
                    continue
                else:
                    sshdecrypt_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[sshdecrypt_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'content_ssh_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования SSH завершён.')


    def import_idps_rules(self, path):
        """Импортируем список правил СОВ"""
        json_file = os.path.join(path, 'config_idps_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил СОВ в раздел "Политики безопасности/СОВ".')
        error = 0

        err, result = self.utm.get_nlists_list('ipspolicy')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил СОВ.')
            self.error = 1
            return
        idps_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_idps_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил СОВ.')
            self.error = 1
            return
        idps_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            if self.utm.float_version < 7.0 and item['action'] == 'reset':
                item['action'] = 'drop'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['services'] = self.get_services(item['services'], item)
            try:
                item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                item['idps_profiles'] = [idps_profiles['ENTENSYS_IPS_POLICY'],]
                item['error'] = True
            if self.utm.float_version < 6:
                item.pop('idps_profiles_exclusions', None)
            else:
                try:
                    item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль исключения СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль исключения СОВ {err}.'
                    item['idps_profiles_exclusions'] = []
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in idps_rules:
                self.stepChanged.emit(f'uGRAY|    Правило СОВ "{item["name"]}" уже существует.')
                err, result = self.utm.update_idps_rule(idps_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило СОВ "{item["name"]}"]')
                    continue
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило СОВ "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_idps_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило СОВ "{item["name"]}" не импортировано]')
                    continue
                else:
                    idps_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило СОВ "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил СОВ.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил СОВ завершён.')


    def import_scada_rules(self, path):
        """Импортируем список правил АСУ ТП"""
        json_file = os.path.join(path, 'config_scada_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил АСУ ТП в раздел "Политики безопасности/Правила АСУ ТП".')
        error = 0

        err, rules = self.utm.get_scada_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил АСУ ТП.')
            self.error = 1
            return
        scada_profiles = {x['name']: x['id'] for x in rules}

        err, result = self.utm.get_scada_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил АСУ ТП.')
            self.error = 1
            return
        scada_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            try:
                item['services'] = [self.ngfw_data['services'][x] for x in item['services']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сервис {err}. Загрузите список сервисов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сервис {err}.'
                item['services'] = []
                item['error'] = True
            try:
                item['scada_profiles'] = [scada_profiles[x] for x in item['scada_profiles']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                item['scada_profiles'] = []
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in scada_rules:
                self.stepChanged.emit(f'uGRAY|    Правило АСУ ТП "{item["name"]}" уже существует.')
                err, result = self.utm.update_scada_rule(scada_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило АСУ ТП "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило АСУ ТП "{item["name"]}" обновлено.')
            else:
                if self.utm.float_version < 6:
                    item.pop('position', None)
                else:
                    item['position'] = 'last'
                err, result = self.utm.add_scada_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило АСУ ТП "{item["name"]}" не импортировано]')
                else:
                    scada_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило АСУ ТП "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил АСУ ТП.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил АСУ ТП завершён.')


    def import_mailsecurity(self, path):
        self.import_mailsecurity_rules(path)
        self.import_mailsecurity_antispam(path)
        self.import_mailsecurity_batv(path)


    def import_mailsecurity_rules(self, path):
        """Импортируем список правил защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
        error = 0

        err, result = self.utm.get_nlist_list('emailgroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты почтового трафика.')
            self.error = 1
            return
        email = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_mailsecurity_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты почтового трафика.')
            self.error = 1
            return
        mailsecurity_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item['enabled'] = False
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            if self.utm.float_version < 6:
                item['protocol'] = list({'pop' if x[1] in ['POP3', 'POP3S'] else 'smtp' for x in item['services']})
                item.pop('services', None)
                item.pop('envelope_to_negate', None)
                item.pop('envelope_from_negate', None)
            else:
                if not item['services']:
                    item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
                item['services'] = self.get_services(item['services'], item)

            try:
                item['envelope_from'] = [[x[0], email[x[1]]] for x in item['envelope_from']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
                item['envelope_from'] = []
                item['error'] = True
            try:
                item['envelope_to'] = [[x[0], email[x[1]]] for x in item['envelope_to']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
                item['envelope_to'] = []
                item['error'] = True

            if self.utm.float_version < 7.1:
                item.pop('rule_log', None)
            if self.utm.float_version < 7:
                item.pop('dst_zones_negate', None)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in mailsecurity_rules:
                self.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
                err, result = self.utm.update_mailsecurity_rule(mailsecurity_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_mailsecurity_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    mailsecurity_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[mailsecurity_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'mailsecurity_rule'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил защиты почтового трафика завершён.')


    def import_mailsecurity_antispam(self, path):
        """Импортируем dnsbl защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        message = 'Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".'
        self.stepChanged.emit('BLUE|{message}\n    Импорт настроек DNSBL.')

        data['white_list'] = self.get_ips_id('white_list', data['white_list'], {'name': 'antispam DNSBL'})
        data['black_list'] = self.get_ips_id('black_list', data['black_list'], {'name': 'antispam DNSBL'})

        err, result = self.utm.set_mailsecurity_dnsbl(data)
        if err:
            self.error = 1
            self.stepChanged.emit(f'RED|       {result}\n       Произошла ошибка при импорте настроек DNSBL.')
        else:
            self.stepChanged.emit(f'GREEN|       Список DNSBL импортирован.')


    def import_mailsecurity_batv(self, path):
        """Импортируем batv защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_batv.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт настройки BATV.')

        err, result = self.utm.set_mailsecurity_batv(data)
        if err:
            self.error = 1
            self.stepChanged.emit(f'RED|       {result}\n       Произошла ошибка при импорте настроек BATV.')
        else:
            self.stepChanged.emit(f'GREEN|       Настройка BATV импортирована.')


    def import_icap_servers(self, path):
        """Импортируем список серверов ICAP"""
        json_file = os.path.join(path, 'config_icap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
        error = 0

        if 'icap_servers' not in self.ngfw_data:
            if self.get_icap_servers():      # Устанавливаем атрибут self.ngfw_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
                return
        icap_servers = self.ngfw_data['icap_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера ICAP')
            if item['name'] in icap_servers:
                self.stepChanged.emit(f'uGRAY|    ICAP-сервер "{item["name"]}" уже существует.')
                err, result = self.utm.update_icap_server(icap_servers[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [ICAP-сервер "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       ICAP-сервер "{item["name"]}" обновлён.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_icap_server(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [ICAP-сервер "{item["name"]}" не импортирован]')
                else:
                    icap_servers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов ICAP завершён.')


    def import_icap_rules(self, path):
        """Импортируем список правил ICAP"""
        json_file = os.path.join(path, 'config_icap_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил ICAP в раздел "Политики безопасности/ICAP-правила".')
        error = 0

        if 'icap_servers' not in self.ngfw_data:
            if self.get_icap_servers():      # Устанавливаем атрибут self.ngfw_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
                return
        icap_servers = self.ngfw_data['icap_servers']

        err, err_msg, result, _ = self.utm.get_loadbalancing_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил ICAP.')
            self.error = 1
            return
        icap_loadbalancing = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_icap_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил ICAP.')
            self.error = 1
            return
        icap_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)

            new_servers = []
            for server in item['servers']:
                if server[0] == 'lbrule':
                    try:
                        new_servers.append(['lbrule', icap_loadbalancing[server[1]]])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден балансировщик серверов ICAP {err}. Импортируйте балансировщики ICAP и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден балансировщик серверов ICAP {err}.'
                        item['error'] = True
                elif server[0] == 'profile':
                    try:
                        new_servers.append(['profile', icap_servers[server[1]]])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сервер ICAP {err}. Импортируйте сервера ICAP и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                        item['error'] = True
            item['servers'] = new_servers

            item['users'] = self.get_guids_users_and_groups(item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)

            new_content_types = []
            for x in item['content_types']:
                try:
                    new_content_types.append(self.ngfw_data['mime'][x])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список типов контента {err}. Импортируйте списки типов контента и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                    item['error'] = True
            item['content_types'] = new_content_types

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in icap_rules:
                self.stepChanged.emit(f'uGRAY|    ICAP-правило "{item["name"]}" уже существует.')
                err, result = self.utm.update_icap_rule(icap_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [ICAP-правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       ICAP-правило "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_icap_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [ICAP-правило "{item["name"]}" не импортировано]')
                else:
                    icap_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[icap_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'icap_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил ICAP завершён.')


    def import_dos_profiles(self, path):
        """Импортируем список профилей DoS"""
        json_file = os.path.join(path, 'config_dos_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей DoS в раздел "Политики безопасности/Профили DoS".')
        error = 0

        err, result = self.utm.get_dos_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей DoS.')
            self.error = 1
            return
        dos_profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in dos_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль DoS "{item["name"]}" уже существует.')
                err, result = self.utm.update_dos_profile(dos_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль DoS "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль DoS "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_dos_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль DoS "{item["name"]}" не импортирован]')
                else:
                    dos_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей DoS завершён.')


    def import_dos_rules(self, path):
        """Импортируем список правил защиты DoS"""
        json_file = os.path.join(path, 'config_dos_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил защиты DoS в раздел "Политики безопасности/Правила защиты DoS".')
        error = 0

        if 'scenarios_rules' not in self.ngfw_data:
            if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
                return
        scenarios_rules = self.ngfw_data['scenarios_rules']

        err, result = self.utm.get_dos_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты DoS.')
            self.error = 1
            return
        dos_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_dos_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты DoS.')
            self.error = 1
            return
        dos_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            if item['dos_profile']:
                try:
                    item['dos_profile'] = dos_profiles[item['dos_profile']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль DoS {err}. Импортируйте профили DoS и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль DoS {err}.'
                    item['dos_profile'] = False
                    item['error'] = True
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Импортируйте сценарии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in dos_rules:
                self.stepChanged.emit(f'uGRAY|    Правило защиты DoS "{item["name"]}" уже существует.')
                err, result = self.utm.update_dos_rule(dos_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило защиты DoS "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило защиты DoS "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_dos_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS "{item["name"]}" не импортировано]')
                else:
                    dos_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[dos_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'dos_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил защиты DoS завершён.')


    #-------------------------------------- Глобальный портал ---------------------------------------
    def import_proxyportal_rules(self, path):
        """Импортируем список URL-ресурсов веб-портала"""
        self.stepChanged.emit('BLUE|Импорт списка ресурсов веб-портала в раздел "Глобальный портал/Веб-портал".')
        json_file = os.path.join(path, 'config_web_portal.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return
        error = 0

        err, result = self.utm.get_proxyportal_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте ресурсов веб-портала.')
            self.error = 1
            return
        list_proxyportal = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя ресурса')
            item.pop('position_layer', None)
            item['users'] = self.get_guids_users_and_groups(item)
            if self.utm.float_version < 7:
                item.pop('transparent_auth', None)
            if self.utm.float_version < 6:
                item.pop('mapping_url_ssl_profile_id', None)
                item.pop('mapping_url_certificate_id', None)
            else:
                try:
                    if item['mapping_url_ssl_profile_id']:
                        item['mapping_url_ssl_profile_id'] = self.ngfw_data['ssl_profiles'][item['mapping_url_ssl_profile_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                    item['mapping_url_ssl_profile_id'] = 0
                    item['error'] = True
                try:
                    if item['mapping_url_certificate_id']:
                        item['mapping_url_certificate_id'] = self.ngfw_data['certs'][item['mapping_url_certificate_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['mapping_url_certificate_id'] = 0
                    item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in list_proxyportal:
                self.stepChanged.emit(f'uGRAY|    Ресурс веб-портала "{item["name"]}" уже существует.')
                err, result = self.utm.update_proxyportal_rule(list_proxyportal[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Ресурс веб-портала "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Ресурс веб-портала "{item["name"]}" обновлён.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_proxyportal_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Ресурс веб-портала "{item["name"]}" не импортирован]')
                else:
                    list_proxyportal[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Ресурс веб-портала "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка ресурсов веб-портала завершён.')


    def import_reverseproxy_servers(self, path):
        """Импортируем список серверов reverse-прокси"""
        json_file = os.path.join(path, 'config_reverseproxy_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов reverse-прокси в раздел "Глобальный портал/Серверы reverse-прокси".')
        error = 0

        if 'reverseproxy_servers' not in self.ngfw_data:
            if self.get_reverseproxy_servers():      # Устанавливаем атрибут self.ngfw_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
                return
        reverseproxy_servers = self.ngfw_data['reverseproxy_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя ресурса')
            if item['name'] in reverseproxy_servers:
                self.stepChanged.emit(f'uGRAY|    Сервер reverse-прокси "{item["name"]}" уже существует.')
                err, result = self.utm.update_reverseproxy_server(reverseproxy_servers[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Сервер reverse-прокси "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Сервер reverse-прокси "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_reverseproxy_server(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Сервер reverse-прокси "{item["name"]}" не импортирован]')
                else:
                    reverseproxy_servers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Сервер reverse-прокси "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов reverse-прокси завершён.')


    def import_reverseproxy_rules(self, path):
        """Импортируем список правил reverse-прокси"""
        json_file = os.path.join(path, 'config_reverseproxy_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил reverse-прокси в раздел "Глобальный портал/Правила reverse-прокси".')
        error = 0

        err, err_msg, _, result = self.utm.get_loadbalancing_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        reverse_loadbalancing = {x['name']: x['id'] for x in result}

        if 'reverseproxy_servers' not in self.ngfw_data:
            if self.get_reverseproxy_servers():      # Устанавливаем атрибут self.ngfw_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
                return
        reverseproxy_servers = self.ngfw_data['reverseproxy_servers']

        err, result = self.utm.get_nlists_list('useragent')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        useragent_list = {x['name']: x['id'] for x in result}

        if self.utm.float_version >= 7.1:
            if 'client_certificate_profiles' not in self.ngfw_data:
                if self.get_client_certificate_profiles():          # Устанавливаем атрибут self.ngfw_data['client_certificate_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси')
                    return
            client_certificate_profiles = self.ngfw_data['client_certificate_profiles']

            if self.utm.float_version < 7.3:
                waf_profiles = {}
                if self.utm.waf_license:  # Проверяем что есть лицензия на WAF
                    # Получаем список профилей WAF. Если err=2, лицензия истекла или нет прав на API.
                    err, result = self.utm.get_waf_profiles_list()
                    if err == 1:
                        self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
                        self.error = 1
                        return
                    elif not err:
                        waf_profiles = {x['name']: x['id'] for x in result}
                else:
                    self.stepChanged.emit('NOTE|    Нет лицензии на модуль WAF. Защита приложений WAF будет выключена в правилах.')

        err, result = self.utm.get_reverseproxy_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        reverseproxy_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)

            if not item['src_zones']:
                self.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не указана src-зона.')
                error = 1
                continue
            try:
                for x in item['servers']:
                    x[1] = reverseproxy_servers[x[1]] if x[0] == 'profile' else reverse_loadbalancing[x[1]]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не найден сервер reverse-прокси или балансировщик {err}. Импортируйте reverse-прокси или балансировщик и повторите попытку.')
                error = 1
                continue

            if self.utm.float_version < 6:
                item.pop('ssl_profile_id', None)
            else:
                if item['ssl_profile_id']:
                    try:
                        item['ssl_profile_id'] = self.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                        item['ssl_profile_id'] = 0
                        item['is_https'] = False
                        item['error'] = True
                else:
                    item['is_https'] = False

            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.ngfw_data['certs'][item['certificate_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = -1
                    item['is_https'] = False
                    item['error'] = True
            else:
                item['certificate_id'] = -1
                item['is_https'] = False

            new_user_agents = []
            for x in item['user_agents']:
                try:
                    new_user_agents.append(['list_id', useragent_list[x[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден Useragent {err}. Импортируйте useragent браузеров и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден Useragent {err}.'
                    item['error'] = True
            item['user_agents'] = new_user_agents

            if self.utm.float_version < 7.1:
                item.pop('user_agents_negate', None)
                item.pop('waf_profile_id', None)
                item.pop('client_certificate_profile_id', None)
            else:
                if item['client_certificate_profile_id']:
                    item['client_certificate_profile_id'] = client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
                    if not item['client_certificate_profile_id']:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Импортируйте профили пользовательских сертификатов и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                        item['error'] = True
                if self.utm.float_version < 7.3:
                    if item['waf_profile_id']:
                        if self.utm.waf_license:
                            try:
                                item['waf_profile_id'] = waf_profiles[item['waf_profile_id']]
                            except KeyError as err:
                                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль WAF {err}. Импортируйте профили WAF и повторите попытку.')
                                item['description'] = f'{item["description"]}\nError: Не найден профиль WAF {err}.'
                                item['waf_profile_id'] = 0
                                item['error'] = True
                        else:
                            item['waf_profile_id'] = 0
                            item['description'] = f'{item["description"]}\nError: Нет лицензии на модуль WAF. Профиль WAF "{item["waf_profile_id"]}" не импортирован в правило.'
                else:
                    item.pop('waf_profile_id', None)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in reverseproxy_rules:
                self.stepChanged.emit(f'uGRAY|    Правило reverse-прокси "{item["name"]}" уже существует.')
                err, result = self.utm.update_reverseproxy_rule(reverseproxy_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило reverse-прокси "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило reverse-прокси "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_reverseproxy_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило reverse-прокси "{item["name"]}" не импортировано]')
                else:
                    reverseproxy_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило reverse-прокси "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[reverseproxy_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'reverseproxy_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил reverse-прокси завершён.')
        self.stepChanged.emit('LBLUE|    Проверьте флаг "Использовать HTTPS" во всех импортированных правилах! Если не установлен профиль SSL, выберите нужный.')


    #----------------------------------- Вышестоящий прокси --------------------------------------
    def import_upstream_proxies_servers(self, path):
        """Импортируем список серверов вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        json_file = os.path.join(path, 'config_upstreamproxies_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов вышестоящих прокси в раздел "Вышестоящие прокси/Серверы".')
        error = 0

        if 'upstreamproxies_servers' not in self.ngfw_data:
            if self.get_upstreamproxies_servers():      # Устанавливаем атрибут self.ngfw_data['upstreamproxies_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов вышестоящих прокси.')
                return
        proxies_servers = self.ngfw_data['upstreamproxies_servers']

        for item in data:
#            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера прокси')
            if item['name'] in proxies_servers:
                self.stepChanged.emit(f'uGRAY|    Сервер вышестоящего прокси "{item["name"]}" уже существует.')
                err, result = self.utm.update_cascade_proxy_server(proxies_servers[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Сервер прокси "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Сервер вышестоящего прокси "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_cascade_proxy_server(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Сервер прокси "{item["name"]}" не импортирован]')
                else:
                    proxies_servers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Сервер вышестоящего прокси "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов вышестоящих прокси завершён.')


    def import_upstream_proxies_profiles(self, path):
        """Импортируем список профилей вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        json_file = os.path.join(path, 'config_upstreamproxies_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей вышестоящих прокси в раздел "Вышестоящие прокси/Профили".')
        error = 0

        if 'upstreamproxies_servers' not in self.ngfw_data:
            if self.get_upstreamproxies_servers():      # Устанавливаем атрибут self.ngfw_data['upstreamproxies_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
                return
        proxies_servers = self.ngfw_data['upstreamproxies_servers']

        if 'upstreamproxies_profiles' not in self.ngfw_data:
            if self.get_upstreamproxies_profiles():      # Устанавливаем атрибут self.ngfw_data['upstreamproxies_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
                return
        proxies_profiles = self.ngfw_data['upstreamproxies_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля прокси')
            new_servers = []
            for x in item['servers']:
                try:
                    new_servers.append(proxies_servers[x])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден сервер {err}. Импортируйте серверы прокси и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер {err}.'
                    error = 1
            item['servers'] = new_servers

            if item['name'] in proxies_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль вышестоящего прокси "{item["name"]}" уже существует.')
                err, result = self.utm.update_cascade_proxy_profile(proxies_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль прокси "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль вышестоящего прокси "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_cascade_proxy_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль прокси "{item["name"]}" не импортирован]')
                else:
                    proxies_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль вышестоящего прокси "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей вышестоящих прокси завершён.')


    def import_upstream_proxies_rules(self, path):
        """Импортируем список правил вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        json_file = os.path.join(path, 'config_upstreamproxies_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил вышестоящих прокси в раздел "Вышестоящие прокси/Правила".')
        error = 0

        if 'upstreamproxies_profiles' not in self.ngfw_data:
            if self.get_upstreamproxies_profiles():      # Устанавливаем атрибут self.ngfw_data['upstreamproxies_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
                return
        proxies_profiles = self.ngfw_data['upstreamproxies_profiles']

        if 'list_templates' not in self.ngfw_data:
            if self.get_templates_list():      # Устанавливаем атрибут self.ngfw_data['list_templates']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
                return
        list_templates = self.ngfw_data['list_templates']

        err, result = self.utm.get_cascade_proxy_rules()
        if err:
            self.stepChanged.emit('RED|    {result}\n    Произошла ошибка при импорте правил вышестоящих прокси.')
            self.error = 1
            return
        proxies_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила прокси')
            item.pop('position_layer', None)
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item.pop('cc', None)

            if item['proxy_profile']:
                try:
                    item['proxy_profile'] = proxies_profiles[item['proxy_profile']]
                except KeyError as err:
                    message = 'Импортируйте профили и повторите попытку.\n       Установлен режим работы: "Мимо прокси".'
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль прокси {err}. {message}')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль прокси {err}. Установлен режим работы: "Мимо прокси".'
                    item['proxy_profile'] = ''
                    item['action'] = 'direct'
                    item['fallback_action'] = 'direct'
                    item.pop('fallback_block_page', None)
                    error = 1
            if 'fallback_block_page' in item:
                try:
                    item['fallback_block_page'] = list_templates[item['fallback_block_page']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
                    item['fallback_block_page'] = -1
                    error = 1
            item['users'] = self.get_guids_users_and_groups(item)
            item['time_restrictions'] = self.get_time_restrictions_id(item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in proxies_rules:
                self.stepChanged.emit(f'uGRAY|    Правило вышестоящего прокси "{item["name"]}" уже существует.')
                err, result = self.utm.update_cascade_proxy_rule(proxies_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило прокси "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило вышестоящего прокси "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_cascade_proxy_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило прокси "{item["name"]}" не импортировано]')
                else:
                    proxies_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило вышестоящего прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил вышестоящих прокси завершён.')


    #------------------------------------------ WAF ----------------------------------------------
    def import_waf_custom_layers(self, path):
        """Импортируем персональные WAF-слои. Для версии 7.1 и выше"""
        if self.utm.float_version >= 7.3:
            return

        json_file = os.path.join(path, 'config_waf_custom_layers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт персональных слоёв WAF в раздел "WAF/Персональные WAF-слои".')
        if not self.utm.waf_license:
            self.stepChanged.emit('NOTE|    Нет лицензии на модуль WAF.')
            return
        error = 0

        err, result = self.utm.get_waf_custom_layers_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте персональных слоёв WAF.')
            self.error = 1
            return
        waf_custom_layers = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in waf_custom_layers:
                self.stepChanged.emit(f'uGRAY|    Персональный WAF-слой "{item["name"]}" уже существует.')
                err, result = self.utm.update_waf_custom_layer(waf_custom_layers[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Персональный WAF-слой "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Персональный WAF-слой "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_waf_custom_layer(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Персональный WAF-слой "{item["name"]}" не импортирован]')
                else:
                    waf_custom_layers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Персональный WAF-слой "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
        else:
            self.stepChanged.emit('GREEN|    Импорт персональных WAF-слоёв завершён.')


    def import_waf_profiles(self, path):
        """Импортируем профили WAF. Для версии 7.1 и выше"""
        if self.utm.float_version >= 7.3:
            return

        json_file = os.path.join(path, 'config_waf_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей WAF в раздел "WAF/WAF-профили".')
        if not self.utm.waf_license:
            self.stepChanged.emit('NOTE|    Нет лицензии на модуль WAF.')
            return
        error = 0

        err, result = self.utm.get_waf_technology_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей WAF.')
            self.error = 1
            return
        waf_technology = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_waf_custom_layers_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей WAF.')
            self.error = 1
            return
        waf_custom_layers = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_waf_system_layers_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей WAF.')
            self.error = 1
            return
        waf_system_layers = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_waf_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей WAF.')
            self.error = 1
            return
        waf_profiles = {x['name']: x['id'] for x in result}

        for item in data:
            new_layers = []
            for layer in item['layers']:
                if layer['type'] == 'custom_layer':
                    try:
                        layer['id'] = waf_custom_layers[layer['id']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден персональный WAF-слой {err}. Импортируйте персональные WAF-слои и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден персональный WAF-слой {err}.'
                        error = 1
                        continue
                else:
                    if self.utm.float_version >= 8.0:
                        self.stepChanged.emit(f'sGREEN|    [Профиль "{item["name"]}"]. Не импортирован системный WAF-слой "{layer["id"]}". В версии 8 его пока нет')
                        item['description'] = f'{item["description"]}\nError: Не импортирован системный WAF-слой "{layer["id"]}".'
                        continue
                    else:
                        try:
                            layer['id'] = waf_system_layers[layer['id']]
                            layer['protection_technologies'] = [waf_technology[x] for x in layer['protection_technologies']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден системный WAF-слой "{layer["id"]}" -  {err}.')
                            item['description'] = f'{item["description"]}\nError: Не найден системный WAF-слой "{layer["id"]}".'
                            error = 1
                            continue
                new_layers.append(layer)
            item['layers'] = new_layers

            if item['name'] in waf_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль WAF "{item["name"]}" уже существует.')
                err, result = self.utm.update_waf_profile(waf_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль WAF "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль WAF "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_waf_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль WAF "{item["name"]}" не импортирован]')
                else:
                    waf_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль WAF "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей WAF завершён.')


    #--------------------------------------- VPN ------------------------------------------------
    def import_vpn_security_profiles(self, path):
        """Импортируем список профилей безопасности VPN"""
        json_file = os.path.join(path, 'config_vpn_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей безопасности VPN в раздел "VPN/Профили безопасности VPN".')
        error = 0

        err, result = self.utm.get_vpn_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей безопасности VPN.')
            self.error = 1
            return
        security_profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if self.utm.float_version < 6:
                item.pop('peer_auth', None)
                item.pop('ike_mode', None)
                item.pop('ike_version', None)
                item.pop('p2_security', None)
                item.pop('p2_key_lifesize', None)
                item.pop('p2_key_lifesize_enabled', None)
                item.pop('p1_key_lifestime', None)
                item.pop('p2_key_lifestime', None)
                item.pop('dpd_interval', None)
                item.pop('dpd_max_failures', None)
                item.pop('dh_groups', None)

            if item['name'] in security_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
                err, result = self.utm.update_vpn_security_profile(security_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_vpn_security_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                else:
                    security_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей безопасности VPN завершён.')


    def import_vpnclient_security_profiles(self, path):
        """Импортируем клиентские профилей безопасности VPN. Для версии 7.1 и выше"""
        json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт клиентских профилей безопасности VPN в раздел "VPN/Клиентские профили безопасности".')
        error = 0

        err, result = self.utm.get_vpn_client_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
            self.error = 1
            return
        security_profiles = {x['name']: x['id'] for x in result}

        for item in data:
            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.ngfw_data['certs'][item['certificate_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = 0
                    error = 1

            if item['name'] in security_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
                err, result = self.utm.update_vpn_client_security_profile(security_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_vpn_client_security_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                else:
                    security_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт клиентских профилей безопасности завершён.')


    def import_vpnserver_security_profiles(self, path):
        """Импортируем серверные профилей безопасности VPN. Для версии 7.1 и выше"""
        json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверных профилей безопасности VPN в раздел "VPN/Серверные профили безопасности".')
        error = 0

        if 'client_certificate_profiles' not in self.ngfw_data:
            if self.get_client_certificate_profiles():          # Устанавливаем атрибут self.ngfw_data['client_certificate_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
            return
        client_certificate_profiles = self.ngfw_data['client_certificate_profiles']

        err, result = self.utm.get_vpn_server_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте серверных профилей безопасности VPN.')
            self.error = 1
            return
        security_profiles = {x['name']: x['id'] for x in result}

        for item in data:
            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.ngfw_data['certs'][item['certificate_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = 0
                    error = 1
            if item['client_certificate_profile_id']:
                try:
                    item['client_certificate_profile_id'] = client_certificate_profiles[item['client_certificate_profile_id']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль сертификата пользователя {err}. Импортируйте профили пользовательских сертификатов и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя {err}.'
                    item['client_certificate_profile_id'] = 0
                    error = 1

            if item['name'] in security_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
                err, result = self.utm.update_vpn_server_security_profile(security_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_vpn_server_security_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                else:
                    security_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверных профилей безопасности завершён.')


    def import_vpn_networks(self, path):
        """Импортируем список сетей VPN"""
        json_file = os.path.join(path, 'config_vpn_networks.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сетей VPN в раздел "VPN/Сети VPN".')
        error = 0

        err, result = self.utm.get_vpn_networks()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка сетей VPN.')
            self.error = 1
            return
        vpn_networks = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сети VPN')
            item['networks'] = self.get_vpn_networks(item['networks'], item)
            if self.utm.float_version < 7.1:
                item.pop('ep_tunnel_all_routes', None)
                item.pop('ep_disable_lan_access', None)
                item.pop('ep_routes_include', None)
                item.pop('ep_routes_exclude', None)
            else:
                item['ep_routes_include'] = self.get_vpn_networks(item['ep_routes_include'], item)
                item['ep_routes_exclude'] = self.get_vpn_networks(item['ep_routes_exclude'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in vpn_networks:
                self.stepChanged.emit(f'uGRAY|    Сеть VPN "{item["name"]}" уже существует.')
                err, result = self.utm.update_vpn_network(vpn_networks[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Сеть VPN "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Сеть VPN "{item["name"]}" обновлена.')
            else:
                err, result = self.utm.add_vpn_network(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Сеть VPN "{item["name"]}" не импортирована]')
                else:
                    vpn_networks[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Сеть VPN "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сетей VPN завершён.')


    def get_vpn_networks(self, networks, rule):
        """Для функции import_vpn_networks"""
        new_networks = []
        for x in networks:
            try:
                new_networks.append(['list_id', self.ngfw_data['ip_lists'][x[1]]] if x[0] == 'list_id' else x)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список IP-адресов {err}. Импортируйте списки IP-адресов и повторите попытку.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список IP-адресов {err}.'
                rule['error'] = 1
        return new_networks


    def import_vpn_client_rules(self, path):
        """Импортируем список клиентских правил VPN"""
        json_file = os.path.join(path, 'config_vpn_client_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт клиентских правил VPN в раздел "VPN/Клиентские правила".')
        error = 0

        if self.utm.float_version < 7.1:
            err, result = self.utm.get_vpn_security_profiles()
        else:
            err, result = self.utm.get_vpn_client_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте клиентских правил VPN.')
            self.error = 1
            return
        vpn_security_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_vpn_client_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте клиентских правил VPN.')
            self.error = 1
            return
        vpn_client_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            try:
                item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности VPN {err}.'
                item['security_profile_id'] = ""
                item['enabled'] = False
                error = 1

            if self.utm.float_version < 7.1:
                if 'xauth_login' not in item:
                    item['xauth_login'] = 'vpn'
                    item['xauth_password'] = 'vpn'
                    if self.utm.float_version >= 6:
                        item['protocol'] = 'l2tp'
                        item['subnet1'] = ''
                        item['subnet2'] = ''
                elif self.utm.float_version < 6:
                    item.pop('protocol', None)
                    item.pop('subnet1', None)
                    item.pop('subnet2', None)
            else:
                item.pop('xauth_login', None)
                item.pop('xauth_password', None)
                item.pop('protocol', None)
                item.pop('subnet1', None)
                item.pop('subnet2', None)

            if item['name'] in vpn_client_rules:
                self.stepChanged.emit(f'uGRAY|    Клиентское правило VPN "{item["name"]}" уже существует.')
                if self.utm.float_version < 7:
                    continue    # Ошибка API update_vpn_client_rule для версий 5 и 6.
                err, result = self.utm.update_vpn_client_rule(vpn_client_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Клиентское правило VPN "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Клиентское правило VPN "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_vpn_client_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Клиентское правило VPN: "{item["name"]}" не импортировано]')
                else:
                    vpn_client_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Клиентское правило VPN "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[vpn_client_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'vpn_client_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт клиентских правил VPN завершён.')


    def import_vpn_server_rules(self, path):
        """Импортируем список серверных правил VPN"""
        json_file = os.path.join(path, 'config_vpn_server_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверных правил VPN в раздел "VPN/Серверные правила".')
        error = 0

        if self.utm.float_version < 7.1:
            err, result = self.utm.get_vpn_security_profiles()
        else:
            err, result = self.utm.get_vpn_server_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте серверных правил VPN.')
            self.error = 1
            return
        vpn_security_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_vpn_networks()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте серверных правил VPN.')
            self.error = 1
            return
        vpn_networks = {x['name']: x['id'] for x in result}
        vpn_networks[False] = False

        err, result = self.utm.get_vpn_server_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте серверных правил VPN.')
            self.error = 1
            return
        vpn_server_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        tag_relations = {}
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('position_layer', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['source_ips'] = self.get_ips_id('src', item['source_ips'], item)
            if self.utm.float_version < 6:
                item.pop('dst_ips', None)
            else:
                item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item)
            try:
                item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
            except KeyError as err:
                message = f'    Error: [Правило "{item["name"]}"] Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.'
                self.stepChanged.emit(f'RED|{message}\n       Error: Правило "{item["name"]}" не импортировано.')
                error = 1
                continue
            try:
                item['tunnel_id'] = vpn_networks[item['tunnel_id']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена сеть VPN {err}. Загрузите сети VPN и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена сеть VPN {err}.'
                item['tunnel_id'] = False
                item['error'] = True
            try:
                item['auth_profile_id'] = self.ngfw_data['auth_profiles'][item['auth_profile_id']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль аутентификации {err}. Загрузите профили аутентификации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль авторизации {err}.'
                item['auth_profile_id'] = False
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in vpn_server_rules:
                self.stepChanged.emit(f'uGRAY|    Серверное правило VPN "{item["name"]}" уже существует.')
                if self.utm.float_version < 6:
                    continue    # Ошибка API update_vpn_client_rule для версий 5.
                err, result = self.utm.update_vpn_server_rule(vpn_server_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Серверное правило VPN "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Серверное правило VPN "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_vpn_server_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Серверное правило VPN "{item["name"]}" не импортировано]')
                else:
                    vpn_server_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Серверное правило VPN "{item["name"]}" импортировано.')

            if self.utm.float_version >= 7.3 and 'tags' in item:
                tag_relations[vpn_server_rules[item['name']]] = item['tags']

        if tag_relations:
            if self.add_tags_for_objects(tag_relations, 'vpn_server_rules'):
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверных правил VPN завершён.')


    #--------------------------------------- Библиотека ---------------------------------------------
    def import_morphology_lists(self, path):
        """Импортируем списки морфологии"""
        json_file = os.path.join(path, 'config_morphology_lists.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
        error = 0

        err, result = self.utm.get_nlists_list('morphology')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списков морфологии.')
            self.error = 1
            return
        morphology_list = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)
            if self.utm.float_version < 6:
                item.pop('list_type_update', None)
                item.pop('schedule', None)
                attributes = []
                attributes.append({'name': 'weight', 'value': item['attributes']['threshold']})
                attributes.append({'name': 'threat_level', 'value': item['attributes']['threat_level']})
                item['attributes'] = attributes

            if item['name'] in morphology_list:
                self.stepChanged.emit(f'uGRAY|    Список морфологии "{item["name"]}" уже существует.')
                err, result = self.utm.update_nlist(morphology_list[item['name']], item)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Список морфологии "{item["name"]}"]')
                    continue
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|       {result}')
                else:
                    self.stepChanged.emit(f'uGRAY|       Список морфологии "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_nlist(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список морфологии "{item["name"]}" не импортирован]')
                    continue
                else:
                    morphology_list[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    err2, result2 = self.utm.add_nlist_items(morphology_list[item['name']], content)
                    if err2 == 2:
                        self.stepChanged.emit(f'uGRAY|       {result2}')
                    elif err2 == 1:
                        error = 1
                        self.stepChanged.emit(f'RED|       {result2}  [Список морфологии "{item["name"]}"]')
                    else:
                        self.stepChanged.emit(f'BLACK|       Содержимое списка морфологии "{item["name"]}" обновлено.')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он обновляется удалённо.')

        if self.utm.float_version == 7.0:
            self.stepChanged.emit(f'rNOTE|    В версии 7.0 не импортируется содержимое списков морфологии, если прописаны слова в русском регистре.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списков морфологии завершён.')


    def import_services_list(self, path):
        """Импортируем список сервисов раздела библиотеки"""
        json_file = os.path.join(path, 'config_services_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
        error = 0
    
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            for value in item['protocols']:
                if self.utm.float_version < 7.1:
                    value.pop('alg', None)
                    if self.utm.float_version < 6:
                        value.pop('app_proto', None)
                        if value['port'] in ('110', '995'):
                            value['proto'] = 'tcp'
        
            if item['name'] in self.ngfw_data['services']:
                self.stepChanged.emit(f'uGRAY|    Сервис "{item["name"]}" уже существует.')
            else:
                err, result = self.utm.add_service(item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Сервис "{item["name"]}"]')
                    error = 1
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    self.ngfw_data['services'][item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" добавлен.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов!')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сервисов завершён.')


    def import_services_groups(self, path):
        """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
        json_file = os.path.join(path, 'config_services_groups_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп сервисов в раздел "Библиотеки/Группы сервисов".')
        error = 0

        for item in data:
            content = item.pop('content')
            item.pop('last_update', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
        
            if item['name'] in self.ngfw_data['service_groups']:
                self.stepChanged.emit(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует.')
                err, result = self.utm.update_nlist(self.ngfw_data['service_groups'][item['name']], item)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Группа сервисов: "{item["name"]}"]')
                    continue
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|       {result}')
                else:
                    self.stepChanged.emit(f'uGRAY|       Группа сервисов "{item["name"]}" обновлена.')
            else:
                err, result = self.utm.add_nlist(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                    continue
                else:
                    self.ngfw_data['service_groups'][item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

            if content:
                new_content = []
                for service in content:
                    try:
                        service['value'] = self.ngfw_data['services'][self.get_transformed_name(service['name'], mode=0)[1]]
                        new_content.append(service)
                    except KeyError as err:
                        self.stepChanged.emit(f'bRED|       Error: Не найден сервис {err}. Загрузите сервисы и повторите попытку.')

                err2, result2 = self.utm.add_nlist_items(self.ngfw_data['service_groups'][item['name']], new_content)
                if err2 == 1:
                    self.stepChanged.emit(f'RED|       {result2}  [Группа сервисов "{item["name"]}"]')
                    error = 1
                elif err2 == 2:
                    self.stepChanged.emit(f'GRAY|       {result2}')
                else:
                    self.stepChanged.emit(f'BLACK|       Содержимое группы сервисов "{item["name"]}" импортировано.')
            else:
                self.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп сервисов завершён.')


    def import_ip_lists(self, path):
        """Импортируем списки IP адресов"""
        if not os.path.isdir(path):
            return
        self.stepChanged.emit('BLUE|Импорт списков IP-адресов в раздел "Библиотеки/IP-адреса".')
        files_list = os.listdir(path)
        if not files_list:
            self.stepChanged.emit("GRAY|    Нет списков IP-адресов для импорта.")
            return
        error = 0
        n = 0

        # Импортируем все списки IP-адресов без содержимого (пустые).
        self.stepChanged.emit(f'LBLUE|    Импортируем списки IP-адресов без содержимого.')
        for file_name in files_list:
            n += 1
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            content = data.pop('content')
            data.pop('last_update', None)
            if self.utm.float_version < 6:
                data['attributes'] = [{'name': 'threat_level', 'value': data['attributes']['threat_level']}]
                data.pop('list_type_update', None)
                data.pop('schedule', None)
            if data['name'] in self.ngfw_data['ip_lists']:
                self.stepChanged.emit(f'uGRAY|    {n} - Список IP-адресов "{data["name"]}" уже существует.')
                err, result = self.utm.update_nlist(self.ngfw_data['ip_lists'][data['name']], data)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Список IP-адресов "{data["name"]}"]')
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    self.stepChanged.emit(f'BLACK|       Список IP-адресов "{data["name"]}" обновлён.')
            else:
                err, result = self.utm.add_nlist(data)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирован]')
                else:
                    self.ngfw_data['ip_lists'][data['name']] = result
                    self.stepChanged.emit(f'BLACK|    {n} - Список IP-адресов "{data["name"]}" импортирован.')

        # Добавляем содержимое в уже добавленные списки IP-адресов.
        n = 0
        self.stepChanged.emit(f'LBLUE|    Импортируем содержимое списков IP-адресов.')
        for file_name in files_list:
            n += 1
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            _, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка', mode=0)
            try:
                list_id = self.ngfw_data['ip_lists'][data['name']]
            except KeyError:
                message = f'    Error: Нет IP-листа "{data["name"]}" в списках IP-адресов NGFW.'
                self.stepChanged.emit(f'RED|{message}\n    Error: Содержимое не добавлено в список IP-адресов "{data["name"]}".')
                error = 1
                continue
            if data['content']:
                new_content = []
                for item in data['content']:
                    if 'list' in item:
                        if self.utm.float_version >= 7:
                            item_list = self.get_transformed_name(item['list'], descr='Имя списка', mode=0)[1]
                            try:
                                item['list'] = self.ngfw_data['ip_lists'][item_list]
                                new_content.append(item)
                            except KeyError:
                                message = f'    Error: Нет IP-листа "{item_list}" в списках IP-адресов NGFW.'
                                self.stepChanged.emit(f'RED|{message}\n    Error: Список "{item_list}" не добавлен в список IP-адресов "{data["name"]}".')
                                error = 1
                        else:
                            self.stepChanged.emit(f'GRAY|    В список "{data["name"]}" не добавлен IP-лист "{item["list"]}". NGFW версии "{self.utm.float_version}" не поддерживает содержимое в виде списков IP-адресов.')
                    else:
                        new_content.append(item)

                err2, result2 = self.utm.add_nlist_items(list_id, new_content)
                if err2 == 1:
                    self.stepChanged.emit(f'RED|    {result2}  [Список IP-адресов "{data["name"]}"]')
                    error = 1
                elif err2 == 2:
                    self.stepChanged.emit(f'GRAY|    {result2}')
                else:
                    self.stepChanged.emit(f'BLACK|    {n} - Содержимое списка IP-адресов "{data["name"]}" импортировано.')
            else:
                self.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списков IP-адресов завершён.')


    def import_useragent_lists(self, path):
        """Импортируем списки Useragent браузеров"""
        json_file = os.path.join(path, 'config_useragents_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Useragent браузеров" в раздел "Библиотеки/Useragent браузеров".')
        error = 0
        err, result = self.utm.get_nlists_list('useragent')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списков Useragent браузеров.')
            self.error = 1
            return
        useragent_list = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            content = item.pop('content')
            item.pop('last_update', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            if self.utm.float_version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)

            if item['name'] in useragent_list:
                self.stepChanged.emit(f'uGRAY|    Список Useragent "{item["name"]}" уже существует.')
                err, result = self.utm.update_nlist(useragent_list[item['name']], item)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Список Useragent {item["name"]}]')
                    continue
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|       {result}')
                else:
                    self.stepChanged.emit(f'BLACK|       Список Useragent "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_nlist(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список Useragent "{item["name"]}" не импортирован]')
                    continue
                else:
                    useragent_list[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

            if content:
                err2, result2 = self.utm.add_nlist_items(useragent_list[item['name']], content)
                if err2 == 2:
                    self.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result2}  [Список Useragent: "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'BLACK|       Содержимое списка Useragent "{item["name"]}" импортировано.')
            else:
                self.stepChanged.emit(f'GRAY|       Список Useragent "{item["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Useragent браузеров" завершён.')


    def import_mime_lists(self, path):
        """Импортируем списки Типов контента"""
        json_file = os.path.join(path, 'config_mime_types.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Типы контента" в раздел "Библиотеки/Типы контента".')
        error = 0
        err, result = self.utm.get_nlists_list('mime')
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        mime_list = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            content = item.pop('content')
            item.pop('last_update', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            if self.utm.float_version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)

            if item['name'] in mime_list:
                self.stepChanged.emit(f'GRAY|    Список Типов контента "{item["name"]}" уже существует.')
                err, result = self.utm.update_nlist(mime_list[item['name']], item)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список Типов контента: {item["name"]}]')
                    continue
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    self.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_nlist(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список Типов контента: "{item["name"]}"]')
                    continue
                else:
                    mime_list[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

            if content:
                err2, result2 = self.utm.add_nlist_items(mime_list[item['name']], content)
                if err2 == 2:
                    self.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result2}  [Список Типов контента: "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'BLACK|       Содержимое списка Типов контента "{item["name"]}" обновлено.')
            else:
                self.stepChanged.emit(f'GRAY|       Список Типов контента "{item["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Типы контента" завершён.')


    def import_url_lists(self, path):
        """Импортируем списки URL"""
        if not os.path.isdir(path):
            return
        self.stepChanged.emit('BLUE|Импорт списков URL в раздел "Библиотеки/Списки URL".')
        error = 0

        files_list = os.listdir(path)
        if not files_list:
            self.stepChanged.emit("GRAY|    Нет списков URL для импорта.")
            return

        # Импортируем все списки URL без содержимого (пустые).
        self.stepChanged.emit(f'LBLUE|    Импортируем списки URL без содержимого.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            content = data.pop('content')
            data.pop('last_update', None)
            if self.utm.float_version < 6:
                data['attributes'] = [{'name': 'threat_level', 'value': 3}]
                data.pop('list_type_update', None)
                data.pop('schedule', None)
            elif self.utm.float_version < 7.1:
                data['attributes'] = {}
            else:
                if not data['attributes'] or 'threat_level' in data['attributes']:
                    data['attributes'] = {'list_compile_type': 'case_insensitive'}

            if data['name'] in self.ngfw_data['url_lists']:
                self.stepChanged.emit(f'GRAY|    Список URL "{data["name"]}" уже существует.')
                err, result = self.utm.update_nlist(self.ngfw_data['url_lists'][data['name']], data)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список URL: "{data["name"]}"]')
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    self.stepChanged.emit(f'BLACK|       Список URL "{data["name"]}" updated.')
            else:
                err, result = self.utm.add_nlist(data)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Список URL: "{data["name"]}" не импортирован]')
                else:
                    self.ngfw_data['url_lists'][data['name']] = result
                    self.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

        # Добавляем содержимое в уже добавленные списки URL.
        self.stepChanged.emit(f'LBLUE|    Импортируем содержимое списков URL.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            try:
                list_id = self.ngfw_data['url_lists'][data['name']]
            except KeyError:
                message = f'    Error: Нет листа URL "{data["name"]}" в списках URL листов NGFW.'
                self.stepChanged.emit(f'RED|{meaage}\n    Error: Содержимое не добавлено в список URL "{data["name"]}".')
                error = 1
                continue
            if data['content']:
                err2, result2 = self.utm.add_nlist_items(list_id, data['content'])
                if err2 == 1:
                    self.stepChanged.emit(f'RED|    {result2}  [Список URL: "{data["name"]}" - содержимое не импортировано]')
                    error = 1
                elif err2 == 2:
                    self.stepChanged.emit(f'GRAY|    {result2}')
                else:
                    self.stepChanged.emit(f'BLACK|    Содержимое списка URL "{data["name"]}" обновлено. Added {result2} record.')
            else:
                self.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списков URL завершён.')


    def import_time_restricted_lists(self, path):
        """Импортируем содержимое календарей"""
        json_file = os.path.join(path, 'config_calendars.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
        error = 0

        for item in data:
            content = item.pop('content')
            item.pop('last_update', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            if self.utm.float_version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)

            if item['name'] in self.ngfw_data['calendars']:
                self.stepChanged.emit(f'uGRAY|    Календарь "{item["name"]}" уже существует.')
                err, result = self.utm.update_nlist(self.ngfw_data['calendars'][item['name']], item)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Календарь: {item["name"]}]')
                    continue
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|       {result}')
                else:
                    self.stepChanged.emit(f'BLACK|       Календарь "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_nlist(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Календарь: "{item["name"]}" не импортирован]')
                    continue
                else:
                    self.ngfw_data['calendars'][item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

            if self.utm.float_version < 6:
                self.stepChanged.emit(f'GRAY|       На версию 5 невозможно импортировать сожержимое календарей. Добавьте содержимое вручную.')
                continue
            if content:
                if self.utm.float_version >= 7.1:
                    for value in content:
                        err2, result2 = self.utm.add_nlist_item(self.ngfw_data['calendars'][item['name']], value)
                        if err2 == 2:
                            self.stepChanged.emit(f'uGRAY|          Элемент "{value["name"]}" уже существует в календаре "{item["name"]}".')
                        elif err2 == 1:
                            error = 1
                            self.stepChanged.emit(f'RED|          {result2}  [Календарь: "{item["name"]}"]')
                        else:
                            self.stepChanged.emit(f'BLACK|          Элемент "{value["name"]}" календаря "{item["name"]}" добавлен.')
                else:
                    err2, result2 = self.utm.add_nlist_items(self.ngfw_data['calendars'][item['name']], content)
                    if err2 == 2:
                        self.stepChanged.emit(f'uGRAY|          {result2}')
                    elif err2 == 1:
                        error = 1
                        self.stepChanged.emit(f'RED|          {result2}  [Календарь: "{item["name"]}"]')
                    else:
                        self.stepChanged.emit(f'BLACK|          Содержимое календаря "{item["name"]}" обновлено.')
            else:
                self.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Календари" завершён.')


    def import_shaper_list(self, path):
        """Импортируем список Полос пропускания раздела библиотеки"""
        json_file = os.path.join(path, 'config_shaper_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
        error = 0

        err, result = self.utm.get_shaper_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка "Полосы пропускания".')
            self.error = 1
            return
        shaper_list = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            if item['name'] in shaper_list:
                self.stepChanged.emit(f'uGRAY|    Полоса пропускания "{item["name"]}" уже существует.')
                err, result = self.utm.update_shaper(shaper_list[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Полоса пропускания: {item["name"]} не обновлена]')
                else:
                    self.stepChanged.emit(f'BLACK|       Полоса пропускания "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_shaper(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: "{item["name"]}" не импортирована]')
                else:
                    shaper_list[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Полосы пропускания" завершён.')


    def import_scada_profiles(self, path):
        """Импортируем список профилей АСУ ТП"""
        json_file = os.path.join(path, 'config_scada_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка профилей АСУ ТП в раздел "Библиотеки/Профили АСУ ТП".')

        err, result = self.utm.get_scada_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка "Профили АСУ ТП".')
            self.error = 1
            return
        scada_profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            if self.utm.float_version < 6:
                item['units'] = [unit for unit in item['units'] if unit['protocol'] != 'opcua']

            if item['name'] in scada_profiles:
                self.stepChanged.emit(f'GRAY|    Профиль АСУ ТП "{item["name"]}" уже существует.')
                err, result = self.utm.update_scada(scada_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль АСУ ТП: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|    Профиль АСУ ТП "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_scada(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль АСУ ТП: "{item["name"]}"]')
                else:
                    scada_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль АСУ ТП "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Профили АСУ ТП".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка профилей АСУ ТП завершён.')


    def import_templates_list(self, path):
        """
        Импортируем список шаблонов страниц.
        После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
        """
        json_file = os.path.join(path, 'config_templates_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка шаблонов страниц в раздел "Библиотеки/Шаблоны страниц".')
        error = 0
        html_files = os.listdir(path)

        if 'list_templates' not in self.ngfw_data:
            if self.get_templates_list():    # Устанавливаем атрибут self.ngfw_data['list_templates']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
                return
        list_templates = self.ngfw_data['list_templates']

        for item in data:
            if item['name'] in list_templates:
                self.stepChanged.emit(f'GRAY|    Шаблон страницы "{item["name"]}" уже существует.')
                err, result = self.utm.update_template(list_templates[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_template(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: "{item["name"]}" не импортирован]')
                    continue
                else:
                    list_templates[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

            if f"{item['name']}.html" in html_files:
                with open(os.path.join(path, f'{item["name"]}.html'), "br") as fh:
                    file_data = fh.read()
                err2, result2 = self.utm.set_template_data(list_templates[item['name']], file_data)
                if err2:
                    self.stepChanged.emit(f'RED|       {result2} [Страница "{item["name"]}.html" не импортирована]')
                    self.error = 1
                else:
                    self.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка шаблонов страниц завершён.')


    def import_url_categories(self, path):
        """Импортируем группы URL категорий с содержимым на UTM"""
        json_file = os.path.join(path, 'config_url_categories.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Категории URL".')
        error = 0

        for item in data:
            if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                    'Recommended for morphology checking', 'Recommended for virus check']:
                content = item.pop('content')
                item.pop('last_update', None)
                item.pop('guid', None)
                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя категории')
                if self.utm.float_version < 6:
                    item['attributes'] = []
                    item.pop('list_type_update', None)
                    item.pop('schedule', None)
                if item['name'] in self.ngfw_data['url_categorygroups']:
                    self.stepChanged.emit(f'GRAY|    Группа URL категорий "{item["name"]}" уже существует.')
                    err, result = self.utm.update_nlist(self.ngfw_data['url_categorygroups'][item['name']], item)
                    if err:
                        error = 1
                        self.stepChanged.emit(f'RED|    {result}  [Группа URL категорий: {item["name"]}]')
                        continue
                    else:
                        self.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" updated.')
                else:
                    err, result = self.utm.add_nlist(item)
                    if err:
                        error = 1
                        self.stepChanged.emit(f'RED|    {result}  [Группа URL категорий: "{item["name"]}" не импортирована]')
                        continue
                    else:
                        self.ngfw_data['url_categorygroups'][item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')
                
                if self.utm.float_version < 6:
                    self.stepChanged.emit(f'GRAY|       На версию 5 невозможно импортировать сожержимое URL категорий. Добавьте содержимое вручную.')
                    continue
                if content:
                    err2, result2 = self.utm.add_nlist_items(self.ngfw_data['url_categorygroups'][item['name']], content)
                    if err2 == 2:
                        self.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        error = 1
                        self.stepChanged.emit(f'RED|       {result2}  [Список: "{item["name"]}"]')
                    else:
                        self.stepChanged.emit(f'BLACK|       Содержимое списка "{item["name"]}" обновлено.')
                else:
                    self.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте URL категорий.')
        else:
            self.stepChanged.emit('GREEN|    Импорт категорий URL завершён.')


    def import_custom_url_category(self, path):
        """Импортируем изменённые категории URL"""
        json_file = os.path.join(path, 'custom_url_categories.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
        error = 0

        err, result = self.utm.get_custom_url_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте изменённых категорий URL.')
            self.error = 1
            return
        custom_url = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('user', None)
            item.pop('change_date', None)
            item.pop('default_categories', None)
            try:
                item['categories'] = [self.ngfw_data['url_categories'][x] for x in item['categories']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {err}. Правило  не добавлено.')
                error = 1
                continue

            if item['name'] in custom_url:
                self.stepChanged.emit(f'GRAY|    URL категория "{item["name"]}" уже существует.')
                err, result = self.utm.update_custom_url(custom_url[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [URL категория: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|    URL категория "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_custom_url(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [URL категория: "{item["name"]}" не импортирована]')
                else:
                    custom_url[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Изменённая категория URL "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт изменённых категории URL завершён.')


    def import_application_signature(self, path):
        """Импортируем список "Приложения" на UTM для версии 7.1 и выше"""
        json_file = os.path.join(path, 'config_applications.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
        error = 0

        err, result = self.utm.get_version71_apps(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте пользовательских приложений.')
            self.error = 1
            return
        apps = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('signature_id', None)

            new_l7categories = []
            for category in item['l7categories']:
                try:
                    new_l7categories.append(self.ngfw_data['l7_categories'][category])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Категория {err} не существует на NGFW. Категория не добавлена.')
                    error = 1
            item['l7categories'] = new_l7categories

            if item['name'] in apps:
                self.stepChanged.emit(f'GRAY|    Приложение "{item["name"]}" уже существует.')
                err, result = self.utm.update_version71_app(apps[item['name']], item)
                if err == 1:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Приложение: {item["name"]}]')
                elif err == 2:
                    self.stepChanged.emit(f'GRAY|       {result}')
                else:
                    self.stepChanged.emit(f'BLACK|       Приложение "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_version71_app(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Приложение: "{item["name"]}" не импортировано]')
                else:
                    apps[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт пользовательских приложений завершён.')


    def import_app_profiles(self, path):
        """Импортируем профили приложений. Только для версии 7.1 и выше."""
        json_file = os.path.join(path, 'config_app_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
        error = 0

        err, result = self.utm.get_l7_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей приложений.')
            self.error = 1
            return
        l7profiles = {x['name']: x['id'] for x in result}

        for item in data:
            new_overrides = []
            for app in item['overrides']:
                try:
                    app['id'] = self.ngfw_data['l7_apps'][app['id']]
                    new_overrides.append(app)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило: "{item["name"]}"] Не найдено приложение {err}.')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in l7profiles:
                self.stepChanged.emit(f'GRAY|    Профиль приложений "{item["name"]}" уже существует.')
                err, result = self.utm.update_l7_profile(l7profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль приложений: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль приложений "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_l7_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль приложений: "{item["name"]}" не импортирован]')
                else:
                    l7profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей приложений завершён.')


    def import_application_groups(self, path):
        """Импортируем группы приложений."""
        json_file = os.path.join(path, 'config_application_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп приложений раздела "Библиотеки/Группы приложений".')
        error = 0

        if self.utm.float_version >= 7.1:
            self.stepChanged.emit('NOTE|    Загрузка списка приложений с NGFW, это может быть долго...')
            err, result = self.utm.get_version71_apps()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте групп приложений.')
                self.error = 1
                return
            apps = {x['name']: x['signature_id'] for x in result}
        else:
            apps = self.ngfw_data['l7_apps']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы приложений')
            content = item.pop('content')
            item.pop('last_update', None)
            if self.utm.float_version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)

            err = self.execute_add_update_nlist(self.ngfw_data['application_groups'], item, 'Группа приложений')
            if err:
                error = 1
                continue

            if content:
                new_content = []
                for app in content:
                    if 'name' not in app:     # Это бывает при некорректном добавлении приложения через API
                        self.stepChanged.emit(f'RED|       Error: [Группа приложений "{item["name"]}"] Приложение "{app}" не добавлено так как не содержит имя.')
                        error = 1
                        continue
                    try:
                        signature_id = apps[app['name']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Группа приложений "{item["name"]}"] Не найдено приложение "{app["name"]}". Приложение не импортировано.')
                        error = 1
                        continue
                    new_content.append({'value': signature_id})
                content = new_content

                err = self.execute_add_nlist_items(self.ngfw_data['application_groups'][item['name']], item['name'], content)
                if err:
                    error = 1
            else:
                self.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп приложений завершён.')


    def import_email_groups(self, path):
        """Импортируем группы почтовых адресов."""
        json_file = os.path.join(path, 'config_email_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп почтовых адресов раздела "Библиотеки/Почтовые адреса".')
        error = 0

        err, result = self.utm.get_nlist_list('emailgroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте групп почтовых адресов.')
            self.error = 1
            return
        emailgroups = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы почтовых адресов')
            content = item.pop('content')
            item.pop('last_update', None)
            if self.utm.float_version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)

            err = self.execute_add_update_nlist(emailgroups, item, 'Группа почтовых адресов')
            if err:
                error = 1
                continue

            if content:
                err = self.execute_add_nlist_items(emailgroups[item['name']], item['name'], content)
                if err:
                    error = 1
            else:
                self.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп почтовых адресов завершён.')


    def import_phone_groups(self, path):
        """Импортируем группы телефонных номеров."""
        json_file = os.path.join(path, 'config_phone_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп телефонных номеров раздела "Библиотеки/Номера телефонов".')
        error = 0

        err, result = self.utm.get_nlist_list('phonegroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте групп телефонных номеров.')
            self.error = 1
            return
        phonegroups = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы телефонных номеров')
            content = item.pop('content')
            item.pop('last_update', None)
            if self.utm.float_version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)

            err = self.execute_add_update_nlist(phonegroups, item, 'Группа телефонных номеров')
            if err:
                error = 1
                continue

            if content:
                err = self.execute_add_nlist_items(phonegroups[item['name']], item['name'], content)
                if err:
                    error = 1
            else:
                self.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп телефонных номеров завершён.')


    def import_custom_idps_signature(self, path):
        """Импортируем пользовательские сигнатуры СОВ. Только для версии 7.1 и выше"""
        json_file = os.path.join(path, 'custom_idps_signatures.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
        error = 0

        err, result = self.utm.get_idps_signatures_list(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        signatures = {x['msg']: x['id'] for x in result}

        for item in data:
            if item['msg'] in signatures:
                self.stepChanged.emit(f'GRAY|    Сигнатура СОВ "{item["msg"]}" уже существует.')
                err, result = self.utm.update_idps_signature(signatures[item['msg']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Сигнатура СОВ: {item["msg"]}]')
                    continue
                else:
                    self.stepChanged.emit(f'BLACK|       Сигнатура СОВ "{item["msg"]}" updated.')
            else:
                err, result = self.utm.add_idps_signature(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ: "{item["msg"]}" не импортирована]')
                    continue
                else:
                    signatures[item['msg']] = result
                    self.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
        else:
            self.stepChanged.emit('GREEN|    Импорт пользовательских сигнатур СОВ завершён.')


    def import_idps_profiles(self, path):
        """Импортируем профили СОВ"""
        json_file = os.path.join(path, 'config_idps_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
        error = 0

        if self.utm.float_version < 6:
            self.stepChanged.emit('RED|    Импорт профилей СОВ на версию 5 не поддерживается.')
            error = 1
        elif self.utm.float_version < 7.1:
            err, result = self.utm.get_nlist_list('ipspolicy')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей СОВ.')
                self.error = 1
                return
            idps = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

            for item in data:
                if 'filters' in item:
                    self.stepChanged.emit('RED|    Error: Импорт профилей СОВ версий 7.1 и выше на более старые версии не поддерживается.')
                    error = 1
                    break

                error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
                content = item.pop('content')
                item.pop('last_update', None)

                err = self.execute_add_update_nlist(idps, item, 'Профиль СОВ')
                if err:
                    error = 1
                    continue
                if content:
                    new_content = []
                    for signature in content:
                        if 'value' not in signature:
                            self.stepChanged.emit(f'RED|    Error: [Профиль СОВ "{item["name"]}"] Сигнатура "{signature["msg"]}" пропущена так как формат не соответствует целевой системе.')
                            error = 1
                            continue
                        new_content.append({'value': signature['value']})
                    content = new_content

                    err = self.execute_add_nlist_items(idps[item['name']], item['name'], content)
                    if err:
                        error = 1
                else:
                    self.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')
        else:
            err, result = self.utm.get_idps_profiles_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей СОВ.')
                self.error = 1
                return
            profiles = {x['name']: x['id'] for x in result}

            err, result = self.utm.get_idps_signatures_list(query={'query': 'owner = You'})
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей СОВ.')
                self.error = 1
                return
            custom_idps = {x['msg']: x['id'] for x in result}

            for item in data:
                if 'filters' not in item:
                    self.stepChanged.emit('RED|    Error: Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
                    error = 1
                    break
                # Исключаем отсутствующие сигнатуры. Получаем ID сигнатур по имени так как ID может не совпадать.
                new_overrides = []
                for signature in item['overrides']:
                    try:
                        if 1000000 < signature['signature_id'] < 1099999:
                            signature['id'] = custom_idps[signature['msg']]
#                        signature.pop('signature_id', None)
#                        signature.pop('msg', None)
                        new_overrides.append(signature)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Профиль СОВ "{item["name"]}"] Не найдена сигнатура {err}.')
                        error = 1
                item['overrides'] = new_overrides

                if item['name'] in profiles:
                    self.stepChanged.emit(f'GRAY|    Профиль СОВ "{item["name"]}" уже существует.')
                    err, result = self.utm.update_idps_profile(profiles[item['name']], item)
                    if err:
                        error = 1
                        self.stepChanged.emit(f'RED|       {result}  [Профиль СОВ: {item["name"]}]')
                    else:
                        self.stepChanged.emit(f'BLACK|       Профиль СОВ "{item["name"]}" updated.')
                else:
                    err, result = self.utm.add_idps_profile(item)
                    if err:
                        error = 1
                        self.stepChanged.emit(f'RED|    {result}  [Профиль СОВ: "{item["name"]}" не импортирован]')
                    else:
                        profiles[item['name']] = result
                        self.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей СОВ завершён.')


    def import_notification_profiles(self, path):
        """Импортируем список профилей оповещения"""
        json_file = os.path.join(path, 'config_notification_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
        error = 0

        if 'notification_profiles' not in self.ngfw_data:
            if self.get_notification_profiles():      # Устанавливаем атрибут self.ngfw_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
                return
        notification_profiles = self.ngfw_data['notification_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля оповещения')
            if item['name'] in notification_profiles:
                self.stepChanged.emit(f'GRAY|    Профиль оповещения "{item["name"]}" уже существует.')
                err, result = self.utm.update_notification_profile(notification_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль оповещения: {item["name"]}]')
                    continue
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль оповещения "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_notification_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: "{item["name"]}" не импортирован]')
                    continue
                else:
                    notification_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
                
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей оповещений завершён.')


    def import_netflow_profiles(self, path):
        """Импортируем список профилей netflow"""
        json_file = os.path.join(path, 'config_netflow_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей netflow в раздел "Библиотеки/Профили netflow".')
        error = 0

        err, result = self.utm.get_netflow_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей netflow.')
            self.error = 1
            return
        profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in profiles:
                self.stepChanged.emit(f'GRAY|    Профиль netflow "{item["name"]}" уже существует.')
                err, result = self.utm.update_netflow_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль netflow: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль netflow "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_netflow_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль netflow: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей netflow завершён.')


    def import_lldp_profiles(self, path):
        """Импортируем список профилей LLDP"""
        json_file = os.path.join(path, 'config_lldp_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
        error = 0

        err, result = self.utm.get_lldp_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей LLDP.')
            self.error = 1
            return
        profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in profiles:
                self.stepChanged.emit(f'GRAY|    Профиль LLDP "{item["name"]}" уже существует.')
                err, result = self.utm.update_lldp_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль LLDP: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль LLDP "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_lldp_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль LLDP: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей LLDP завершён.')


    def import_ssl_profiles(self, path):
        """Импортируем список профилей SSL"""
        json_file = os.path.join(path, 'config_ssl_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей SSL в раздел "Библиотеки/Профили SSL".')
        error = 0

        for item in data:
            if self.utm.float_version < 7.1:
                item.pop('supported_groups', None)
            else:
                if 'supported_groups' not in item:
                    item['supported_groups'] = []
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')

            ssl_profiles = self.ngfw_data['ssl_profiles']
            if item['name'] in ssl_profiles:
                self.stepChanged.emit(f'GRAY|    Профиль SSL "{item["name"]}" уже существует.')
                err, result = self.utm.update_ssl_profile(ssl_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль SSL: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль SSL "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_ssl_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль SSL: "{item["name"]}" не импортирован]')
                else:
                    ssl_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей SSL .')


    def import_ssl_forward_profiles(self, path):
        """Импортируем профили пересылки SSL"""
        json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
        error = 0

        err, result = self.utm.get_ssl_forward_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей пересылки SSL.')
            self.error = 1
            return
        profiles = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in profiles:
                self.stepChanged.emit(f'GRAY|    Профиль пересылки SSL "{item["name"]}" уже существует.')
                err, result = self.utm.update_ssl_forward_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль пересылки SSL: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль пересылки SSL "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_ssl_forward_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей пересылки SSL завершён.')


    def import_hip_objects(self, path):
        """Импортируем HIP объекты"""
        json_file = os.path.join(path, 'config_hip_objects.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт HIP объектов в раздел "Библиотеки/HIP объекты".')
        error = 0

        if self.utm.float_version >= 8.0:
            self.stepChanged.emit(f'ORANGE|    Импорт HIP объектов не доступен в версии {self.utm.version}.')
            return

        err, result = self.utm.get_hip_objects_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте HIP объектов.')
            self.error = 1
            return
        profiles = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in profiles:
                self.stepChanged.emit(f'GRAY|    HIP объект "{item["name"]}" уже существует.')
                err, result = self.utm.update_hip_object(profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [HIP объект: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       HIP объект "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_hip_object(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [HIP объект: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт HIP объектов завершён.')


    def import_hip_profiles(self, path):
        """Импортируем HIP профили"""
        json_file = os.path.join(path, 'config_hip_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт HIP профилей в раздел "Библиотеки/HIP профили".')
        error = 0

        if self.utm.float_version >= 8.0:
            self.stepChanged.emit(f'ORANGE|    Импорт HIP профилей не доступен в версии {self.utm.version}.')
            return

        err, result = self.utm.get_hip_objects_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте HIP профилей.')
            self.error = 1
            return
        hip_objects = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_hip_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте HIP профилей.')
            self.error = 1
            return
        profiles = {x['name']: x['id'] for x in result}

        for item in data:
            for obj in item['hip_objects']:
                obj['id'] = hip_objects[obj['id']]
            if item['name'] in profiles:
                self.stepChanged.emit(f'GRAY|    HIP профиль "{item["name"]}" уже существует.')
                err, result = self.utm.update_hip_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [HIP профиль: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       HIP профиль "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_hip_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [HIP профиль: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт HIP профилей завершён.')


    def import_bfd_profiles(self, path):
        """Импортируем профили BFD"""
        json_file = os.path.join(path, 'config_bfd_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей BFD в раздел "Библиотеки/Профили BFD".')
        error = 0

        err, result = self.utm.get_bfd_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей BFD.')
            self.error = 1
            return
        profiles = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in profiles:
                self.stepChanged.emit(f'GRAY|    Профиль BFD "{item["name"]}" уже существует.')
                err, result = self.utm.update_bfd_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль BFD: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Профиль BFD "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_bfd_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей BFD завершён.')


    def import_useridagent_syslog_filters(self, path):
        """Импортируем syslog фильтры UserID агента"""
        json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт syslog фильтров UserID агента в раздел "Библиотеки/Syslog фильтры UserID агента".')
        error = 0
        err, result = self.utm.get_useridagent_filters_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте syslog фильтров UserID агента.')
            self.error = 1
            return
        filters = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in filters:
                self.stepChanged.emit(f'GRAY|    Фильтр "{item["name"]}" уже существует.')
                err, result = self.utm.update_useridagent_filter(filters[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Фильтр: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Фильтр "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_useridagent_filter(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Фильтр: "{item["name"]}" не импортирован]')
                else:
                    filters[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Syslog фильтров UserID агента завершён.')


    def import_scenarios(self, path):
        """Импортируем список сценариев"""
        json_file = os.path.join(path, 'config_scenarios.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сценариев в раздел "Библиотеки/Сценарии".')
        error = 0

        if 'scenarios_rules' not in self.ngfw_data:
            if self.get_scenarios_rules():     # Устанавливаем атрибут self.ngfw_data['scenarios_rules']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
                return
        scenarios_rules = self.ngfw_data['scenarios_rules']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сценария')
            new_conditions = []
            for condition in item['conditions']:
                if condition['kind'] == 'application':
                    condition['apps'] = self.get_apps(item, apps=condition['apps'])
                elif condition['kind'] == 'mime_types':
                    try:
                        condition['content_types'] = [self.ngfw_data['mime'][x] for x in condition['content_types']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найден тип контента {err}. Загрузите типы контента и повторите попытку.')
                        condition['content_types'] = []
                        error = 1
                elif condition['kind'] == 'url_category':
                    condition['url_categories'] = self.get_url_categories_id(condition['url_categories'], item['name'])
                elif condition['kind'] == 'health_check':
                    if self.utm.float_version < 6:
                        self.stepChanged.emit(f'bRED|    Error: [Сценарий "{item["name"]}"] Условие "Проверка состояния" не поддерживается в версии 5.')
                        continue
                    elif self.utm.float_version == 7.0:
                        self.stepChanged.emit(f'bRED|    Error: [Сценарий "{item["name"]}"] Условие "Проверка состояния" нельзя импортировать в версию 7.0.')
                        continue
                new_conditions.append(condition)
            item['conditions'] = new_conditions

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in scenarios_rules:
                self.stepChanged.emit(f'GRAY|    Сценарий "{item["name"]}" уже существует.')
                err, result = self.utm.update_scenarios_rule(scenarios_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Сценарий: {item["name"]}]')
                    continue
                else:
                    self.stepChanged.emit(f'BLACK|       Сценарий "{item["name"]}" updated.')
            else:
                err, result = self.utm.add_scenarios_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Сценарий: "{item["name"]}" не импортирован]')
                    continue
                else:
                    scenarios_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сценариев завершён.')


    def import_tags(self, path):
        """Импортируем Тэги"""
        json_file = os.path.join(path, 'config_tags.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт тэгов в раздел "Библиотеки/Тэги".')
        error = 0
        err, result = self.utm.get_tags_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте тэгов.')
            self.error = 1
            return
        tags = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in tags:
                self.stepChanged.emit(f'GRAY|    Тэг "{item["name"]}" уже существует.')
                err, result = self.utm.update_tag(tags[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Тэг: {item["name"]}]')
                else:
                    self.stepChanged.emit(f'BLACK|       Тэг "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_tag(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Тэг: "{item["name"]}" не импортирован]')
                else:
                    tags[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Тэг "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Тэгов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт тэгов завершён.')


    #---------------------------------------- Оповещения ------------------------------------
    def import_notification_alert_rules(self, path):
        """Импортируем список правил оповещений"""
        json_file = os.path.join(path, 'config_alert_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил оповещений в раздел "Диагностика и мониторинг/Оповещения/Правила оповещений".')
        error = 0

        if 'notification_profiles' not in self.ngfw_data:
            if self.get_notification_profiles():      # Устанавливаем атрибут self.ngfw_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return
        notification_profiles = self.ngfw_data['notification_profiles']

        err, result = self.utm.get_nlist_list('emailgroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил оповещений.')
            self.error = 1
            return
        email_group = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        err, result = self.utm.get_nlist_list('phonegroup')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил оповещений.')
            self.error = 1
            return
        phone_group = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        err, result = self.utm.get_notification_alert_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил оповещений.')
            self.error = 1
            return
        alert_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            try:
                item['notification_profile_id'] = notification_profiles[item['notification_profile_id']]
            except KeyError as err:
                message = f'    Error: [Правило "{item["name"]}"] Не найден профиль оповещений {err}. Импортируйте профили оповещений и повторите попытку.'
                self.stepChanged.emit(f'RED|{message}\n       Error: Правило "{item["name"]}" не импортировано.')
                error = 1
                continue

            new_emails = []
            for x in item['emails']:
                try:
                    new_emails.append(['list_id', email_group[x[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена группа почтовых адресов {err}. Загрузите почтовые адреса и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найдена группа почтовых адресов {err}.'
                    item['enabled'] = False
                    error = 1
            item['emails'] = new_emails

            new_phones = []
            for x in item['phones']:
                try:
                    new_phones.append(['list_id', phone_group[x[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена группа телефонных номеров {err}. Загрузите номера телефонов и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найдена группа телефонных номеров {err}.'
                    item['enabled'] = False
                    error = 1
            item['phones'] = new_phones

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in alert_rules:
                self.stepChanged.emit(f'uGRAY|    Правило оповещения "{item["name"]}" уже существует.')
                err, result = self.utm.update_notification_alert_rule(alert_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило оповещения "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило оповещения "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_notification_alert_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило оповещения: "{item["name"]}" не импортировано]')
                else:
                    alert_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило оповещения "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил оповещений завершён.')


    def import_snmp_security_profiles(self, path):
        """Импортируем профили безопасности SNMP"""
        json_file = os.path.join(path, 'config_snmp_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Оповещения/Профили безопасности SNMP".')
        error = 0

        err, result = self.utm.get_snmp_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей безопасности SNMP.')
            self.error = 1
            return
        snmp_security_profiles = {x['name']: x['id'] for x in result}

        for item in data:
            if item['name'] in snmp_security_profiles:
                self.stepChanged.emit(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует.')
                err, result = self.utm.update_snmp_security_profile(snmp_security_profiles[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности SNMP "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Профиль безопасности SNMP "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_snmp_security_profile(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности SNMP "{item["name"]}" не импортирован]')
                else:
                    snmp_security_profiles[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей безопасности SNMP завершён.')


    def import_snmp_rules(self, path):
        """Импортируем список правил SNMP"""
        json_file = os.path.join(path, 'config_snmp_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка правил SNMP в раздел "Диагностика и мониторинг/Оповещения/SNMP".')
        error = 0

        if self.utm.float_version >= 7.1:
            err, result = self.utm.get_snmp_security_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return
            snmp_security_profiles = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_snmp_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        snmp_rules = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if self.utm.float_version >= 7.1:
                if 'snmp_security_profile' in item:
                    if item['snmp_security_profile']:
                        try:
                            item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности SNMP {err}. Импортируйте профили безопасности SNMP и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности SNMP {err}.'
                            item['snmp_security_profile'] = 0
                            item['enabled'] = False
                            error = 1
                else:
                    item['snmp_security_profile'] = 0
                    item['enabled'] = False
                    item.pop('username', None)
                    item.pop('auth_type', None)
                    item.pop('auth_alg', None)
                    item.pop('auth_password', None)
                    item.pop('private_alg', None)
                    item.pop('private_password', None)
                    if item['version'] == 3:
                        item['version'] = 2
                        item['community'] = 'public'
            else:
                if 'snmp_security_profile' in item:
                    item.pop('snmp_security_profile', None)
                    item.pop('enabled', None)
                    item['username'] = ''
                    item['auth_type'] = ''
                    item['auth_alg'] = 'md5'
                    item['auth_password'] = False
                    item['private_alg'] = 'aes'
                    item['private_password'] = False
                    if item['version'] == 3:
                        item['version'] = 2
                        item['community'] = 'public'

            if item['name'] in snmp_rules:
                self.stepChanged.emit(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует.')
                err, result = self.utm.update_snmp_rule(snmp_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило SNMP "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило SNMP "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_snmp_rule(item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
                else:
                    snmp_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил SNMP завершён.')


    def import_snmp_settings(self, path):
        """Импортируем параметры SNMP. Для версии 7.1 и выше."""
        self.stepChanged.emit('BLUE|Импорт параметров SNMP в раздел "Диагностика и мониторинг/Оповещения/Параметры SNMP".')

        self.import_snmp_engine(path)
        self.import_snmp_sys_name(path)
        self.import_snmp_sys_location(path)
        self.import_snmp_sys_description(path)

        self.stepChanged.emit('GREEN|    Параметры SNMP импортированы  в раздел "Диагностика и мониторинг/Оповещения/Параметры SNMP".')


    def import_snmp_engine(self, path):
        json_file = os.path.join(path, 'config_snmp_engine.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_engine(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}/n    Произошла ошибка при импорте SNMP Engine ID.')
            self.error = 1
        else:
            self.stepChanged.emit('BLACK|    SNMP Engine ID импортирован.')


    def import_snmp_sys_name(self, path):
        json_file = os.path.join(path, 'config_snmp_sysname.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_sysname(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте значения SNMP SysName.')
            self.error = 1
        else:
            self.stepChanged.emit('BLACK|    Значение SNMP SysName импортировано.')


    def import_snmp_sys_location(self, path):
        json_file = os.path.join(path, 'config_snmp_syslocation.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_syslocation(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте значения SNMP SysLocation.')
            self.error = 1
        else:
            self.stepChanged.emit('BLACK|    Значение SNMP SysLocation импортировано.')


    def import_snmp_sys_description(self, path):
        json_file = os.path.join(path, 'config_snmp_sysdescription.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        err, result = self.utm.set_snmp_sysdescription(data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте значения SNMP SysDescription.')
            self.error = 1
        else:
            self.stepChanged.emit('BLACK|    Значение SNMP SysDescription импортировано.')


    def pass_function(self, path):
        """Функция заглушка"""
        self.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')


    #############################------------ Служебные функции ------------#####################################
    def get_ips_id(self, mode, rule_ips, rule):
        """
        Получить ID списков IP-адресов. Если список IP-адресов не существует на NGFW, он пропускается.
        mode - принимает значения: src | dst (для формирования сообщений).
        """
        new_rule_ips = []
        for ips in rule_ips:
            if ips[0] == 'geoip_code':
                new_rule_ips.append(ips)
            if ips[0] == 'mac':
                new_rule_ips.append(ips)
            try:
                if ips[0] == 'list_id':
                    new_rule_ips.append(['list_id', self.ngfw_data['ip_lists'][ips[1]]])
                elif ips[0] == 'urllist_id':
                    if self.utm.float_version < 6:
                        self.stepChanged.emit(f'bRED|    Error: [Правило "{rule["name"]}"] Список доменов "{ips[1]}" не добавлен в источник/назначение. Версия 5 не поддерживает данный функционал.')
                    else:
                        new_rule_ips.append(['urllist_id', self.ngfw_data['url_lists'][ips[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список {mode}-адресов (IP/URL) "{ips[1]}". Загрузите списки в библиотеки и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов  (IP/URL) "{ips[1]}".'
                rule['error'] = True
        return new_rule_ips


    def get_zones_id(self, mode, zones, rule):
        """
        Получить ID зон. Если зона не существует на NGFW, то она пропускается.
        mode - принимает значения: src | dst (для формирования сообщений).
        """
        new_zones = []
        for zone_name in zones:
            try:
                new_zones.append(self.ngfw_data['zones'][zone_name])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена {mode}-зона "{zone_name}". Импортируйте зоны и повторите попытку.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone_name}".'
                rule['error'] = True
        return new_zones


    def get_urls_id(self, urls, rule):
        """Получить ID списков URL. Если список не существует на NGFW, он пропускается."""
        new_urls = []
        for item in urls:
            try:
                new_urls.append(self.ngfw_data['url_lists'][item])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список URL "{item}". Загрузите списки URL и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список URL "{item}".'
                rule['error'] = True
        return new_urls


    def get_url_categories_id(self, rule, referer=0):
        """Получить ID категорий URL и групп категорий URL. Если список не существует на NGFW, он пропускается."""
        new_categories = []
        rule_data = rule['referer_categories'] if referer else rule['url_categories']
        for item in rule_data:
            try:
                if item[0] == 'list_id':
                    new_categories.append(['list_id', self.ngfw_data['url_categorygroups'][item[1]]])
                elif item[0] == 'category_id':
                    new_categories.append(['category_id', self.ngfw_data['url_categories'][item[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория URL "{item[1]}". Загрузите категории URL и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена категория URL "{item[1]}".'
                rule['error'] = True
        return new_categories


    def get_time_restrictions_id(self, rule):
        """Получить ID календарей. Если не существуют на NGFW, то пропускается."""
        new_schedules = []
        for cal_name in rule['time_restrictions']:
            try:
                new_schedules.append(self.ngfw_data['calendars'][cal_name])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден календарь "{cal_name}".')
                rule['description'] = f'{rule["description"]}\nError: Не найден календарь "{cal_name}".'
                rule['error'] = True
        return new_schedules


    def get_guids_users_and_groups(self, rule):
        """
        Получить GUID-ы групп и пользователей по их именам.
        Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
        """
        new_users = []
        for item in rule['users']:
            match item[0]:
                case 'special':
                    new_users.append(item)
                case 'user':
                    user_name = None
                    try:
                        ldap_domain, _, user_name = item[1].partition("\\")
                    except IndexError:
                        self.stepChanged.emit(f'NOTE|    Error: [Правило "{rule["name"]}"] Не указано имя пользователя в "{item}".')
                    if user_name:
                        err, result = self.utm.get_ldap_user_guid(ldap_domain, user_name)
                        if err:
                            self.stepChanged.emit(f'RED|    {result}  [Rule "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                            rule['error'] = True
                        elif not result:
                            self.stepChanged.emit(f'RED|    Error: [Rule "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}". Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                            rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене или LDAP-коннектора для домена "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            new_users.append(['user', result])
                    else:
                        try:
                            new_users.append(['user', self.ngfw_data['local_users'][item[1]]])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден локальный пользователь "{err}". Импортируйте локальных пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь "{err}".'
                            rule['error'] = True
                case 'group':
                    group_name = None
                    try:
                        ldap_domain, _, group_name = item[1].partition("\\")
                    except IndexError:
                        self.stepChanged.emit(f'NOTE|    Error: [Правило "{rule["name"]}"] Не указано имя группы в "{item}".')
                    if group_name:
                        err, result = self.utm.get_ldap_group_guid(ldap_domain, group_name)
                        if err:
                            self.stepChanged.emit(f'RED|    {result}  [Rule "{rule["name"]}"]')
                            rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                            rule['error'] = True
                        elif not result:
                            self.stepChanged.emit(f'RED|    Error: [Rule "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}". Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                            rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене или LDAP-коннектора для домена "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            new_users.append(['group', result])
                    else:
                        try:
                            new_users.append(['group', self.ngfw_data['local_groups'][item[1]]])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа пользователей "{err}"]. Импортируйте группы пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей "{err}".'
                            rule['error'] = True
        return new_users


    def get_services(self, service_list, rule):
        """Получаем ID сервисов по их именам. Если сервис не найден, то он пропускается."""
        new_service_list = []
        if self.utm.float_version < 7:
            for item in service_list:
                if item[0] == 'list_id':
                    self.stepChanged.emit(f'bRED|    Error: [Правило "{rule["name"]}"] Группа сервисов "{item[1]}" не добавлена. В версии 6 группы сервисов не поддерживаются.')
                else:
                    try:
                        _, service_name = self.get_transformed_name(item[1], descr='Имя сервиса')
                        new_service_list.append(self.ngfw_data['services'][service_name])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден сервис {err}. Импортируйте сервисы и повторите попытку.')
                        rule['description'] = f'{rule["description"]}\nError: Не найден сервис {err}.'
                        rule['error'] = True
        else:
            for item in service_list:
                try:
                    if item[0] == 'service':
                        _, service_name = self.get_transformed_name(item[1], descr='Имя сервиса')
                        new_service_list.append(['service', self.ngfw_data['services'][service_name]])
                    elif item[0] == 'list_id':
                        _, service_name = self.get_transformed_name(item[1], descr='Имя группы сервисов')
                        new_service_list.append(['list_id', self.ngfw_data['service_groups'][service_name]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден сервис {err}. Загрузите сервисы и повторите импорт.')
                    rule['description'] = f'{rule["description"]}\nError: Не найден сервис {err}.'
                    rule['error'] = True
        return new_service_list


    def get_apps(self, rule, apps=None):
        """Определяем ID приложения или группы приложений по именам."""
        new_app_list = []
        applications = apps if apps else rule['apps']
        for app in applications:
            if app[0] == 'ro_group':
                if app[1] == 'All':
                    if self.utm.float_version >= 6:
                        new_app_list.append(['ro_group', 0])
                    else:
                        self.stepChanged.emit(f'bRED|    Error [Правило "{rule["name"]}"]. Категорию "All" нельзя добавить в версии 5.')
                else:
                    try:
                        new_app_list.append(['ro_group', self.ngfw_data['l7_categories'][app[1]]])
                    except KeyError as err:
                        message = '    Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.'
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория l7 "{app[1]}".\n{message}')
                        rule['description'] = f'{rule["description"]}\nError: Не найдена категория l7 "{app[1]}".'
                        rule['error'] = True
            elif app[0] == 'group':
                try:
                    new_app_list.append(['group', self.ngfw_data['application_groups'][app[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа приложений l7 "{app[1]}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найдена группа приложений l7 "{app[1]}".'
                    rule['error'] = True
            elif app[0] == 'app':
                if self.utm.float_version < 7:
                    try:
                        new_app_list.append(['app', self.ngfw_data['l7_apps'][app[1]]])
                    except KeyError as err:
                        message = '    Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.'
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдено приложение "{app[1]}".\n{message}')
                        rule['description'] = f'{rule["description"]}\nError: Не найдено приложение "{app[1]}".'
                        rule['error'] = True
                else:
                    self.stepChanged.emit(f'NOTE|    Правило "{rule["name"]}": приложение {app[1]} не добавлено, так как в версии 7.0 отдельное приложение добавить нельзя.')
        return new_app_list


    def execute_add_update_nlist(self, ngfw_named_list, item, item_note):
        """Обновляем существующий именованный список или создаём новый именованный список"""
        if item['name'] in ngfw_named_list:
            self.stepChanged.emit(f'GRAY|    {item_note} "{item["name"]}" уже существует.')
            err, result = self.utm.update_nlist(ngfw_named_list[item['name']], item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}  [{item_note}: {item["name"]}]')
                return 1
            elif err == 2:
                self.stepChanged.emit(f'GRAY|    {result}')
            else:
                self.stepChanged.emit(f'BLACK|    {item_note} "{item["name"]}" updated.')
        else:
            err, result = self.utm.add_nlist(item)
            if err:
                self.stepChanged.emit(f'RED|    {result}  [{item_note}: "{item["name"]}"]')
                return 1
            else:
                ngfw_named_list[item['name']] = result
                self.stepChanged.emit(f'BLACK|    {item_note} "{item["name"]}" импортирована.')
        return 0


    def execute_add_nlist_items(self, list_id, item_name, content):
        """Импортируем содержимое в именованный список"""
        err, result = self.utm.add_nlist_items(list_id, content)
        if err == 2:
            self.stepChanged.emit(f'GRAY|       {result}')
        elif err == 1:
            self.stepChanged.emit(f'RED|       {result}  [Список: "{item_name}"]')
            return 1
        else:
            self.stepChanged.emit(f'BLACK|       Содержимое списка "{item_name}" обновлено.')
        return 0


    def add_new_nlist(self, name, nlist_type, content):
        """Добавляем в библиотеку новый nlist с содержимым."""
        nlist = {
            'name': name,
            'description': '',
            'type': nlist_type,
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
        }
        err, list_id = self.utm.add_nlist(nlist)
        if err:
            return err, list_id
        err, result = self.utm.add_nlist_items(list_id, content)
        if err:
            return err, result
        return 0, list_id


    def add_empty_vrf(self, vrf_name):
        """Добавляем пустой VRF"""
        vrf = {
            'name': vrf_name,
            'description': '',
            'interfaces': [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }
        err, result = self.utm.add_vrf(vrf)
        if err:
            return err, result
        return 0, result    # Возвращаем ID добавленного VRF


    def get_2fa_profiles(self):
        """Получаем список профилей MFA и устанавливаем значение self.ngfw_data['profiles_2fa']"""
        err, result = self.utm.get_2fa_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['profiles_2fa'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        return 0

    def get_notification_profiles(self):
        """Получаем список профилей оповещения и устанавливаем значение self.ngfw_data['notification_profiles']"""
        err, result = self.utm.get_notification_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['notification_profiles'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        self.ngfw_data['notification_profiles'][-5] = -5
        return 0


    def get_templates_list(self):
        """Получаем список шаблонов страниц и устанавливаем значение self.ngfw_data['list_templates']"""
        err, result = self.utm.get_templates_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['list_templates'] = {x['name']: x['id'] for x in result}
        self.ngfw_data['list_templates'][-1] = -1
        return 0


    def get_client_certificate_profiles(self):
        """
        Получаем список профилей пользовательских сертификатов и
        устанавливаем значение атрибута self.ngfw_data['client_certificate_profiles']
        """
        err, result = self.utm.get_client_certificate_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['client_certificate_profiles'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        self.ngfw_data['client_certificate_profiles'][0] = 0
        return 0


    def get_scenarios_rules(self):
        """Устанавливаем значение self.ngfw_data['scenarios_rules']"""
        err, result = self.utm.get_scenarios_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['scenarios_rules'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        return 0


    def get_icap_servers(self):
        """Получаем список серверов ICAP и устанавливаем значение атрибута self.ngfw_data['icap_servers']"""
        err, result = self.utm.get_icap_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['icap_servers'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        return 0


    def get_reverseproxy_servers(self):
        """Получаем список серверов reverse-proxy и устанавливаем значение атрибута self.ngfw_data['reverseproxy_servers']"""
        err, result = self.utm.get_reverseproxy_servers()
        if err:
            self.stepChanged.emit(f'RED|       {result}')
            self.error = 1
            return 1
        self.ngfw_data['reverseproxy_servers'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        return 0


    def get_upstreamproxies_servers(self):
        """Получаем список серверов вышестоящих proxy и устанавливаем значение атрибута self.ngfw_data['upstreamproxies_servers']"""
        err, result = self.utm.get_cascade_proxy_servers()
        if err:
            self.stepChanged.emit(f'RED|       {result}')
            self.error = 1
            return 1
        self.ngfw_data['upstreamproxies_servers'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        return 0


    def get_upstreamproxies_profiles(self):
        """Получаем список профилей вышестоящих proxy и устанавливаем значение атрибута self.ngfw_data['upstreamproxies_profiles']"""
        err, result = self.utm.get_cascade_proxy_profiles()
        if err:
            self.stepChanged.emit(f'RED|       {result}')
            self.error = 1
            return 1
        self.ngfw_data['upstreamproxies_profiles'] = {self.get_transformed_name(x['name'], mode=0)[1]: x['id'] for x in result}
        return 0


    def add_tags_for_objects(self, data, object_type):
        """Добавляем тэги к объектам определённой группы"""
        if self.utm.product == 'dcfw':
            return 0
        error = 0
        tag_relations = []
        for object_id, tags in data.items():
            for tag in tags:
                try:
                    tag_relations.append({
                        'tag_id': self.ngfw_data['tags'][tag],
                        'object_id': object_id,
                        'object_type': object_type
                    })
                except KeyError as err:
                    self.parent.stepChanged.emit(f'RED|    Error: Не найден тэг {err}.')
                    error = 1
        err, result = self.utm.set_tags_in_objects(tag_relations)
        if err or error:
            self.parent.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте тэгов для {object_type}.')
            error = 1
        return error


class Zone:
    def __init__(self, parent, zone):
        self.parent = parent
        self.name = zone['name']
        self.description = zone['description']
        self.services_access = zone['services_access']
        self.enable_antispoof = zone['enable_antispoof']
        self.antispoof_invert = zone['antispoof_invert']
        self.networks = zone['networks']
        self.sessions_limit_enabled = zone['sessions_limit_enabled']
        self.sessions_limit_exclusions = zone['sessions_limit_exclusions']
        self.ngfw_version = parent.utm.float_version
        self.ngfw_zone_services = {v: k for k, v in zone_services.items()}
        self.error = 0
        self.check_services_access()
        self.check_sessions_limit()
        self.check_networks()


    def check_services_access(self):
        """Обрабатываем сервисы из контроля доступа."""
        new_service_access = []
        for service in self.services_access:
            # Проверяем что такой сервис существует в этой версии NGFW и получаем его ID.
            service_name = service['service_id']
            try:
                service['service_id'] = self.ngfw_zone_services[service_name]
            except KeyError as err:
                self.parent.stepChanged.emit(f'RED|    Error: [Зона "{self.name}"] Не корректный сервис "{service_name}" в контроле доступа. Возможно он не существует в этой версии NGFW.')
                self.description = f'{self.description}\nError: Не импортирован сервис "{service_name}" в контроль доступа.'
                self.error = 1
                continue
            if service['service_id'] == 34 and self.parent.utm.float_version < 7.4:
                continue
            # Приводим список разрешённых адресов сервиса в соответствие с версией NGFW.
            if service['allowed_ips']:
                if self.ngfw_version < 7.1:
                    if isinstance(service['allowed_ips'][0], list):
                        service['allowed_ips'] = []
                        self.parent.stepChanged.emit(f'ORANGE|    Warning: Для зоны "{self.name}" в контроле доступа сервиса "{service_name}" удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.')
                        self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.'
                else:
                    if isinstance(service['allowed_ips'][0], list):
                        allowed_ips = []
                        for item in service['allowed_ips']:
                            if item[0] == 'list_id':
                                _, list_name = self.parent.get_transformed_name(item[1], err=0, descr='Имя списка', mode=0)
                                try:
                                    item[1] = self.parent.ngfw_data['ip_lists'][list_name]
                                except KeyError as err:
                                    self.parent.stepChanged.emit(f'RED|    Error: [Зона "{self.name}"] В контроле доступа сервиса "{service_name}" не найден список IP-адресов {err}.')
                                    self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" не найден список IP-адресов {err}.'
                                    self.error = 1
                                    continue
                            allowed_ips.append(item)
                        service['allowed_ips'] = allowed_ips
                    else:
                        nlist_name = f'Zone {self.name} (service access: {service_name})'
                        if nlist_name in self.parent.ngfw_data['ip_lists']:
                            service['allowed_ips'] = [['list_id', self.parent.ngfw_data['ip_lists'][nlist_name]]]
                        else:
                            content = [{'value': ip} for ip in service['allowed_ips']]
                            err, list_id = self.parent.add_new_nlist(nlist_name, 'network', content)
                            if err == 1:
                                message = f'Error: [Зона "{self.name}"] Не создан список IP-адресов в контроле доступа сервиса "{service_name}".'
                                self.parent.stepChanged.emit(f'RED|    {list_id}\n       {message}')
                                self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" не создан список IP-адресов.'
                                self.error = 1
                                continue
                            elif err == 2:
                                message = f'Warning: Список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}" уже существует.'
                                self.parent.stepChanged.emit('ORANGE|    {message}\n       Перезапустите конвертер и повторите попытку.')
                                continue
                            else:
                                self.parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}".')
                                service['allowed_ips'] = [['list_id', list_id]]
                                self.parent.ngfw_data['ip_lists'][nlist_name] = list_id

            # Удаляем сервисы зон версии 7.1 которых нет в более старых версиях.
#            if self.ngfw_version < 7.1:
#                for service in self.services_access:
#                    if service['service_id'] in (31, 32, 33):
#                        continue
            new_service_access.append(service)

        self.services_access = new_service_access


    def check_networks(self):
        """Обрабатываем защиту от IP-спуфинга"""
        if self.networks:
            if self.ngfw_version < 7.1:
                if isinstance(self.networks[0], list):
                    self.networks = []
                    self.parent.stepChanged.emit(f'ORANGE|    Для зоны "{zone["name"]}" удалены списки IP-адресов в защите от IP-спуфинга. Списки поддерживаются только в версии 7.1 и выше.')
                    self.description = f'{self.description}\nError: В защите от IP-спуфинга удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.'
            else:
                if isinstance(self.networks[0], list):
                    new_networks = []
                    for item in self.networks:
                        if item[0] == 'list_id':
                            _, list_name = self.parent.get_transformed_name(item[1], err=0, descr='Имя списка', mode=0)
                            try:
                                item[1] = self.parent.ngfw_data['ip_lists'][list_name]
                            except KeyError as err:
                                self.parent.stepChanged.emit(f'RED|    Error: [Зона "{self.name}"] В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.')
                                self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.'
                                self.error = 1
                                continue
                        new_networks.append(item)
                    self.networks = new_networks
                else:
                    nlist_name = f'Zone {self.name} (IP-spufing)'
                    if nlist_name in self.parent.ngfw_data['ip_lists']:
                        self.networks = [['list_id', self.parent.ngfw_data['ip_lists'][nlist_name]]]
                    else:
                        content = [{'value': ip} for ip in self.networks]
                        err, list_id = self.parent.add_new_nlist(nlist_name, 'network', content)
                        if err == 1:
                            message = f'Error: [Зона "{self.name}"] Не создан список IP-адресов в защите от IP-спуфинга.'
                            self.parent.stepChanged.emit(f'RED|    {list_id}\n       {message}')
                            self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не создан список IP-адресов.'
                            self.networks = []
                            self.error = 1
                        elif err == 2:
                            message = f'Warning: Список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{self.name}" уже существует.'
                            self.parent.stepChanged.emit('ORANGE|    {message}\n       Перезапустите конвертер и повторите попытку.')
                            self.networks = []
                        else:
                            self.parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{self.name}".')
                            self.networks = [['list_id', list_id]]
                            self.parent.ngfw_data['ip_lists'][nlist_name] = list_id
        if not self.networks:
            self.enable_antispoof = False
            self.antispoof_invert = False


    def check_sessions_limit(self):
        """Обрабатываем ограничение сессий"""
        new_sessions_limit_exclusions = []
        if self.ngfw_version >= 7.1:
            for item in self.sessions_limit_exclusions:
                try:
                    item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                    new_sessions_limit_exclusions.append(item)
                except KeyError as err:
                    self.parent.stepChanged.emit(f'RED|    Error: [Зона "{self.name}"] В разделе "Ограничение сессий" не найден список IP-адресов {err}.')
                    self.description = f'{self.description}\nError: В разделе "Ограничение сессий" не найден список IP-адресов {err}.'
                    self.error = 1
            self.sessions_limit_exclusions = new_sessions_limit_exclusions
            if not self.sessions_limit_exclusions:
                self.sessions_limit_enabled = False

