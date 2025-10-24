#!/usr/bin/python3
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
# Экспорт конфигурации UserGate NGFW в json-формат версии 7.
# Версия 3.16  24.10.2025
#

import os, sys, json
from datetime import datetime as dt
from xmlrpc.client import DateTime as class_DateTime
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import ReadWriteBinFile, MyMixedService
from services import zone_services, default_urlcategorygroup


class ExportSelectedPoints(QThread, ReadWriteBinFile, MyMixedService):
    """Экспортируем разделы конфигурации с NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points=None, selected_path=None, selected_points=None):
        super().__init__()
        self.utm = utm
        self.config_path = config_path      # Путь к каталогу с конфигурацией данного узла
        self.all_points = all_points
        self.selected_path = selected_path
        self.selected_points = selected_points

        self.error = 0
        self.export_funcs = {
            'GeneralSettings':  self.export_general_settings,
            'DeviceManagement': self.pass_function,
            'Administrators': self.export_admins,
            'Certificates': self.export_certificates,
            'UserCertificateProfiles': self.export_users_certificate_profiles,
            'Zones': self.export_zones,
            'Interfaces': self.export_interfaces_list,
            'Gateways': self.export_gateways_list,
            'DHCP': self.export_dhcp_subnets,
            'DNS': self.export_dns_config,
            'VRF': self.export_vrf_list,
            'WCCP': self.export_wccp,
            'Routes': self.export_routes,
            'OSPF': self.export_ospf_config,
            'BGP': self.export_bgp_config,
            'Groups': self.export_local_groups,
            'Users': self.export_local_users,
            'AuthServers': self.export_auth_servers,
            'AuthProfiles': self.export_auth_profiles,
            'CaptivePortal': self.export_captive_portal_rules,
            'CaptiveProfiles': self.export_captive_profiles,
            'TerminalServers': self.export_terminal_servers,
            'MFAProfiles': self.export_2fa_profiles,
            'UserIDagent': self.export_userid_agent,
            'BYODPolicies': self.export_byod_policy,
            'BYODDevices': self.pass_function,
            'Firewall': self.export_firewall_rules,
            'NATandRouting': self.export_nat_rules,
            'LoadBalancing': self.export_loadbalancing_rules,
            'TrafficShaping': self.export_shaper_rules,
            "ContentFiltering": self.export_content_rules,
            "SafeBrowsing": self.export_safebrowsing_rules,
            "TunnelInspection": self.export_tunnel_inspection_rules,
            "SSLInspection": self.export_ssldecrypt_rules,
            "SSHInspection": self.export_sshdecrypt_rules,
            "IntrusionPrevention": self.export_idps_rules,
            "Scenarios": self.export_scenarios,
            "MailSecurity": self.export_mailsecurity_rules,
            "ICAPRules": self.export_icap_rules,
            "ICAPServers": self.export_icap_servers,
            "DoSRules": self.export_dos_rules,
            "DoSProfiles": self.export_dos_profiles,
            "SCADARules": self.export_scada_rules,
            "WebPortal": self.export_proxyportal_rules,
            "ReverseProxyRules": self.export_reverseproxy_rules,
            "ReverseProxyServers": self.export_reverseproxy_servers,
            "UpstreamProxiesServers": self.export_upstream_proxies_servers,
            "UpstreamProxiesProfiles": self.export_upstream_proxies_profiles,
            "UpstreamProxiesRules": self.export_upstream_proxies_rules,
            "WAFprofiles": self.export_waf_profiles_list,
            "CustomWafLayers": self.export_waf_custom_layers,
            "SystemWafRules": self.pass_function,
            "ServerRules": self.export_vpn_server_rules,
            "ClientRules": self.export_vpn_client_rules,
            "VPNNetworks": self.export_vpn_networks,
            "SecurityProfiles": self.export_vpn_security_profiles,
            "ServerSecurityProfiles": self.export_vpnserver_security_profiles,
            "ClientSecurityProfiles": self.export_vpnclient_security_profiles,
            "Morphology": self.export_morphology_lists,
            "Services": self.export_services_list,
            "ServicesGroups": self.export_services_groups,
            "IPAddresses": self.export_IP_lists,
            "Useragents": self.export_useragent_lists,
            "ContentTypes": self.export_mime_lists,
            "URLLists": self.export_url_lists,
            "TimeSets": self.export_time_restricted_lists,
            "BandwidthPools": self.export_shaper_list,
            "SCADAProfiles": self.export_scada_profiles,
            "ResponcePages": self.export_templates_list,
            "URLCategories": self.export_url_categories,
            "OverURLCategories": self.export_custom_url_category,
            "Applications": self.export_applications,
            "ApplicationProfiles": self.export_app_profiles,
            "ApplicationGroups": self.export_application_groups,
            "Emails": self.export_email_groups,
            "Phones": self.export_phone_groups,
            "IPDSSignatures": self.export_custom_idps_signatures,
            "IDPSProfiles": self.export_idps_profiles,
            "NotificationProfiles": self.export_notification_profiles,
            "NetflowProfiles": self.export_netflow_profiles,
            "SSLProfiles": self.export_ssl_profiles,
            "LLDPProfiles": self.export_lldp_profiles,
            "SSLForwardingProfiles": self.export_ssl_forward_profiles,
            "HIDObjects": self.export_hip_objects,
            "HIDProfiles": self.export_hip_profiles,
            "BfdProfiles": self.export_bfd_profiles,
            "UserIdAgentSyslogFilters": self.export_useridagent_syslog_filters,
            "Tags": self.export_tags,
            "AlertRules": self.export_notification_alert_rules,
            "SNMP": self.export_snmp_rules,
            "SNMPParameters": self.export_snmp_settings,
            "SNMPSecurityProfiles": self.export_snmp_security_profiles,
        }


    def run(self):
        """Экспортируем разделы конфигурации"""
        # Читаем бинарный файл библиотечных данных
        err, self.ngfw_data = self.read_bin_file()
        if err:
            self.stepChanged.emit('iRED|Экспорт конфигурации с UserGate NGFW прерван. Не удалось прочитать служебные данные.')
            return

        if self.all_points:
            """Экспортируем всё в пакетном режиме"""
            for item in self.all_points:
                top_level_path = os.path.join(self.config_path, item['path'])
                for point in item['points']:
                    current_path = os.path.join(top_level_path, point)
                    if point in self.export_funcs:
                        self.export_funcs[point](current_path)
                    else:
                        self.error = 1
                        self.stepChanged.emit(f'RED|Не найдена функция для экспорта {point}!')
        else:
            """Экспортируем определённые разделы конфигурации"""
            for point in self.selected_points:
                current_path = os.path.join(self.selected_path, point)
                if point in self.export_funcs:
                    self.export_funcs[point](current_path)
                else:
                    self.error = 1
                    self.stepChanged.emit(f'RED|Не найдена функция для экспорта {point}!')

        # Сохраняем бинарный файл библиотечных данных после изменений в процессе работы
        if self.write_bin_file(self.ngfw_data):
            self.stepChanged.emit('iRED|Экспорт конфигурации с UserGate NGFW прерван. Не удалось записать служебные данные.')
            return

        if self.error:
            self.stepChanged.emit('iORANGE|Экспорт конфигурации прошёл с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Экспорт конфигурации завершён.\n')


    #------------------------------------ UserGate -------------------------------------------------
    def export_general_settings(self, path):
        """Экспортируем 1раздел 'UserGate/Настройки/Настройки интерфейса'"""
        self.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Настройки интерфейса".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        if 'client_cert_profiles' not in self.ngfw_data:
            if self.get_client_certificate_profiles():     # Заполняем self.ngfw_data['client_cert_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек интерфейса.')
                return

        error = 0
        params = ['ui_timezone', 'ui_language']
        if self.utm.float_version > 5:
            params.extend(['web_console_ssl_profile_id', 'response_pages_ssl_profile_id'])
        if self.utm.float_version >= 7.1:
            params.append('api_session_lifetime')
            params.append('endpoint_ssl_profile_id')
            params.append('endpoint_certificate_id')

        err, data = self.utm.get_settings_params(params)
        if err:
            self.stepChanged.emit(f'RED|    {data}')
            error = 1
        else:
            err, result = self.utm.get_webui_auth_mode()
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                if isinstance(result, dict):
                    if result['type'] == 'pki':
                        cert_id = result['client_certificate_profile_id']
                        result['client_certificate_profile_id'] = self.ngfw_data['client_cert_profiles'][int(cert_id)]
                data['webui_auth_mode'] = result

            if self.utm.float_version > 5:
                if self.ngfw_data['ssl_profiles']:
                    data['web_console_ssl_profile_id'] = self.ngfw_data['ssl_profiles'][data['web_console_ssl_profile_id']]
                    data['response_pages_ssl_profile_id'] = self.ngfw_data['ssl_profiles'][data['response_pages_ssl_profile_id']]
                else:
                    data.pop('web_console_ssl_profile_id', None)
                    data.pop('response_pages_ssl_profile_id', None)
            if self.utm.float_version >= 7.1:
                data['endpoint_certificate_id'] = self.ngfw_data['certs'].get(data['endpoint_certificate_id'], 0)
                if self.ngfw_data['ssl_profiles']:
                    data['endpoint_ssl_profile_id'] = self.ngfw_data['ssl_profiles'].get(data['endpoint_ssl_profile_id'], 0)
                else:
                    data.pop('endpoint_ssl_profile_id', 0)

            json_file = os.path.join(path, 'config_settings_ui.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit('ORANGE|    Ошибка экспорта настроек интерфейса.')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Настройки интерфейса выгружены в файл "{json_file}".')


        """Экспортируем раздел 'UserGate/Настройки/Модули'"""
        self.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Модули".')
        error = 0

        params = ["auth_captive", "logout_captive", "block_page_domain", "ftpclient_captive", "ftp_proxy_enabled"]
        if self.utm.float_version >= 7.1:
            params.extend(['tunnel_inspection_zone_config', 'lldp_config'])
        if self.utm.float_version >= 7.4:
            params.insert(2, 'cert_captive')

        err, data = self.utm.get_settings_params(params)
        if err:
            self.stepChanged.emit(f'RED|    {data}')
            error = 1
        else:
            if self.utm.float_version >= 7.1:
                data['tunnel_inspection_zone_config'].pop('cc', None)
                zone_number = data['tunnel_inspection_zone_config']['target_zone']
                data['tunnel_inspection_zone_config']['target_zone'] = self.ngfw_data['zones'].get(zone_number, 'Unknown')
            json_file = os.path.join(path, 'config_settings_modules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

        err, data = self.utm.get_proxy_port()
        if err:
            self.stepChanged.emit(f'RED|    {data}')
            error = 1
        else:
            proxy_port_file = os.path.join(path, 'config_proxy_port.json')
            with open(proxy_port_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit('ORANGE|    Ошибка экспорта настроек модулей.')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Настройки модулей выгружены в файл "{json_file}".')


        """Экспортируем SNMP Engine ID. Для версий 6 и 7.0"""
        if 5 < self.utm.float_version < 7.1:
            self.stepChanged.emit('BLUE|Экспорт SNMP Engine ID из раздела "UserGate/Настройки/Модули/SNMP Engine ID".')
            engine_path = os.path.join(self.config_path, 'Notifications/SNMPParameters')
            err, msg = self.create_dir(engine_path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
            else:
                self.export_snmp_engine(engine_path)


        """Экспортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
        self.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Настройки кэширования HTTP".')
        error = 0

        params = ['http_cache_mode', 'http_cache_docsize_max', 'http_cache_precache_size']
        if self.utm.float_version >= 7:
            params.extend([
                'add_via_enabled', 'add_forwarded_enabled', 'smode_enabled', 'module_l7_enabled',
                'module_idps_enabled', 'module_sip_enabled', 'module_h323_enabled', 'module_sunrpc_enabled', 
                'module_ftp_alg_enabled', 'module_tftp_enabled', 'legacy_ssl_enabled', 'http_connection_timeout',
                'http_loading_timeout', 'icap_wait_timeout'
            ])

        err, data = self.utm.get_settings_params(params)
        if err:
            self.stepChanged.emit(f'RED|    {data}')
            error = 1
        else:
            json_file = os.path.join(path, 'config_proxy_settings.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки кэширования HTTP и доп.параметры выгружены в файл "{json_file}".')

        err, data = self.utm.get_nlist_list('httpcwl')
        if err:
            self.stepChanged.emit(f'RED|    {data}' if err == 1 else f'ORANGE|    {data}')
            error = 1
        else:
            for content in data['content']:
                content.pop('id')
            json_file = os.path.join(path, 'config_proxy_exceptions.json')
            with open(json_file, 'w') as fh:
                json.dump(data['content'], fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit('ORANGE|    Ошибка экспорта настроек кэширования HTTP.')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Исключения из кэширования HTTP выгружены в файл "{json_file}".')


        """Экспортируем настройки NTP"""
        self.stepChanged.emit('BLUE|Экспорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')

        err, result = self.utm.get_ntp_config()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Ошибка экспорта настроек NTP.')
            self.error = 1
        else:
            result.pop('local_time', None)
            result.pop('timezone', None)
            if self.utm.float_version >= 7.1:
                result['utc_time'] = dt.strptime(result['utc_time'].value, "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
            else:
                result['utc_time'] = dt.strptime(result['utc_time'].value, "%Y%m%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")

            json_file = os.path.join(path, 'config_ntp.json')
            with open(json_file, 'w') as fh:
                json.dump(result, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки NTP выгружены в файл "{json_file}".')


        """Экспортируем настройки веб-портала"""
        self.stepChanged.emit('BLUE|Выгружаются настройки Веб-портала раздела "UserGate/Настройки/Веб-портал":')

        if 'list_templates' not in self.ngfw_data:
            if self.get_templates_list():     # Заполняем self.ngfw_data['list_templates']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек Веб-портала.')
                return

        err, data = self.utm.get_proxyportal_config()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте настроек Веб-портала.')
            self.error = 1
        else:
            if self.utm.float_version > 5:
                data['ssl_profile_id'] = self.ngfw_data['ssl_profiles'][data['ssl_profile_id']]
            else:
                data['ssl_profile_id'] = "Default SSL profile"
            if self.utm.float_version >= 7.1:
                data['client_certificate_profile_id'] = self.ngfw_data['client_cert_profiles'].get(data['client_certificate_profile_id'], 0)
            else:
                data['client_certificate_profile_id'] = 0

            data['user_auth_profile_id'] = self.ngfw_data['auth_profiles'].get(data['user_auth_profile_id'], 1)
            data['proxy_portal_template_id'] = self.ngfw_data['list_templates'].get(data['proxy_portal_template_id'], -1)
            data['proxy_portal_login_template_id'] = self.ngfw_data['list_templates'].get(data['proxy_portal_login_template_id'], -1)
            data['certificate_id'] = self.ngfw_data['certs'].get(data['certificate_id'], -1)

            json_file = os.path.join(path, 'config_web_portal.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки Веб-портала выгружены в файл "{json_file}".')


        """Экспортируем настройки вышестоящего прокси"""
        if 7.1 >= self.utm.float_version < 7.4:
            self.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

            err, result = self.utm.get_upstream_proxy_settings()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Ошибка экспорта настроек вышестоящего прокси.')
                self.error = 1
            else:
                json_file = os.path.join(path, 'upstream_proxy_settings.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Настройки вышестоящего прокси выгружены в файл "{json_file}".')


        """Экспортируем настройки вышестоящего прокси для проверки лицензии и обновлений"""
        if self.utm.float_version >= 7.1:
            self.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Настройки/Вышестоящий прокси для проверки лицензии и обновлений".')

            err, result = self.utm.get_upstream_proxy_update_settings()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Ошибка экспорта настроек вышестоящего прокси для проверки лицензии и обновлений.')
                self.error = 1
            else:
                json_file = os.path.join(path, 'upstream_proxy_update_settings.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Настройки вышестоящего прокси для проверки лицензии и обновлений выгружены в файл "{json_file}".')


    def export_certificates(self, path):
        """Экспортируем сертификаты."""
        self.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Сертификаты".')
        error = 0

        err, result = self.utm.get_certificates_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте сертификатов.')
            self.error = 1
            return

        for item in result:
            self.stepChanged.emit(f'BLACK|    Экспорт сертификата {item["name"]}.')
            item.pop('cc', None)
            if isinstance(item['not_before'], class_DateTime):
                try:
                    item['not_before'] = dt.strptime(item['not_before'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    item['not_before'] = ''
            else:
                if item['not_before']:
                    item['not_before'] = dt.strptime(item['not_before'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(item['not_after'], class_DateTime):
                try:
                    item['not_after'] = dt.strptime(item['not_after'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                except Exception:
                    item['not_after'] = ''
            else:
                if item['not_after']:
                    item['not_after'] = dt.strptime(item['not_after'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

            # Для каждого сертификата создаём свой каталог.
            path_cert = os.path.join(path, item['name'])
            err, msg = self.create_dir(path_cert)
            if err:
                self.stepChanged.emit(f'RED|       {msg}')
                error = 1
            else:
                # Выгружаем сертификат в формат DER.
                err, base64_cert = self.utm.get_certificate_data(item['id'])
                if err:
                    self.stepChanged.emit(f'RED|       {base64_cert}')
                    error = 1
                else:
                    with open(os.path.join(path_cert, 'cert.der'), 'wb') as fh:
                        fh.write(base64_cert.data)

                # Выгружаем сертификат с цепочками в формат PEM.
                err, base64_cert = self.utm.get_certificate_chain_data(item['id'])
                if err:
                    self.stepChanged.emit(f'ORANGE|       Не удалось выгрузить сертификат в формате PEM [{base64_cert}]')
                    error = 1
                else:
                    with open(os.path.join(path_cert, 'cert.pem'), 'wb') as fh:
                        fh.write(base64_cert.data)

                # Выгружаем детальную информацию сертификата в файл certificate_details.json.
                err, details_info = self.utm.get_certificate_details(item['id'])
                if err:
                    self.stepChanged.emit(f'RED|       {details_info}')
                    error = 1
                else:
                    if isinstance(details_info['notBefore'], class_DateTime):
                        try:
                            details_info['notBefore'] = dt.strptime(details_info['notBefore'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            details_info['notBefore'] = ''
                    else:
                        if details_info['notBefore']:
                            details_info['notBefore'] = dt.strptime(details_info['notBefore'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    if isinstance(details_info['notAfter'], class_DateTime):
                        try:
                            details_info['notAfter'] = dt.strptime(details_info['notAfter'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                        except Exception:
                            details_info['notAfter'] = ''
                    else:
                        if details_info['notAfter']:
                            details_info['notAfter'] = dt.strptime(details_info['notAfter'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

                    if 'chain' in details_info:
                        for chain_item in details_info['chain']:
                            if isinstance(chain_item['notBefore'], class_DateTime):
                                try:
                                    chain_item['notBefore'] = dt.strptime(chain_item['notBefore'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    chain_item['notBefore'] = ''
                            else:
                                if chain_item['notBefore']:
                                    chain_item['notBefore'] = dt.strptime(chain_item['notBefore'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                            if isinstance(chain_item['notAfter'], class_DateTime):
                                try:
                                    chain_item['notAfter'] = dt.strptime(chain_item['notAfter'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                                except Exception:
                                    chain_item['notAfter'] = ''
                            else:
                                if chain_item['notAfter']:
                                    chain_item['notAfter'] = dt.strptime(chain_item['notAfter'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

                    json_file = os.path.join(path_cert, 'certificate_details.json')
                    with open(json_file, 'w') as fh:
                        json.dump(details_info, fh, indent=4, ensure_ascii=False)

                # Выгружаем общую информацию сертификата в файл certificate_list.json.
                item.pop('id', None)
                json_file = os.path.join(path_cert, 'certificate_list.json')
                with open(json_file, 'w') as fh:
                    json.dump(item, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|       Сертификат {item["name"]} экспортирован в каталог {path_cert}.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте сертификатов.')
        else:
            self.stepChanged.emit(f'GREEN|    Сертификаты выгружены в каталог "{path}".')


    def export_users_certificate_profiles(self, path):
        """Экспортируем профили пользовательских сертификатов. Только для версии 7.1 и выше."""
        self.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Профили пользовательских сертификатов".')

        err, result = self.utm.get_client_certificate_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте профилей пользовательских сертификатов.')
            self.error = 1
            return

        if result:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте профилей пользовательских сертификатов.')
                self.error = 1
                return

            for item in result:
                item.pop('id', None)
                item.pop('cc', None)
                item['ca_certificates'] = [self.ngfw_data['certs'][x] for x in item['ca_certificates']]

            json_file = os.path.join(path, 'users_certificate_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(result, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили пользовательских сертификатов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей пользовательских сертификатов для экспорта.')


    def export_admins(self, path):
        """Экспортируем профили администраторов и список администраторов."""
        self.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Администраторы".')
        admin_profiles = {}
        error = 0

        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте раздела "UserGate/Администраторы".')
            self.error = 1
            return

        err, result = self.utm.get_admins_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте профилей администраторов.')
            self.error = 1
            return

        if result:
            for item in result:
                admin_profiles[item['id']] = item['name']
                item.pop('id', None)
                item.pop('cc', None)

            json_file = os.path.join(path, 'administrator_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(result, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Профили администраторов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей администраторов для экспорта.')

        err, result2 = self.utm.get_admins()
        if err:
            self.stepChanged.emit(f'RED|    {result2}\n    Произошла ошибка при экспорте списка администраторов.')
            self.error = 1
            return

        if result2:
            for item in result2:
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('cc', None)
                if item['is_root']:
                    continue
                item['profile_id'] = admin_profiles[item['profile_id']]
                if item['type'] == 'auth_profile':
                    try:
                        item['user_auth_profile_id'] = self.ngfw_data['auth_profiles'][item['user_auth_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль аутентификации для администратора "{item["login"]}". Профиль установлен в дефолтное значение.')
                        item['user_auth_profile_id'] = 'Example user auth profile'
                        error = 1

            json_file = os.path.join(path, 'administrators_list.json')
            with open(json_file, 'w') as fh:
                json.dump(result2, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Список администраторов выгружен в файл "{json_file}".')

        err, result3 = self.utm.get_admin_config()
        if err:
            self.stepChanged.emit(f'RED|    {result2}\n    Произошла ошибка при экспорте настроек аутентификации.')
            self.error = 1
            return

        json_file = os.path.join(path, 'auth_settings.json')
        with open(json_file, 'w') as fh:
            json.dump(result3, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    Настройки аутентификации выгружены в файл "{json_file}".')


        if error:
            self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте раздела "UserGate/Администраторы".')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Экспорт раздела "UserGate/Администраторы" завершён.')


    #---------------------------------- Сеть -------------------------------------------------------
    def export_zones(self, path):
        """Экспортируем список зон."""
        self.stepChanged.emit('BLUE|Экспорт настроек раздела "Сеть/Зоны".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return
        error = 0

        err, data = self.utm.get_zones_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}')
            error = 1
        else:
            for zone in data:
                zone['name'] = self.get_transformed_name(zone['name'], descr='Имя зоны')[1]
                zone.pop('id', None)
                zone.pop('cc', None)
                if self.utm.float_version < 7:
                    zone['sessions_limit_enabled'] = False
                    zone['sessions_limit_threshold'] = 0
                    zone['sessions_limit_exclusions'] = []
                elif self.utm.float_version == 7.0 and zone['sessions_limit_threshold'] == -1:
                    zone['sessions_limit_threshold'] = 0
                elif self.utm.float_version >= 7.1:
                    for net in zone['networks']:
                        if net[0] == 'list_id':
                            net[1] = self.ngfw_data['ip_lists'][net[1]]
                    for item in zone['sessions_limit_exclusions']:
                        item[1] = self.ngfw_data['ip_lists'][item[1]]

                # Удаляем неиспользуемые в настоящий момент сервисы зон: 3, 16, 20, 21 (в zone_services = false).
                new_services_access = []
                for service in zone['services_access']:
                    service['service_id'] = zone_services.get(service['service_id'], False)
                    for item in service['allowed_ips']:
                        if item[0] == 'list_id':
                            item[1] = self.ngfw_data['ip_lists'][item[1]]
                    if service['service_id']:
                        new_services_access.append(service)
                zone['services_access'] = new_services_access

            json_file = os.path.join(path, 'config_zones.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

        if error:
            self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте зон.')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Настройки зон выгружены в файл "{json_file}".')


    def export_interfaces_list(self, path):
        """Экспортируем список интерфейсов"""
        self.stepChanged.emit('BLUE|Экспорт интерфейсов из раздела "Сеть/Интерфейсы".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return
        error = 0

        err, result = self.utm.get_netflow_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        list_netflow = {x['id']: x['name'] for x in result}

        list_lldp = {}
        if self.utm.float_version >= 7.0:    
            err, result = self.utm.get_lldp_profiles_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return
            list_lldp = {x['id']: x['name'] for x in result}

        err, data = self.utm.get_interfaces_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте интерфейсов.')
            self.error = 1
            return

        iface_name = self.translate_iface_name(path, data)     # Преобразуем имена интерфейсов для версии 5 из eth в port.
        id_list = []
        for item in data:
            item['full_id'] = item['id']
            id_list.append(item['full_id'])
            item['id'], _ = item['id'].split(':')
            item.pop('link_info', None)
            item.pop('speed', None)
            item.pop('errors', None)
            item.pop('running', None)
#            item.pop('node_name', None)
            if item['zone_id']:
                item['zone_id'] = self.ngfw_data['zones'].get(item['zone_id'], 0)
            item['netflow_profile'] = list_netflow.get(item['netflow_profile'], 'undefined')
            lldp_profile = item.get('lldp_profile', 'undefined')
            item['lldp_profile'] = list_lldp.get(lldp_profile, 'undefined')
            if self.utm.float_version < 7.1:
                item['ifalias'] = ''
                item['flow_control'] = False
                if item['mode'] == 'dhcp':
                    item['dhcp_default_gateway'] = True
            if self.utm.float_version < 6:
                item.pop('iface_id', None)
                item.pop('qlen', None)
                item.pop('nameservers', None)
                item.pop('ifindex', None)
                item['id'] = iface_name[item['id']]
                item['name'] = iface_name[item['name']]
                if item['kind'] == 'vlan':
                    item['link'] = iface_name[item['link']]
                elif item['kind'] == 'bridge':
                    ports = item['bridging']['ports']
                    ports = [iface_name[x] for x in ports]
                    item['bridging']['ports'] = ports
                elif item['kind'] == 'bond':
                    ports = item['bonding']['slaves']
                    ports = [iface_name[x] for x in ports]
                    item['bonding']['slaves'] = ports
                if item['kind'] == 'ppp':
                    item.pop('dhcp_relay', None)
                    item['pppoe'].pop('index', None)
                    item['pppoe'].pop('name', None)
                    item['pppoe'].pop('iface_id', None)
                    item['pppoe'].pop('id', None)
                    if item['pppoe']['peer'] is None:
                        item['pppoe']['peer'] = ""
                    item['pppoe']['ifname'] = iface_name[item['pppoe']['ifname']]
                if item['kind'] == 'tunnel':
                    item.pop('dhcp_relay', None)
                    item['tunnel'].pop('name', None)
                    item['tunnel'].pop('ttl', None)
                    item['tunnel'].pop('id', None)
                    if 'vni' not in item['tunnel'].keys():
                        item['tunnel']['vni'] = 0
                if item['kind'] not in ('vpn', 'ppp', 'tunnel'):
                    if not item['dhcp_relay']:
                        item['dhcp_relay'] = {
                            'enabled': False,
                            'host_ipv4': '',
                            'servers': []
                        }
                    else:
                        item['dhcp_relay'].pop('id', None)
                        item['dhcp_relay'].pop('iface_id', None)

        data.sort(key=lambda x: x['name'])
        self.add_tags_for_rules(data, id_list, object_type='interfaces')

        json_file = os.path.join(path, 'config_interfaces.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Настройки интерфейсов выгружены в файл "{json_file}".')


    def export_gateways_list(self, path):
        """Экспортируем список шлюзов"""
        self.stepChanged.emit('BLUE|Экспорт шлюзов раздела "Сеть/Шлюзы".')

        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте шлюзов.')
            self.error = 1
            return

        err, data = self.utm.get_gateways_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте шлюзов.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_interfaces_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}/n    Произошла ошибка при экспорте шлюзов.')
                self.error = 1
                return
            else:
                iface_names = self.translate_iface_name(path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.
                iface_names['undefined'] = 'undefined'

            for item in data:
                item.pop('id', None)
                item.pop('active', None)
                item.pop('protocol', None)
                item.pop('_appliance_iface', None)
                item.pop('index', None)
                item.pop('uid', None)
                item.pop('cc', None)
                if not 'name' in item or not item['name']:
                    item['name'] = item['ipv4']
                item['iface'] = iface_names[item['iface']] if item['iface'] else 'undefined'
                if self.utm.float_version < 6:
                    item['is_automatic'] = False
                    item['vrf'] = 'default'

            json_file = os.path.join(path, 'config_gateways.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки шлюзов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет шлюзов для экспорта.')

        """Экспортируем настройки проверки сети шлюзов"""
        self.stepChanged.emit('BLUE|Экспорт проверки сети раздела "Сеть/Шлюзы".')

        err, result = self.utm.get_gateway_failover()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте настроек проверки сети.')
            self.error = 1
        else:
            json_file = os.path.join(path, 'config_gateway_failover.json')
            with open(json_file, 'w') as fh:
                json.dump(result, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки "Проверка сети" выгружены в файл "{json_file}".')


    def export_dhcp_subnets(self, path):
        """Экспортируем настройки DHCP"""
        self.stepChanged.emit('BLUE|Экспорт настроек DHCP раздела "Сеть/DHCP".')
        err, data = self.utm.get_dhcp_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте настроек DHCP.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_interfaces_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте настроек DHCP.')
                self.error = 1
                return
            else:
                iface_names = self.translate_iface_name(path, result) # Преобразуем имена интерфейсов для версии 5 из eth в port.

            for item in data:
                item['iface_id'] = iface_names[item['iface_id']]
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(path, 'config_dhcp_subnets.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек DHCP для экспорта.')


    def export_dns_config(self, path):
        """Экспортируем настройки DNS"""
        self.stepChanged.emit('BLUE|Экспорт настройек DNS раздела "Сеть/DNS".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        error = 0
        params = (
            'use_cache_enabled',
            'enable_dns_filtering',
            'recursive_enabled',
            'dns_max_ttl',
            'dns_max_queries_per_user',
            'only_a_for_unknown',
            'dns_receive_timeout',
            'dns_max_attempts'
        )
        err, result = self.utm.get_settings_params(params)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            json_file = os.path.join(path, 'config_dns_proxy.json')
            with open(json_file, 'w') as fh:
                json.dump(result, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Настройки DNS-прокси выгружены в файл "{json_file}".')

        err, result = self.utm.get_dns_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            if result:
                json_file = os.path.join(path, 'config_dns_servers.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Список системных DNS серверов выгружен в файл "{json_file}".')
    
        err, result = self.utm.get_dns_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            if result:
                for item in result:
                    item.pop('id', None)
                    item.pop('cc', None)
                    item.pop('position_layer', None)
                json_file = os.path.join(path, 'config_dns_rules.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Список правил DNS прокси выгружен в файл "{json_file}".')
    
        err, result = self.utm.get_dns_static_records()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            if result:
                for item in result:
                    item.pop('id', None)
                    item.pop('cc', None)
                json_file = os.path.join(path, 'config_dns_static.json')
                with open(json_file, 'w') as fh:
                    json.dump(result, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Статические записи DNS прокси выгружены в файл "{json_file}".')

        if error:
            self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DNS.')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Настройки DNS экспортированы в каталог "{path}".')


    def export_vrf_list(self, path):
        """Экспортируем настройки VRF"""
        self.stepChanged.emit('BLUE|Экспорт настроек VRF раздела "Сеть/Виртуальные маршрутизаторы".')
        err, data = self.utm.get_routes_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте настроек VRF.')
            self.error = 1
            return

        if data:
            if self.utm.float_version >= 7.1:
                err, result = self.utm.get_bfd_profiles()
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте настроек VRF.')
                    self.error = 1
                    return
                bfd_profiles = {x['id']: x['name'] for x in result}
                bfd_profiles[-1] = -1

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                for x in item['routes']:
                    x.pop('id', None)
                route_maps = {}
                filters = {}
                item['bgp'].pop('id', None)
                if item['bgp']['as_number'] == "null":
                    item['bgp']['as_number'] = 0
                if self.utm.float_version < 7:
                    item['bgp']['as_number'] = int(item['bgp']['as_number'])
                for x in item['bgp']['routemaps']:
                    route_maps[x['id']] = x['name']
                    x.pop('id', None)
                for x in item['bgp']['filters']:
                    filters[x['id']] = x['name']
                    x.pop('id', None)
                for x in item['bgp']['neighbors']:
                    x.pop('id', None)
                    x.pop('state', None)
                    x['remote_asn'] = int(x['remote_asn'])
                    for i, rmap in enumerate(x['filter_in']):
                        x['filter_in'][i] = filters[rmap]
                    for i, rmap in enumerate(x['filter_out']):
                        x['filter_out'][i] = filters[rmap]
                    for i, rmap in enumerate(x['routemap_in']):
                        x['routemap_in'][i] = route_maps[rmap]
                    for i, rmap in enumerate(x['routemap_out']):
                        x['routemap_out'][i] = route_maps[rmap]
                    x['bfd_profile'] = -1 if self.utm.float_version < 7.1 else bfd_profiles[x['bfd_profile']]

                item['ospf'].pop('id', None)
                # В версии 6 переделываем item['ospf'] для версии 7.4
                if isinstance(item['ospf']['default_originate'], bool):
                    new_redistribute = []
                    for x in item['ospf']['redistribute']:
                        new_redistribute.append({
                            'enabled': True,
                            'kind': x,
                            'metric': item['ospf']['metric'],
                            'routemaps': []
                        })
                    item['ospf']['redistribute'] = new_redistribute
                    item['ospf']['routemaps'] = []
                    item['ospf']['default_originate'] = {
                        'enabled': item['ospf']['default_originate'],
                        'always': False,
                        'metric': item['ospf']['metric']
                    }
                    item['ospf'].pop('metric', None)

                for x in item['ospf']['interfaces']:
                    x['bfd_profile'] = -1 if self.utm.float_version < 7.1 else bfd_profiles[x['bfd_profile']]
                for x in item['ospf']['areas']:
                    x.pop('id', None)
                item['rip'].pop('id', None)
                if not isinstance(item['rip']['default_originate'], bool):
                    item['rip']['default_originate'] = True
                item['pimsm'].pop('id', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(path, 'config_vrf.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки VRF выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет настроек VRF для экспорта.')


    def export_routes(self, path):
        """Экспортируем список маршрутов. Только версия 5."""
        self.stepChanged.emit('BLUE|Экспорт списка маршрутов раздела "Сеть/Маршруты".')
        path = path.replace('Routes', 'VRF', 1)
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        err, result = self.utm.get_interfaces_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте списка маршрутов.')
            self.error = 1
            return
        else:
            iface_names = self.translate_iface_name(path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

        routes = []
        err, data = self.utm.get_routes_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте списка маршрутов.')
            self.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('node_name', None)
            if 'name' not in item.keys() or not item['name']:
                item['name'] = item['dest']
            item.pop('multihop', None)
            item.pop('vrf', None)
            item.pop('active', None)
            item['ifname'] = iface_names[item['iface_id']] if item['iface_id'] else 'undefined'
            item.pop('iface_id', None)
            item['kind'] = 'unicast'

        routes.append({
            'name': 'default',
            'description': '',
#            'interfaces': [],
            'routes': data,
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {},
        })

        json_file = os.path.join(path, 'config_vrf.json')
        with open(json_file, 'w') as fh:
            json.dump(routes, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'GREEN|    Список маршрутов выгружен в файл "{json_file}".')


    def export_ospf_config(self, path):
        """Экспортируем конфигурацию OSPF (только для v.5)"""
        self.stepChanged.emit('BLUE|Экспорт конфигурации OSPF раздела "Сеть/OSPF".')
        path = path.replace('OSPF', 'VRF', 1)
        json_file = os.path.join(path, 'config_vrf.json')

        err, msg = self.create_dir(path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as fh:
                    data = json.load(fh)
            except Exception as err:
                self.stepChanged.emit(f'RED|    {err}\n    Произошла ошибка при экспорте конфигурации OSPF.')
                self.error = 1
                return
        else:
            data = [{
                'name': 'default',
                'description': '',
                'routes': [],
                'ospf': {},
                'bgp': {},
                'rip': {},
                'pimsm': {},
            },]

        err, result = self.utm.get_interfaces_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте конфигурации OSPF.')
            self.error = 1
            return
        else:
            iface_names = self.translate_iface_name(path, result)     # Преобразуем имена интерфейсов для версии 5 из eth в port.

        err, ospf, ifaces, areas = self.utm.get_ospf_config()
        if err:
            self.stepChanged.emit(f'RED|    {ospf}\n    Произошла ошибка при экспорте конфигурации OSPF.')
            self.error = 1
            return

        ospf['enabled'] = False
        for item in ifaces:
            item['iface_id'], _ = item['iface_id'].split(':')
            item['iface_id'] = iface_names[item['iface_id']]
            item['auth_params'].pop('md5_key', None)
            item['auth_params'].pop('plain_key', None)
            item['bfd_profile'] = -1
        for item in areas:
            item.pop('id', None)
            item.pop('area_range', None)

        ospf['interfaces'] = ifaces
        ospf['areas'] = areas
        for item in data:
            if item['name'] == 'default':
                item['ospf'] = ospf
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Конфигурация OSPF выгружена в файл "{json_file}".')
                break


    def export_bgp_config(self, path):
        """Экспортируем конфигурацию BGP (только для v.5)"""
        self.stepChanged.emit('BLUE|Экспорт конфигурации BGP раздела "Сеть/BGP".')
        path = path.replace('BGP', 'VRF', 1)
        json_file = os.path.join(path, 'config_vrf.json')

        err, msg = self.create_dir(path, delete='no')
        if err:
            self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте конфигурации BGP.')
            self.error = 1
            return

        if os.path.exists(json_file):
            try:
                with open(json_file, 'r') as fh:
                    data = json.load(fh)
            except Exception as err:
                self.stepChanged.emit(f'RED|    {err}\n    Произошла ошибка при экспорте конфигурации BGP.')
                self.error = 1
                return
        else:
            data = [{
                'name': 'default',
                'description': '',
                'routes': [],
                'ospf': {},
                'bgp': {},
                'rip': {},
                'pimsm': {},
            },]

        err, bgp, neigh, rmaps, filters = self.utm.get_bgp_config()
        if err:
            self.stepChanged.emit(f'RED|    {bgp}\n    Произошла ошибка при экспорте конфигурации BGP.')
            self.error = 1
            return

        route_maps = {}
        bgp_filters = {}
        if bgp['as_number'] == 'null':
            bgp['as_number'] = 0
        else:
            bgp['as_number'] = int(bgp['as_number'])
        bgp.pop('id', None)
        bgp.pop('strict_ip', None)
        bgp.pop('multiple_asn', None)
        for item in rmaps:
            route_maps[item['id']] = item['name']
            item.pop('id', None)
            item.pop('position', None)
            item['match_items'] = [x[:-4] for x in item['match_items']]
        for item in filters:
            bgp_filters[item['id']] = item['name']
            item.pop('id', None)
            item.pop('position', None)
            item['filter_items'] = [x[:-4] for x in item['filter_items']]
        for item in neigh:
            item.pop('id', None)
            item.pop('iface_id', None)
            item.pop('state', None)
            item['remote_asn'] = int(item['remote_asn'])
            for i, fmap in enumerate(item['filter_in']):
                item['filter_in'][i] = bgp_filters[fmap]
            for i, fmap in enumerate(item['filter_out']):
                item['filter_out'][i] = bgp_filters[fmap]
            for i, fmap in enumerate(item['routemap_in']):
                item['routemap_in'][i] = route_maps[fmap]
            for i, fmap in enumerate(item['routemap_out']):
                item['routemap_out'][i] = route_maps[fmap]
            item['bfd_profile'] = -1
        bgp['routemaps'] = rmaps
        bgp['filters'] = filters
        bgp['neighbors'] = neigh
        for item in data:
            if item['name'] == 'default':
                item['bgp'] = bgp
                with open(json_file, 'w') as fh:
                    json.dump(data, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'GREEN|    Конфигурация BGP выгружена в файл "{json_file}".')
                break


    def export_wccp(self, path):
        """Экспортируем список правил WCCP"""
        self.stepChanged.emit('BLUE|Экспорт списка правил WCCP из раздела "Сеть/WCCP".')

        err, data = self.utm.get_wccp_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка правил WCCP.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item['ports'] = [int(x) for x in item['ports']]
                item.pop('id', None)
                item.pop('cc', None)
                if item['routers']:
                    for x in item['routers']:
                        x[1] = self.ngfw_data['ip_lists'][x[1]] if x[0] == 'list_id' else x[1]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте списка правил WCCP.')
                self.error = 1
                return

            json_file = os.path.join(path, 'config_wccp.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список правил WCCP выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил WCCP для экспорта.')


    def export_local_groups(self, path):
        """Экспортируем список локальных групп пользователей"""
        self.stepChanged.emit('BLUE|Экспорт списка локальных групп из раздела "Пользователи и устройства/Группы".')
        error = 0

        err, data = self.utm.get_groups_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка локальных групп.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                item.pop('cc', None)
                err, users = self.utm.get_group_users(item['id'])
                if err:
                    self.stepChanged.emit(f'RED|    {users}')
                    item['users'] = []
                    error = 1
                else:
                    if self.utm.float_version < 6:
                        item['users'] = [x['name'] for x in users]
                    else:
                        item['users'] = [x[1] for x in users]
                item.pop('id', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте списка локальных групп.')
                self.error = 1
                return

            json_file = os.path.join(path, 'config_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных групп.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Список локальных групп выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет локальных групп для экспорта.')
    

    def export_local_users(self, path):
        """Экспортируем список локальных пользователей"""
        self.stepChanged.emit('BLUE|Экспорт списка локальных пользователей из раздела "Пользователи и устройства/Пользователи".')
        err, data = self.utm.get_users_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка локальных пользователей.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('icap_clients', None)
                item.pop('creation_date', None)
                item.pop('expiration_date', None)
                item.pop('cc', None)
                if not item['first_name']:
                    item['first_name'] = ""
                if not item['last_name']:
                    item['last_name'] = ""
                item['groups'] = [self.ngfw_data['local_groups'][guid] for guid in item['groups']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(path, 'config_users.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет локальных пользователей для экспорта.')


    def export_auth_servers(self, path):
        """Экспортируем список серверов аутентификации"""
        self.stepChanged.emit('BLUE|Экспорт списка серверов аутентификации из раздела "Пользователи и устройства/Серверы аутентификации".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте списка серверов аутентификации.')
            self.error = 1
            return

        err, ldap, radius, tacacs, ntlm, saml = self.utm.get_auth_servers()
        if err:
            self.stepChanged.emit(f'RED|    {ldap}\n    Произошла ошибка при экспорте списка серверов аутентификации.')
            self.error = 1
            return

        n = 0
        if ldap:
            json_file = os.path.join(path, 'config_ldap_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ldap, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Список серверов LDAP выгружен в файл "{json_file}".')
        else:
            n += 1
        if radius:
            json_file = os.path.join(path, 'config_radius_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(radius, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Список серверов RADIUS выгружен в файл "{json_file}".')
        else:
            n += 1
        if tacacs:
            json_file = os.path.join(path, 'config_tacacs_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(tacacs, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Список серверов TACACS выгружен в файл "{json_file}".')
        else:
            n += 1
        if ntlm:
            json_file = os.path.join(path, 'config_ntlm_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ntlm, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Список серверов NTLM выгружен в файл "{json_file}".')
        else:
            n += 1
        if saml:
            for item in saml:
                item['certificate_id'] = self.ngfw_data['certs'].get(item['certificate_id'], 0)
            json_file = os.path.join(path, 'config_saml_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(saml, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'BLACK|    Список серверов SAML выгружен в файл "{json_file}".')
        else:
            n += 1

        if n == 5:
            self.stepChanged.emit(f'GRAY|    Нет серверов аутентификации для экспорта.')
        else:
            self.stepChanged.emit(f'GREEN|    Список серверов аутентификации экспортирован.')


    def export_2fa_profiles(self, path):
        """Экспортируем список MFA профилей"""
        self.stepChanged.emit('BLUE|Экспорт списка MFA профилей из раздела "Пользователи и устройства/Профили MFA".')

        err, data = self.utm.get_2fa_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка MFA профилей.')
            self.error = 1
            return

        if data:
            if 'notification_profiles' not in self.ngfw_data:
                if self.get_notification_profiles():    # Заполняем self.ngfw_data['notification_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка MFA профилей.')
                    return
            list_notifications = self.ngfw_data['notification_profiles']

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте списка MFA профилей.')
                self.error = 1
                return

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                if item['type'] == 'totp':
                    item['init_notification_profile_id'] = list_notifications.get(item['init_notification_profile_id'], item['init_notification_profile_id'])
                    item.pop('auth_notification_profile_id', None)
                else:
                    item['auth_notification_profile_id'] = list_notifications.get(item['auth_notification_profile_id'], item['auth_notification_profile_id'])
                    item.pop('init_notification_profile_id', None)

            json_file = os.path.join(path, 'config_2fa_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список MFA профилей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет MFA профилей для экспорта.')


    def export_auth_profiles(self, path):
        """Экспортируем список профилей аутентификации"""
        self.stepChanged.emit('BLUE|Экспорт списка профилей авторизации из раздела "Пользователи и устройства/Профили аутентификации".')

        err, data = self.utm.get_auth_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей аутентификации.')
            self.error = 1
            return

        if data:
            err, ldap, radius, tacacs, ntlm, saml = self.utm.get_auth_servers()
            if err:
                self.stepChanged.emit(f'RED|    {ldap}\n    Произошла ошибка при экспорте профилей аутентификации.')
                self.error = 1
                return
            auth_servers = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

            err, result = self.utm.get_2fa_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте профилей аутентификации.')
                self.error = 1
                return
            profiles_2fa = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                item['2fa_profile_id'] = profiles_2fa.get(item['2fa_profile_id'], False)
                for auth_method in item['allowed_auth_methods']:
                    if len(auth_method) == 2:
                        if 'saml_idp_server' in auth_method:
                            auth_method['saml_idp_server_id'] = auth_method.pop('saml_idp_server', False)
                        for key, value in auth_method.items():
                            if isinstance(value, int):
                                auth_method[key] = auth_servers[value]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте профилей аутентификации.')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_auth_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список профилей аутентификации выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей аутентификации для экспорта.')


    def export_captive_profiles(self, path):
        """Экспортируем список Captive-профилей"""
        self.stepChanged.emit('BLUE|Экспорт списка Captive-профилей из раздела "Пользователи и устройства/Captive-профили".')

        err, data = self.utm.get_captive_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте Captive-профилей.')
            self.error = 1
            return

        if data:
            if 'list_templates' not in self.ngfw_data:
                if self.get_templates_list():     # Заполняем self.ngfw_data['list_templates']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
                    return
            list_templates = self.ngfw_data['list_templates']

            if 'notification_profiles' not in self.ngfw_data:
                if self.get_notification_profiles():    # Заполняем self.ngfw_data['notification_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
                    return
            list_notifications = self.ngfw_data['notification_profiles']

            if (6 <= self.utm.float_version < 7.1):
                result = self.utm._server.v3.accounts.groups.list(self.utm._auth_token, 0, 1000, {}, [])['items']
                list_groups = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            if 'client_cert_profiles' not in self.ngfw_data:
                if self.get_client_certificate_profiles():     # Заполняем self.ngfw_data['client_cert_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
                    return

            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                item['captive_template_id'] = list_templates.get(item['captive_template_id'], -1)
                item['notification_profile_id'] = list_notifications.get(item['notification_profile_id'], -1)
                try:
                    item['user_auth_profile_id'] = self.ngfw_data['auth_profiles'][item['user_auth_profile_id']]
                except KeyError:
                    self.stepChanged.emit('bRED|    Warning: Не найден профиль аутентификации для Captive-профиля "{item["name"]}". Профиль установлен в дефолтное значение.')
                    item['user_auth_profile_id'] = 'Example user auth profile'
#                    for k, v in self.ngfw_data['auth_profiles'].items():
#                        print(k, '-', v)
                if (6 <= self.utm.float_version < 7.1):
                    item['ta_groups'] = [list_groups[guid] for guid in item['ta_groups']]
                else:
                    item['ta_groups'] = [self.ngfw_data['local_groups'][guid] for guid in item['ta_groups']]
                if self.utm.float_version < 6:
                    item['ta_expiration_date'] = ''
                else:
                    if item['ta_expiration_date']:
                        item['ta_expiration_date'] = dt.strptime(item['ta_expiration_date'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                if self.utm.float_version >= 7.1:
                    item['use_https_auth'] = True
                    item['client_certificate_profile_id'] = self.ngfw_data['client_cert_profiles'].get(item['client_certificate_profile_id'], 0)
                else:
                    item['captive_auth_mode'] = 'aaa'
                    item['client_certificate_profile_id'] = 0
                item.pop('id', None)    # это есть в версии 5
                item.pop('guid', None)  # это есть в версии 6 и выше
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_captive_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список Captive-профилей выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет Captive-профилей для экспорта.')


    def export_captive_portal_rules(self, path):
        """Экспортируем список правил Captive-портала"""
        self.stepChanged.emit('BLUE|Экспорт списка правил Captive-портала из раздела "Пользователи и устройства/Captive-портал".')

        err, data = self.utm.get_captive_portal_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил Captive-портала.')
            self.error = 1
            return

        error = 0
        if data:
            err, result = self.utm.get_captive_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил Captive-портала.')
                self.error = 1
                return
            captive_profiles = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('rownumber', None)
                item.pop('position_layer', None),
                item.pop('time_created', None)
                item.pop('time_updated', None)
                item['profile_id'] = captive_profiles.get(item['profile_id'], 0)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['urls'] = self.get_urls_name(item['urls'], item)
                item['url_categories'] = self.get_url_categories_name(item['url_categories'], item)
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)

                if item.pop('error', False):
                    error = 1

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_captive_portal_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил Captive-портала.')
            else:
                self.stepChanged.emit(f'GREEN|    Список правил Captive-портала выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил Captive-портала для экспорта.')


    def export_terminal_servers(self, path):
        """Экспортируем список терминальных серверов"""
        self.stepChanged.emit('BLUE|Экспорт списка терминальных серверов из раздела "Пользователи и устройства/Терминальные серверы".')

        err, data = self.utm.get_terminal_servers()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте терминальных серверов.')
            self.error = 1
            return
        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя сервера')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_terminal_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список терминальных серверов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет терминальных серверов для экспорта.')


    def export_byod_policy(self, path):
        """Экспортируем список Политики BYOD"""
        self.stepChanged.emit('BLUE|Экспорт списка Политики BYOD из раздела "Пользователи и устройства/Политики BYOD".')

        err, data = self.utm.get_byod_policy()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка "Политики BYOD".')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя BYOD')[1]
                item.pop('id', None)
                item.pop('position_layer', None)
                item.pop('deleted_users', None)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_byod_policy.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список "Политики BYOD" выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет политики BYOD для экспорта.')


    def export_userid_agent(self, path):
        """Экспортируем настройки UserID агент"""
        self.stepChanged.emit('BLUE|Экспорт настроек UserID агент из раздела "Пользователи и устройства/UserID агент".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return
        expiration_time = 2700

        err, data = self.utm.get_useridagent_config()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n       Произошла ошибка при экспорте настроек свойств агента UserID.')
            self.error = 1
        else:
            data.pop('cc', None)
            expiration_time = data.pop('expiration_time', 2700)
            if 'radius_monitoring_interval' not in data:
                data['radius_monitoring_interval'] = 120
            if data['tcp_ca_certificate_id']:
                data['tcp_ca_certificate_id'] = self.ngfw_data['certs'][data['tcp_ca_certificate_id']]
            if data['tcp_server_certificate_id']:
                data['tcp_server_certificate_id'] = self.ngfw_data['certs'][data['tcp_server_certificate_id']]
            data['ignore_networks'] = [['list_id', self.ngfw_data['ip_lists'][x[1]]] for x in data['ignore_networks']]

            json_file = os.path.join(path, 'userid_agent_config.json')
            with open(json_file, 'w') as fh:
                json.dump([data], fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Настройки свойств агента UserID выгружены в файл "{json_file}".')


        err, data = self.utm.get_useridagent_servers()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n       Произошла ошибка при экспорте коннекторов агента UserID.')
            return

        if data:
            err, result = self.utm.get_useridagent_filters()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n       Произошла ошибка при экспорте коннекторов агента UserID.')
                self.error = 1
                return
            useridagent_filters = {x['id']: x['name'] for x in result}

            for item in data:
                item.pop('id', None)
                item.pop('status', None)
                item.pop('cc', None)
                if 'expiration_time' not in item:
                    item['expiration_time'] = expiration_time
                if item['type'] == 'radius':
                    item['server_secret'] = ''
                item['auth_profile_id'] = self.ngfw_data['auth_profiles'][item['auth_profile_id']]
                if 'filters' in item:
                    item['filters'] = [useridagent_filters[x] for x in item['filters']]

            json_file = os.path.join(path, 'userid_agent_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Коннекторы UserID агент выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет коннекторов агента UserID для экспорта.')


    #------------------------------ Политики сети --------------------------------------------------
    def export_firewall_rules(self, path):
        """Экспортируем список правил межсетевого экрана"""
        self.stepChanged.emit('BLUE|Экспорт правил межсетевого экрана из раздела "Политики сети/Межсетевой экран".')

        err, data = self.utm.get_firewall_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил межсетевого экрана.')
            self.error = 1
            return

        if data:
            error = 0
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Заполняем self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил межсетевого экрана.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

            if self.utm.float_version >= 7.1:
                err, result = self.utm.get_l7_profiles_list()
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил межсетевого экрана.')
                    self.error = 1
                    return
                l7_profiles = {x['id']: x['name'] for x in result}

                if self.utm.product != 'dcfw':
                    err, result = self.utm.get_hip_profiles_list()
                    if err:
                        self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил межсетевого экрана.')
                        self.error = 1
                        return
                    hip_profiles = {x['id']: x['name'] for x in result}

                idps_profiles = {}
                err, result = self.utm.get_idps_profiles_list()
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n       Не удалось получить профили СОВ для экспорта правил МЭ. Профили СОВ не будут установлены в правилах.')
                    error = 1
                else:
                    idps_profiles = {x['id']: x['name'] for x in result}

            id_list = []
            duplicate = {}
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                if item['name'] in duplicate.keys():
                    num = duplicate[item['name']]
                    num = num + 1
                    duplicate[item['name']] = num
                    item['name'] = f"{item['name']} {num}"
                else:
                    duplicate[item['name']] = 0
                id_list.append(item['id'])
                item.pop('guid', None)
                item.pop('rownumber', None)
                item.pop('active', None)
                item.pop('deleted_users', None)

                if item['scenario_rule_id']:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['services'] = self.get_services(item['services'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                if 'apps' in item:
                    item['apps'] = self.get_apps(item['apps'], item)
                if 'ips_profile' in item and item['ips_profile']:
                    try:
                        item['ips_profile'] = idps_profiles[item['ips_profile']]
                    except KeyError as err:
                        self.stepChanged.emit('RED|    Error: [Правило "{item["name"]}"] Не найден профиль СОВ.')
                        error = 1
                        item['ips_profile'] = False
                if 'l7_profile' in item and item['l7_profile']:
                    item['l7_profile'] = l7_profiles[item['l7_profile']]

                if self.utm.product == 'dcfw':
                    item['hip_profiles'] = []
                else:
                    if 'hip_profiles' in item:
                        item['hip_profiles'] = [hip_profiles[x] for x in item['hip_profiles']]

                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='fw_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_firewall_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил межсетевого экрана.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил межсетевого экрана для экспорта.')


    def export_nat_rules(self, path):
        """Экспортируем список правил NAT"""
        self.stepChanged.emit('BLUE|Экспорт правил NAT из раздела "Политики сети/NAT и маршрутизация".')

        err, data = self.utm.get_traffic_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил NAT.')
            self.error = 1
            return

        if data:
            error = 0
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Заполняем self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил межсетевого экрана.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

            err, result = self.utm.get_gateways_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил NAT.')
                self.error = 1
                return
            ngfw_gateways = {f'{x["id"]}:{x["node_name"]}': x['name'] for x in result if 'name' in x}

            id_list = []
            for item in data:
                id_list.append(item['id'])
                item.pop('cc', None)
                item.pop('guid', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                if item['scenario_rule_id']:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                item['zone_in'] = self.get_zones_name(item['zone_in'], item)
                if item['action'] != 'nat':
                    item['zone_out'] = []
                else:
                    item['zone_out'] = self.get_zones_name(item['zone_out'], item)
                item['source_ip'] = self.get_ips_name(item['source_ip'], item)
                item['dest_ip'] = self.get_ips_name(item['dest_ip'], item)
                if item['action'] == 'port_mapping':
                    item['service'] = []
                else:
                    item['service'] = self.get_services(item['service'], item)
                item['gateway'] = ngfw_gateways.get(item['gateway'], item['gateway'])
                if self.utm.float_version >= 6:
                    item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                else:
                    item['users'] = []
                    item['position_layer'] = 'local'
                    item['time_created'] = ''
                    item['time_updated'] = ''

                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='traffic_rule')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_nat_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил NAT.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила NAT выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил NAT для экспорта.')


    def export_loadbalancing_rules(self, path):
        """Экспортируем список правил балансировки нагрузки"""
        self.stepChanged.emit('BLUE|Экспорт правил балансировки нагрузки из раздела "Политики сети/Балансировка нагрузки".')
        err, tcpudp, icap, reverse = self.utm.get_loadbalancing_rules()
        if err:
            self.stepChanged.emit(f'RED|    {tcpudp}\n    Произошла ошибка при экспорте правил балансировки нагрузки.')
            self.error = 1
            return

        if tcpudp or icap or reverse:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте правил балансировки нагрузки.')
                self.error = 1
                return
        else:
            self.stepChanged.emit(f'GRAY|    Нет правил балансировки нагрузки  для экспорта.')
            return

        tcp_err = 0; icap_err = 0; reverse_err = 0
        if tcpudp:
            tcp_err = self.export_loadbalancing_tcpudp(path, tcpudp)
        if self.utm.product != 'dcfw':
            if icap:
                icap_err = self.export_loadbalancing_icap(path, icap)
            if reverse:
                reverse_err = self.export_loadbalancing_reverse(path, reverse)

        if tcp_err or icap_err or reverse_err:
            self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил балансировки нагрузки.')
        else:
            self.stepChanged.emit('GREEN|    Экспорт правил балансировки нагрузки завершён.')


    def export_loadbalancing_tcpudp(self, path, tcpudp):
        """Экспортируем балансировщики TCP/UDP"""
        self.stepChanged.emit('BLUE|    Экспортируем балансировщики TCP/UDP.')
        for item in tcpudp:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)
            item['name'] = self.get_transformed_name(item['name'], descr='Имя балансировщика')[1]
            if self.utm.float_version < 7.1:
                item['src_zones'] = []
                item['src_zones_negate'] = False
                item['src_ips'] = []
                item['src_ips_negate'] = False
            else:
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)

        json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
        with open(json_file, 'w') as fh:
            json.dump(tcpudp, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|       Список балансировщиков TCP/UDP выгружен в файл "{json_file}".')
        return 0


    def export_loadbalancing_icap(self, path, icap):
        """Экспортируем балансировщики ICAP"""
        self.stepChanged.emit('BLUE|    Экспортируем балансировщики ICAP.')
        err, result = self.utm.get_icap_servers()
        if err:
            self.stepChanged.emit(f'RED|       {result}\n       Произошла ошибка при экспорте балансировиков ICAP.')
            self.error = 1
            return 1
        icap_servers = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

        for item in icap:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = self.get_transformed_name(item['name'], descr='Имя балансировщика')[1]
            item['profiles'] = [icap_servers[x] for x in item['profiles']]

        json_file = os.path.join(path, 'config_loadbalancing_icap.json')
        with open(json_file, 'w') as fh:
            json.dump(icap, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|       Список балансировщиков ICAP выгружен в файл "{json_file}".')
        return 0


    def export_loadbalancing_reverse(self, path, reverse):
        """Экспортируем балансировщики reverse-прокси"""
        self.stepChanged.emit('BLUE|    Экспортируем балансировщики reverse-прокси.')
        err, result = self.utm.get_reverseproxy_servers()
        if err:
            self.stepChanged.emit(f'RED|       {result}\n       Произошла ошибка при экспорте балансировиков reverse-прокси.')
            self.error = 1
            return 1
        reverse_servers = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

        for item in reverse:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = self.get_transformed_name(item['name'], descr='Имя балансировщика')[1]
            item['profiles'] = [reverse_servers[x] for x in item['profiles']]

        json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
        with open(json_file, 'w') as fh:
            json.dump(reverse, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|       Список балансировщиков reverse-прокси выгружен в файл "{json_file}".')
        return 0


    def export_shaper_rules(self, path):
        """Экспортируем список правил пропускной способности"""
        self.stepChanged.emit('BLUE|Экспорт правил пропускной способности из раздела "Политики сети/Пропускная способность".')

        err, data = self.utm.get_shaper_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил пропускной способности.')
            self.error = 1
            return

        if data:
            error = 0
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Заполняем self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил пропускной способности.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

            err, result = self.utm.get_shaper_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил пропускной способности.')
                self.error = 1
                return
            shaper_list = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            id_list = []
            for item in data:
                id_list.append(item['id'])
                item.pop('rownumber', None)
                item.pop('guid', None)
                item.pop('deleted_users', None)
                item.pop('active', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя балансировщика')[1]
                if item['scenario_rule_id']:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['services'] = self.get_services(item['services'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['apps'] = self.get_apps(item['apps'], item)
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                item['pool'] = shaper_list[item['pool']]
                if self.utm.float_version < 6:
                    item['position_layer'] = 'local'
                    item['limit'] = True
                    item['limit_value'] = '3/h'
                    item['limit_burst'] = 5
                    item['log'] = False
                    item['log_session_start'] = True

                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='shaper_rule')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_shaper_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил пропускной способности.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил пропускной способности для экспорта.')


    #---------------------------- Политики безопасности ---------------------------------------
    def export_content_rules(self, path):
        """Экспортируем список правил фильтрации контента"""
        self.stepChanged.emit('BLUE|Экспорт список правил фильтрации контента из раздела "Политики безопасности/Фильтрация контента".')

        err, data = self.utm.get_content_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}/n    Произошла ошибка при экспорте правил фильтрации контента.')
            self.error = 1
            return

        if data:
            error = 0
            duplicate = {}
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Заполняем self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил фильтрации контента.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

            if 'list_templates' not in self.ngfw_data:
                if self.get_templates_list():     # Заполняем self.ngfw_data['list_templates']
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил фильтрации контента.')
                    return
            templates_list = self.ngfw_data['list_templates']

            err, result = self.utm.get_nlists_list('morphology')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил фильтрации контента.')
                self.error = 1
                return
            morphology_list = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            err, result = self.utm.get_nlists_list('useragent')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил фильтрации контента.')
                self.error = 1
                return
            useragent_list = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            data.pop()    # удаляем последнее правило (защищённое).
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                if item['name'] in duplicate.keys():
                    num = duplicate[item['name']]
                    num = num + 1
                    duplicate[item['name']] = num
                    item['name'] = f"{item['name']} {num}"
                else:
                    duplicate[item['name']] = 0
                id_list.append(item['id'])
                item.pop('rownumber', None)
                item.pop('guid', None)
                item.pop('deleted_users', None)
                item.pop('active', None)
                item['blockpage_template_id'] = templates_list.get(item['blockpage_template_id'], -1)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['url_categories'] = self.get_url_categories_name(item['url_categories'], item)
                item['morph_categories'] = [morphology_list[x] for x in item['morph_categories']]
                item['urls'] = self.get_urls_name(item['urls'], item)
                item['referers'] = self.get_urls_name(item['referers'], item)
                if 'referer_categories' in item:
                    item['referer_categories'] = self.get_url_categories_name(item['referer_categories'], item)
                else:
                    item['referer_categories'] = []     # В версии 5 этого поля нет.
                    item['users_negate'] = False        # В версии 5 этого поля нет.
                    item['position_layer'] = 'local'    # В версии 5 этого поля нет.
                for x in item['user_agents']:
                    x[1] = useragent_list[x[1]] if x[0] == 'list_id' else x[1]
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                item['content_types'] = [self.ngfw_data['mime'][x] for x in item['content_types']]
                if item['scenario_rule_id']:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                if self.utm.float_version < 7:
                    item['time_created'] = ''
                    item['time_updated'] = ''
                elif self.utm.float_version < 7.1:
                    item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                    item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)
                else:
                    if item['time_created'].value:
                        item['time_created'] = dt.strptime(item['time_created'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        item['time_created'] = ''
                    if item['time_updated'].value:
                        item['time_updated'] = dt.strptime(item['time_updated'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        item['time_updated'] = ''

                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='content_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_content_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил фильтрации контента.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила фильтрации контента выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил фильтрации контента для экспорта.')


    def export_safebrowsing_rules(self, path):
        """Экспортируем список правил веб-безопасности"""
        self.stepChanged.emit('BLUE|Экспорт правил веб-безопасности из раздела "Политики безопасности/Веб-безопасность".')

        err, data = self.utm.get_safebrowsing_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил веб-безопасности.')
            self.error = 1
            return

        if data:
            error = 0
            id_list = []
            for item in data:
                id_list.append(item['id'])
                item.pop('rownumber', None)
                item.pop('guid', None)
                item.pop('deleted_users', None)
                item.pop('active', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                item['url_list_exclusions'] = self.get_urls_name(item['url_list_exclusions'], item)
                if self.utm.float_version < 6:
                    item.pop('dst_zones', None)
                    item.pop('dst_ips', None)
                    item.pop('dst_zones_negate', None)
                    item.pop('dst_ips_negate', None)
                    item['position_layer'] = 'local'
                if self.utm.float_version < 7:
                    item['time_created'] = ''
                    item['time_updated'] = ''
                elif self.utm.float_version < 7.1:
                    item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                    item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)
                else:
                    if item['time_created'].value:
                        item['time_created'] = dt.strptime(item['time_created'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        item['time_created'] = ''
                    if item['time_updated'].value:
                        item['time_updated'] = dt.strptime(item['time_updated'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        item['time_updated'] = ''

                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='content_fo_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_safebrowsing_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил веб-безопасности.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила веб-безопасности выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил веб-безопасности для экспорта.')


    def export_tunnel_inspection_rules(self, path):
        """Экспортируем правила инспектирования туннелей"""
        self.stepChanged.emit('BLUE|Экспорт правил инспектирования туннелей из раздела "Политики безопасности/Инспектирование туннелей".')

        err, data = self.utm.get_tunnel_inspection_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил инспектирования туннелей.')
            self.error = 1
            return

        if data:
            error = 0
            id_list = []
            for item in data:
                id_list.append(item['id'])
                item.pop('guid', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                if item.pop('error', False):
                    error = 1
            self.add_tags_for_rules(data, id_list, object_type='tunnel_inspection_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил инспектирования туннелей.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила инспектирования туннелей выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил инспектирования туннелей для экспорта.')


    def export_ssldecrypt_rules(self, path):
        """Экспортируем список правил инспектирования SSL"""
        self.stepChanged.emit('BLUE|Экспорт правил инспектирования SSL из раздела "Политики безопасности/Инспектирование SSL".')

        err, data = self.utm.get_ssldecrypt_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил инспектирования SSL.')
            self.error = 1
            return

        if data:
            ssl_forward_profiles = {}
            if self.utm.float_version >= 7:
                err, result = self.utm.get_ssl_forward_profiles()
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил инспектирования SSL.')
                    self.error = 1
                    return
                ssl_forward_profiles = {x['id']: x['name'] for x in result}
                ssl_forward_profiles[-1] = -1

            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('rownumber', None)
                item.pop('guid', None)
                item.pop('deleted_users', None)
                item.pop('active', None)
                item.pop('content_types_negate', None)
                item.pop('url_list_exclusions', None)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['url_categories'] = self.get_url_categories_name(item['url_categories'], item)
                item['urls'] = self.get_urls_name(item['urls'], item)
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                if 'ssl_profile_id' in item:
                    item['ssl_profile_id'] = self.ngfw_data['ssl_profiles'].get(item['ssl_profile_id'], 'Default SSL profile')
                else:
                    item['ssl_profile_id'] = 'Default SSL profile'
                item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']] if 'ssl_forward_profile_id' in item else -1
                if self.utm.float_version < 6:
                    item['position_layer'] = 'local'
                if self.utm.float_version < 7:
                    item['time_created'] = ''
                    item['time_updated'] = ''
                elif self.utm.float_version < 7.1:
                    item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                    item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)
                else:
                    try:
                        item['time_created'] = dt.strptime(item['time_created'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        item['time_created'] = ''
                    try:
                        item['time_updated'] = dt.strptime(item['time_updated'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        item['time_updated'] = ''
                if item.pop('error', False):
                    error = 1
            self.add_tags_for_rules(data, id_list, object_type='content_https_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил инспектирования SSL.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила инспектирования SSL выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил инспектирования SSL для экспорта.')


    def export_sshdecrypt_rules(self, path):
        """Экспортируем список правил инспектирования SSH"""
        self.stepChanged.emit('BLUE|Экспорт правил инспектирования SSH из раздела "Политики безопасности/Инспектирование SSH".')

        err, data = self.utm.get_sshdecrypt_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил инспектирования SSH.')
            self.error = 1
            return

        if data:
            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('rownumber', None)
                item.pop('guid', None)
                item.pop('active', None)
                item.pop('urls_negate', None)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                item['protocols'] = self.get_services(item['protocols'], item)
                if self.utm.float_version < 7:
                    item['time_created'] = ''
                    item['time_updated'] = ''
                    item['layer'] = 'Content Rules'
                elif self.utm.float_version < 7.1:
                    item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                    item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)
                    item['layer'] = 'Content Rules'
                else:
                    try:
                        item['time_created'] = dt.strptime(item['time_created'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        item['time_created'] = ''
                    try:
                        item['time_updated'] = dt.strptime(item['time_updated'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        item['time_updated'] = ''
                if item.pop('error', False):
                    error = 1
            self.add_tags_for_rules(data, id_list, object_type='content_ssh_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил инспектирования SSH.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила инспектирования SSH выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил инспектирования SSH для экспорта.')


    def export_idps_rules(self, path):
        """Экспортируем список правил СОВ"""
        self.stepChanged.emit('BLUE|Экспорт правил СОВ из раздела "Политики безопасности/СОВ".')

        err, data = self.utm.get_idps_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил СОВ.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_nlists_list('ipspolicy')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил СОВ.')
                self.error = 1
                return
            idps_profiles = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            error = 0
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('apps', None)
                item.pop('apps_negate', None)
                item.pop('cc', None)
                if item['action'] == 'drop':   # Для версий < 7
                    item['action'] = 'reset'
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['services'] = self.get_services(item['services'], item)
                try:
                    item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
                except KeyError as err:
                    self.stepChanged.emit('RED|    Error: [Правило "{item["name"]}"] Не найден профиль СОВ {err}. Проверьте профиль СОВ этого правила.')
                    item['idps_profiles'] = []
                    error = 1
                if self.utm.float_version < 6:
                    item['position_layer'] = 'local'
                    item['idps_profiles_exclusions'] = []
                else:
                    try:
                        item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
                    except KeyError as err:
                        self.stepChanged.emit('RED|    Error: [Правило "{item["name"]}"] Не найден профиль исключения СОВ {err}. Проверьте профили СОВ этого правила.')
                        item['idps_profiles_exclusions'] = []
                        error = 1
                if item.pop('error', False):
                    error = 1

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_idps_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил СОВ.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила СОВ выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил СОВ для экспорта.')


    def export_scada_rules(self, path):
        """Экспортируем список правил АСУ ТП"""
        self.stepChanged.emit('BLUE|Экспорт правил АСУ ТП из раздела "Политики безопасности/Правила АСУ ТП".')

        err, data = self.utm.get_scada_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил АСУ ТП.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_scada_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил АСУ ТП.')
                self.error = 1
                return
            scada_profiles = {x['id']: x['name'] for x in result}

            error = 0
            for item in data:
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('cc', None)
                if self.utm.float_version < 6:
                    item['position_layer'] = 'local'
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['services'] = [self.ngfw_data['services'][x] for x in item['services']]
                item['scada_profiles'] = [scada_profiles[x] for x in item['scada_profiles']]
                if item.pop('error', False):
                    error = 1

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_scada_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил АСУ ТП.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила АСУ ТП выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил АСУ ТП для экспорта.')


    def export_scenarios(self, path):
        """Экспортируем список сценариев"""
        self.stepChanged.emit('BLUE|Экспорт списка сценариев из раздела "Политики безопасности/Сценарии".')

        err, data = self.utm.get_scenarios_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка сценариев.')
            self.error = 1
            return

        if data:
            error = 0
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item.pop('id', None)
                item.pop('cc', None)
                for condition in item['conditions']:
                    if condition['kind'] == 'application':
                        condition['apps'] = self.get_apps(condition['apps'], item)
                    elif condition['kind'] == 'mime_types':
                        condition['content_types'] = [self.ngfw_data['mime'][x] for x in condition['content_types']]
                    elif condition['kind'] == 'url_category':
                        condition['url_categories'] = self.get_url_categories_name(condition['url_categories'], item)

                if item.pop('error', False):
                    error = 1

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_scenarios.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка сценариев.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Список сценариев выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет сценариев для экспорта.')


    def export_mailsecurity_rules(self, path):
        """Экспортируем список правил защиты почтового трафика"""
        self.stepChanged.emit('BLUE|Экспорт правил защиты почтового трафика из раздела "Политики безопасности/Защита почтового трафика".')
        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}')
            self.error = 1
            return

        err, data = self.utm.get_mailsecurity_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил защиты почтового трафика.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_nlist_list('emailgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил защиты почтового трафика.')
                self.error = 1
                return
            email = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('guid', None)
                item.pop('deleted_users', None)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                if self.utm.float_version < 6:
                    item['services'] = [['service', "POP3" if x == 'pop' else x.upper()] for x in item.pop('protocol')]
                    if not item['services']:
                        item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
                    item['envelope_to_negate'] = False
                    item['envelope_from_negate'] = False
                    item['position_layer'] = 'local'
                else:
                    item['services'] = self.get_services(item['services'], item)
                if 'dst_zones_negate' not in item:      # Этого поля нет в версиях 5 и 6.
                    item['dst_zones_negate'] = False
                item['envelope_from'] = [[x[0], email[x[1]]] for x in item['envelope_from']]
                item['envelope_to'] = [[x[0], email[x[1]]] for x in item['envelope_to']]
                if self.utm.float_version < 7.1:
                    item['rule_log'] = False
                if item.pop('error', False):
                    error = 1
            self.add_tags_for_rules(data, id_list, object_type='mailsecurity_rule')

            json_file = os.path.join(path, 'config_mailsecurity_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте правил защиты почтового трафика.')
                self.error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Список правил защиты почтового трафика выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил защиты почтового трафика для экспорта.')


        err, dnsbl, batv = self.utm.get_mailsecurity_dnsbl()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте настроек антиспама.')
            self.error = 1
            return

        dnsbl['white_list'] = self.get_ips_name(dnsbl['white_list'], {'name': 'DNSBL white_list'})
        dnsbl['black_list'] = self.get_ips_name(dnsbl['black_list'], {'name': 'DNSBL black_list'})

        json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
        with open(json_file, 'w') as fh:
            json.dump(dnsbl, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    Настройки DNSBL выгружен в файл "{json_file}".')

        json_file = os.path.join(path, 'config_mailsecurity_batv.json')
        with open(json_file, 'w') as fh:
            json.dump(batv, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    Настройки BATV выгружен в файл "{json_file}".')
        self.stepChanged.emit('GREEN|    Раздел защиты почтового трафика экспортирован.')


    def export_icap_rules(self, path):
        """Экспортируем список правил ICAP"""
        self.stepChanged.emit('BLUE|Экспорт правил ICAP из раздела "Политики безопасности/ICAP-правила".')

        err, data = self.utm.get_icap_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил ICAP.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_icap_servers()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил ICAP.')
                self.error = 1
                return
            icap_servers = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            err, err_msg, result, _ = self.utm.get_loadbalancing_rules()
            if err:
                self.stepChanged.emit(f'RED|    {err_msg}\n    Произошла ошибка при экспорте правил ICAP.')
                self.error = 1
                return
            icap_loadbalancing = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('guid', None)
                for server in item['servers']:
                    if server[0] == 'lbrule':
                        try:
                            server[1] = icap_loadbalancing[server[1]]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Rule: "{item["name"]}"] Не найден балансировщик серверов ICAP {err}.')
                            error = 1
                            item['servers'] = []
                    elif server[0] == 'profile':
                        try:
                            server[1] = icap_servers[server[1]]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Rule: "{item["name"]}"] Не найден сервер ICAP {err}.')
                            error = 1
                            item['servers'] = []
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['url_categories'] = self.get_url_categories_name(item['url_categories'], item)
                item['urls'] = self.get_urls_name(item['urls'], item)
                item['content_types'] = [self.ngfw_data['mime'][x] for x in item['content_types']]
                if self.utm.float_version < 6:
                    item['position_layer'] = 'local'
                if self.utm.float_version < 7:
                    item['time_created'] = ''
                    item['time_updated'] = ''
                else:
                    item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                    item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)
                if item.pop('error', False):
                    error = 1
            self.add_tags_for_rules(data, id_list, object_type='icap_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_icap_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил ICAP.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила ICAP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил ICAP для экспорта.')


    def export_icap_servers(self, path):
        """Экспортируем список серверов ICAP"""
        self.stepChanged.emit('BLUE|Экспорт серверов ICAP из раздела "Политики безопасности/ICAP-серверы".')

        err, data = self.utm.get_icap_servers()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка серверов ICAP.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя сервера')[1]
                item.pop('id', None)
                item.pop('cc', None)
                item.pop('active', None)
                item.pop('error', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_icap_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit('GREEN|    Список серверов ICAP выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов ICAP для экспорта.')


    def export_dos_profiles(self, path):
        """Экспортируем список профилей DoS"""
        self.stepChanged.emit('BLUE|Экспорт профилей DoS из раздела "Политики безопасности/Профили DoS".')

        err, data = self.utm.get_dos_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей DoS.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_dos_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили DoS выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей DoS для экспорта.')


    def export_dos_rules(self, path):
        """Экспортируем список правил защиты DoS"""
        self.stepChanged.emit('BLUE|Экспорт правил защиты DoS из раздела "Политики безопасности/Правила защиты DoS".')

        err, data = self.utm.get_dos_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил защиты DoS.')
            self.error = 1
            return

        if data:
            if 'scenarios_rules' not in self.ngfw_data:
                if self.get_scenarios_rules():     # Заполняем self.ngfw_data['scenarios_rules']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил защиты DoS.')
                    return
            scenarios_rules = self.ngfw_data['scenarios_rules']

            err, result = self.utm.get_dos_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил защиты DoS.')
                self.error = 1
                return
            dos_profiles = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                id_list.append(item['id'])
                item.pop('guid', None)
                item.pop('active', None)
                item.pop('rownumber', None)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['dst_zones'] = self.get_zones_name(item['dst_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['services'] = self.get_services(item['services'], item)
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                if item['dos_profile']:
                    item['dos_profile'] = dos_profiles[item['dos_profile']]
                if item['scenario_rule_id']:
                    item['scenario_rule_id'] = scenarios_rules[item['scenario_rule_id']]
                if self.utm.float_version < 6:
                    item['position_layer'] = 'local'
                if item.pop('error', False):
                    error = 1
            self.add_tags_for_rules(data, id_list, object_type='dos_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_dos_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил защиты DoS.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила защиты DoS выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил защиты DoS для экспорта.')


    #---------------------------------- Глобальный портал  --------------------------------------
    def export_proxyportal_rules(self, path):
        """Экспортируем список URL-ресурсов веб-портала"""
        self.stepChanged.emit('BLUE|Экспорт списка ресурсов веб-портала из раздела "Глобальный портал/Веб-портал".')

        err, data = self.utm.get_proxyportal_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка ресурсов веб-портала.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя ресурса')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('rownumber', None)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                if self.utm.float_version < 7:
                    item['transparent_auth'] = False
                if self.utm.float_version < 6:
                    item['mapping_url_ssl_profile_id'] = 0
                    item['mapping_url_certificate_id'] = 0
                    item['position_layer'] = 'local'
                else:
                    if item['mapping_url_ssl_profile_id']:
                        item['mapping_url_ssl_profile_id'] = self.ngfw_data['ssl_profiles'][item['mapping_url_ssl_profile_id']]
                    if item['mapping_url_certificate_id']:
                        item['mapping_url_certificate_id'] = self.ngfw_data['certs'][item['mapping_url_certificate_id']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_web_portal.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список ресурсов веб-портала выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет ресурсов веб-портала для экспорта.')


    def export_reverseproxy_servers(self, path):
        """Экспортируем список серверов reverse-прокси"""
        self.stepChanged.emit('BLUE|Экспорт списка серверов reverse-прокси из раздела "Глобальный портал/Серверы reverse-прокси".')

        err, data = self.utm.get_reverseproxy_servers()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка серверов reverse-прокси.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя сервера')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_reverseproxy_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список серверов reverse-прокси выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов reverse-прокси для экспорта.')


    def export_reverseproxy_rules(self, path):
        """Экспортируем список правил reverse-прокси"""
        self.stepChanged.emit('BLUE|Экспорт правил reverse-прокси из раздела "Глобальный портал/Правила reverse-прокси".')

        err, data = self.utm.get_reverseproxy_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил reverse-прокси.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_nlists_list('useragent')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил reverse-прокси.')
                self.error = 1
                return
            useragent_list = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            err, err_msg, _, result = self.utm.get_loadbalancing_rules()
            if err:
                self.stepChanged.emit(f'RED|    {err_msg}\n    Произошла ошибка при экспорте правил reverse-прокси.')
                self.error = 1
                return
            reverse_loadbalancing = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            err, result = self.utm.get_reverseproxy_servers()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил reverse-прокси.')
                self.error = 1
                return
            reverse_servers = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            if self.utm.float_version >= 7.1:
                if 'client_cert_profiles' not in self.ngfw_data:
                    if self.get_client_certificate_profiles():     # Заполняем self.ngfw_data['client_cert_profiles']
                        self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил reverse-прокси.')
                        return
                client_cert_profiles = self.ngfw_data['client_cert_profiles']


            if self.utm.float_version < 7.3:
                waf_profiles = {}
                if self.utm.waf_license:  # Проверяем что есть лицензия на WAF
                    # Получаем список профилей WAF. Если err=2, значит лицензия истекла или нет прав на API.
                    err, result = self.utm.get_waf_profiles_list()
                    if err == 1:
                        self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил reverse-прокси.')
                        self.error = 1
                        return
                    elif err == 2:
                        self.stepChanged.emit(f'ORANGE|    {result}')
                        error = 1
                    else:
                        waf_profiles = {x['id']: x['name'] for x in result}

            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('guid', None)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                if self.utm.float_version < 6:
                    item.pop('from', None)
                    item.pop('to', None)
                    item['ssl_profile_id'] = 0
                    item['position_layer'] = 'local'
                else:
                    try:
                        if item['ssl_profile_id']:
                            item['ssl_profile_id'] = self.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Указан несуществующий профиль SSL.')
                        item['ssl_profile_id'] = 0
                        item['is_https'] = False
                        error = 1

                if item['certificate_id']:
                    try:
                        item['certificate_id'] = self.ngfw_data['certs'][item['certificate_id']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Указан несуществующий сертификат "{item["certificate_id"]}".')
                        item['certificate_id'] = 0
                        item['is_https'] = False
                        error = 1
                else:
                    item['certificate_id'] = 0

                try:
                    item['user_agents'] = [['list_id', useragent_list[x[1]]] for x in item['user_agents']]
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Указан несуществующий Useragent.')
                    item['user_agents'] = []
                    error = 1

                for x in item['servers']:
                    try:
                        x[1] = reverse_servers[x[1]] if x[0] == 'profile' else reverse_loadbalancing[x[1]]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Указан несуществующий сервер reverse-прокси или балансировщик.')
                        x = ['profile', 'Example reverse proxy server']
                        error = 1
                if self.utm.float_version < 7.1:
                    item['user_agents_negate'] = False
                    item['waf_profile_id'] = 0
                    item['client_certificate_profile_id'] = 0
                else:
                    item['client_certificate_profile_id'] = client_cert_profiles.get(item['client_certificate_profile_id'], 0)
                    if self.utm.float_version < 7.3:
                        try:
                            item['waf_profile_id'] = waf_profiles[item['waf_profile_id']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль WAF {err}.')
                            item['waf_profile_id'] = 0
                            error = 1
                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='reverseproxy_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_reverseproxy_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил reverse-прокси.')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Правила reverse-прокси выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил reverse-прокси для экспорта.')


    #_-------------------------------- Вышестоящие прокси ------------------------------------
    def export_upstream_proxies_servers(self, path):
        """Экспортируем список серверов вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        self.stepChanged.emit('BLUE|Экспорт списка серверов вышестоящих прокси из раздела "Вышестоящие прокси/Серверы".')

        err, data = self.utm.get_cascade_proxy_servers()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка серверов вышестоящих прокси.')
            self.error = 1
            return

        if data:
            self.ngfw_data['upstreamproxies_servers'] = {}
            for item in data:
                self.ngfw_data['upstreamproxies_servers'][item['id']] = item['name']
                item.pop('id', None)
                item.pop('active', None)
                item.pop('errorMessage', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_upstreamproxies_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список серверов вышестоящих прокси выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверов вышестоящих прокси для экспорта.')


    def export_upstream_proxies_profiles(self, path):
        """Экспортируем список профилей вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        self.stepChanged.emit('BLUE|Экспорт списка профилей вышестоящих прокси из раздела "Вышестоящие прокси/Профили".')

        err, data = self.utm.get_cascade_proxy_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка профилей вышестоящих прокси.')
            self.error = 1
            return

        if data:
            if 'upstreamproxies_servers' not in self.ngfw_data:
                if self.get_upstreamproxies_servers():  # Заполняем self.ngfw_data['upstreamproxies_servers']
                    self.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте списка профилей вышестоящих прокси.')
                    return
            proxies_servers = self.ngfw_data['upstreamproxies_servers']

            self.ngfw_data['upstreamproxies_profiles'] = {}
            for item in data:
                self.ngfw_data['upstreamproxies_profiles'][item['id']] = item['name']
                item.pop('id', None)
                item.pop('active', None)
                item.pop('error', None)
                item.pop('cc', None)
                try:
                    item['servers'] = [proxies_servers[x] for x in item['servers']]
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден сервер для профиля. Серверы не добавлены в профиль.')
                    item['servers'] = []

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_upstreamproxies_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список профилей вышестоящих прокси выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей вышестоящих прокси для экспорта.')


    def export_upstream_proxies_rules(self, path):
        """Экспортируем список правил вышестоящих прокси"""
        if self.utm.float_version < 7.4:
            return

        self.stepChanged.emit('BLUE|Экспорт списка правил вышестоящих прокси из раздела "Вышестоящие прокси/Правила".')

        err, data = self.utm.get_cascade_proxy_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка правил вышестоящих прокси.')
            self.error = 1
            return

        if data:
            error = 0
            if 'list_templates' not in self.ngfw_data:
                if self.get_templates_list():            # Заполняем self.ngfw_data['list_templates']
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил фильтрации контента.')
                    return
            templates_list = self.ngfw_data['list_templates']

            if 'upstreamproxies_pofiles' not in self.ngfw_data:
                if self.get_upstreamproxies_profiles():  # Заполняем self.ngfw_data['upstreamproxies_profiles']
                    self.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте списка правил вышестоящих прокси.')
                    return
            proxies_profiles = self.ngfw_data['upstreamproxies_profiles']

            for item in data:
                item.pop('id', None)
                item.pop('active', None)
                item.pop('cc', None)
                if item['proxy_profile']:
                    try:
                        item['proxy_profile'] = proxies_profiles[item['proxy_profile']]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль для правила. Установлено действие "Мимо прокси".')
                        item['proxy_profile'] = ''
                        item['action'] = 'direct'
                        item['fallback_action'] = 'direct'
                if 'fallback_block_page' in item:
                    item['fallback_block_page'] = templates_list.get(item['fallback_block_page'], -1)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])
                item['time_restrictions'] = self.get_time_restrictions_name(item['time_restrictions'], item)
                item['url_categories'] = self.get_url_categories_name(item['url_categories'], item)
                item['urls'] = self.get_urls_name(item['urls'], item)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['src_ips'] = self.get_ips_name(item['src_ips'], item)
                item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)

                if item.pop('error', False):
                    error = 1

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_upstreamproxies_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте. Список правил вышестоящих прокси выгружен в файл "{json_file}".')
                self.error = 1
            else:
                self.stepChanged.emit(f'GREEN|    Список правил вышестоящих прокси выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил вышестоящих прокси для экспорта.')


    #---------------------------------------- WAF --------------------------------------------
    def export_waf_custom_layers(self, path):
        """Экспортируем персональные WAF-слои. Для версии 7.1 и выше"""
        if self.utm.float_version >= 7.3 or not self.utm.waf_license:
            return

        self.stepChanged.emit('BLUE|Экспорт персональных слоёв WAF из раздела "WAF/Персональные WAF-слои".')

        err, data = self.utm.get_waf_custom_layers_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте персональных слоёв WAF.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_waf_custom_layers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Персональные WAF-слои выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет персональных WAF-слоёв для экспорта.')


    def export_waf_profiles_list(self, path):
        """Экспортируем профили WAF. Для версии 7.1 и выше"""
        if self.utm.float_version >= 7.3 or not self.utm.waf_license:
            return

        self.stepChanged.emit('BLUE|Экспорт профилей WAF из раздела "WAF/WAF-профили".')

        err, data = self.utm.get_waf_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей WAF.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_waf_technology_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return
            waf_technology = {x['id']: x['name'] for x in result}

            err, result = self.utm.get_waf_custom_layers_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return
            waf_custom_layers = {x['id']: x['name'] for x in result}

            err, result = self.utm.get_waf_system_layers_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return
            waf_system_layers = {x['id']: x['name'] for x in result}

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                for layer in item['layers']:
                    if layer['type'] == 'custom_layer':
                        layer['id'] = waf_custom_layers[layer['id']]
                    else:
                        layer['id'] = waf_system_layers[layer['id']]
                        layer['protection_technologies'] = [waf_technology[x] for x in layer['protection_technologies']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_waf_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили WAF выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей WAF для экспорта.')


    #------------------------------------ VPN ------------------------------------------
    def export_vpn_security_profiles(self, path):
        """Экспортируем список профилей безопасности VPN. Для версий 5, 6, 7.0"""
        self.stepChanged.emit('BLUE|Экспорт профилей безопасности VPN из раздела "VPN/Профили безопасности VPN".')

        err, data = self.utm.get_vpn_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей безопасности VPN.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]
                item.pop('id', None)
                item.pop('cc', None)
                if self.utm.float_version < 6:
                    item['peer_auth'] = 'psk'
                    item['ike_mode'] = 'main'
                    item['ike_version'] = 1
                    item['p2_security'] = item['security']
                    item['p2_key_lifesize'] = 4608000
                    item['p2_key_lifesize_enabled'] = False
                    item['p1_key_lifetime'] = 86400
                    item['p2_key_lifetime'] = 43200
                    item['dpd_interval'] = 60
                    item['dpd_max_failures'] = 5
                    item['dh_groups'] = ['DH_GROUP2_PRIME_1024', 'DH_GROUP14_PRIME_2048']

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_vpn_security_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили безопасности VPN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей безопасности VPN для экспорта.')


    def export_vpnclient_security_profiles(self, path):
        """Экспортируем клиентские профили безопасности VPN. Для версии 7.1 и выше"""
        self.stepChanged.emit('BLUE|Экспорт клиентских профилей безопасности VPN из раздела "VPN/Клиентские профили безопасности".')

        err, data = self.utm.get_vpn_client_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте клиентских профилей безопасности VPN.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['certificate_id'] = self.ngfw_data['certs'].get(item['certificate_id'], 0)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Клиентские профили безопасности VPN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет клиентских профилей безопасности VPN для экспорта.')


    def export_vpnserver_security_profiles(self, path):
        """Экспортируем серверные профили безопасности VPN. Для версии 7.1 и выше"""
        self.stepChanged.emit('BLUE|Экспорт серверных профилей безопасности VPN из раздела "VPN/Серверные профили безопасности".')

        err, data = self.utm.get_vpn_server_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте серверных профилей безопасности VPN.')
            self.error = 1
            return

        if data:
            if 'client_cert_profiles' not in self.ngfw_data:
                if self.get_client_certificate_profiles():     # Заполняем self.ngfw_data['client_cert_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте серверных профилей безопасности VPN.')
                    return
            client_cert_profiles = self.ngfw_data['client_cert_profiles']

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['certificate_id'] = self.ngfw_data['certs'].get(item['certificate_id'], 0)
                item['client_certificate_profile_id'] = client_cert_profiles.get(item['client_certificate_profile_id'], 0)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Серверные профили безопасности VPN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверных профилей безопасности VPN для экспорта.')


    def export_vpn_networks(self, path):
        """Экспортируем список сетей VPN"""
        self.stepChanged.emit('BLUE|Экспорт списка сетей VPN из раздела "VPN/Сети VPN".')

        err, data = self.utm.get_vpn_networks()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка сетей VPN.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя сети')[1]
                item.pop('id', None)
                item.pop('cc', None)
                for x in item['networks']:
                    if x[0] == 'list_id':
                        x[1] = self.ngfw_data['ip_lists'][x[1]]
                if self.utm.float_version < 7.1:
                    item['ep_tunnel_all_routes'] = False
                    item['ep_disable_lan_access'] = False
                    item['ep_routes_include'] = []
                    item['ep_routes_exclude'] = []
                else:
                    for x in item['ep_routes_include']:
                        if x[0] == 'list_id':
                            x[1] = self.ngfw_data['ip_lists'][x[1]]
                    for x in item['ep_routes_exclude']:
                        if x[0] == 'list_id':
                            x[1] = self.ngfw_data['ip_lists'][x[1]]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_vpn_networks.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список сетей VPN выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет сетей VPN для экспорта.')


    def export_vpn_client_rules(self, path):
        """Экспортируем список клиентских правил VPN"""
        self.stepChanged.emit('BLUE|Экспорт клиентских правил VPN из раздела "VPN/Клиентские правила".')

        err, data = self.utm.get_vpn_client_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте клиентских правил VPN.')
            self.error = 1
            return

        if data:
            if self.utm.float_version < 7.1:
                err, result = self.utm.get_vpn_security_profiles()
            else:
                err, result = self.utm.get_vpn_client_security_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте клиентских правил VPN.')
                self.error = 1
                return
            vpn_security_profiles = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('connection_time', None)
                item.pop('last_error', None)
                item.pop('status', None)
                item.pop('cc', None)
                item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
                if self.utm.float_version < 6:
                    item['protocol'] = 'l2tp'
                    item['subnet1'] = ''
                    item['subnet2'] = ''

            self.add_tags_for_rules(data, id_list, object_type='vpn_client_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_vpn_client_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Клиентские правила VPN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет клиентских правил VPN для экспорта.')


    def export_vpn_server_rules(self, path):
        """Экспортируем список серверных правил VPN"""
        self.stepChanged.emit('BLUE|Экспорт серверных правил VPN из раздела "VPN/Серверные правила".')

        err, data = self.utm.get_vpn_server_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте серверных правил VPN.')
            self.error = 1
            return

        if data:
            if self.utm.float_version < 7.1:
                err, result = self.utm.get_vpn_security_profiles()
            else:
                err, result = self.utm.get_vpn_server_security_profiles()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте серверных правил VPN.')
                self.error = 1
                return
            vpn_security_profiles = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            err, result = self.utm.get_vpn_networks()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте серверных правил VPN.')
                self.error = 1
                return
            vpn_networks = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            error = 0
            id_list = []
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                id_list.append(item['id'])
                item.pop('guid', None)
                item.pop('rownumber', None)
                item.pop('cc', None)
                item['src_zones'] = self.get_zones_name(item['src_zones'], item)
                item['source_ips'] = self.get_ips_name(item['source_ips'], item)
                if self.utm.float_version < 6:
                    item['dst_ips'] = []
                    item['position_layer'] = 'local'
                else:
                    item['dst_ips'] = self.get_ips_name(item['dst_ips'], item)
                item['users'] = self.get_names_users_and_groups(item['users'], item['name'])

                item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
                item['tunnel_id'] = vpn_networks.get(item['tunnel_id'], False)
                item['auth_profile_id'] = self.ngfw_data['auth_profiles'].get(item['auth_profile_id'], False)
                if self.utm.float_version >= 7.1:
                    item.pop('allowed_auth_methods', None)

                if item.pop('error', False):
                    error = 1

            self.add_tags_for_rules(data, id_list, object_type='vpn_server_rules')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_vpn_server_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)

            if error:
                self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте серверных правил VPN.')
            else:
                self.stepChanged.emit(f'GREEN|    Серверные правила VPN выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет серверных правил VPN для экспорта.')


    #------------------------------------ Библиотека ------------------------------------------
    def export_morphology_lists(self, path):
        """Экспортируем списки морфологии"""
        self.stepChanged.emit('BLUE|Экспорт списков морфологии из раздела "Библиотеки/Морфология".')

        err, data = self.utm.get_nlist_list('morphology')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списков морфологии.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                if self.utm.float_version < 6:
                    attributes = {}
                    for attr in item['attributes']:
                        if attr['name'] == 'threat_level':
                            attributes['threat_level'] = attr['value']
                        else:
                            attributes['threshold'] = attr['value']
                    item['attributes'] = attributes
                    try:
                        item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        item['last_update'] = ''
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                for content in item['content']:
                    content.pop('id', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_morphology_lists.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Списки морфологии выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет списков морфологии для экспорта.')


    def export_services_list(self, path):
        """Экспортируем список сервисов раздела библиотеки"""
        self.stepChanged.emit('BLUE|Экспорт списка сервисов из раздела "Библиотеки/Сервисы".')

        err, data = self.utm.get_services_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка сервисов.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id')
                item.pop('guid')
                item.pop('cc', None)
                item.pop('readonly', None)
                for value in item['protocols']:
                    if 'alg' not in value:
                        value['alg'] = ''
                    if self.utm.float_version < 6:
                        match value['port']:
                            case '110':
                                value['proto'] = 'pop3'
                                value['app_proto'] = 'pop3'
                            case '995':
                                value['proto'] = 'pop3s'
                                value['app_proto'] = 'pop3s'
                            case '25':
                                value['app_proto'] = 'smtp'
                            case '465':
                                value['app_proto'] = 'smtps'
                        if 'app_proto' not in value:
                            value['app_proto'] = ''

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_services_list.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список сервисов выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет сервисов для экспорта.')


    def export_services_groups(self, path):
        """Экспортируем группы сервисов раздела библиотеки. Только для версии 7 и выше"""
        self.stepChanged.emit('BLUE|Экспорт списка групп сервисов сервисов из раздела "Библиотеки/Группы сервисов".')
    
        err, data = self.utm.get_nlist_list('servicegroup')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте групп сервисов.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id')
                item.pop('guid')
                item.pop('editable')
                item.pop('enabled')
                item.pop('version')
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id')
                    content.pop('guid')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_services_groups_list.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы сервисов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп сервисов для экспорта.')


    def export_IP_lists(self, path):
        """Экспортируем списки IP-адресов и преобразует формат атрибутов списков к версии 7"""
        self.stepChanged.emit('BLUE|Экспорт списка IP-адресов из раздела "Библиотеки/IP-адреса".')

        err, data = self.utm.get_nlist_list('network')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списков IP-адресов.')
            self.error = 1
            return

        if data:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for item in data:
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                if self.utm.float_version < 6:
                    item['attributes'] = {'threat_level': x['value'] for x in item['attributes']}
                    try:
                        item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        item['last_update'] = ''
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id', None)
                    if 'list' in content:
                        content['list'] = content['value']
                        content.pop('value', None)
                        content.pop('readonly', None)
                        content.pop('description', None)

                json_file = os.path.join(path, f'{item["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(item, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Список IP-адресов "{item["name"]}" выгружен в файл "{json_file}".')

            self.stepChanged.emit('GREEN|    Экспорт списков IP-адресов завершён.')
        else:
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для экспорта.')


    def export_useragent_lists(self, path):
        """Экспортируем списки useragent и преобразует формат атрибутов списков к версии 7"""
        self.stepChanged.emit('BLUE|Экспорт списка "Useragent браузеров" из раздела "Библиотеки/Useragent браузеров".')

        err, data = self.utm.get_nlist_list('useragent')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка "Useragent браузеров".')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {}
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                for content in item['content']:
                    content.pop('id', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            json_file = os.path.join(path, 'config_useragents_list.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список "Useragent браузеров" выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет Useragent браузеров для экспорта.')


    def export_mime_lists(self, path):
        """Экспортируем списки Типов контента и преобразует формат атрибутов списков к версии 7"""
        self.stepChanged.emit('BLUE|Экспорт списка "Типы контента" из раздела "Библиотеки/Типы контента".')

        err, data = self.utm.get_nlist_list('mime')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка "Типы контента".')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {}
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_mime_types.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список "Типы контента" выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет типов контента для экспорта.')


    def export_url_lists(self, path):
        """Экспортируем списки URL и преобразует формат атрибутов списков к версии 6"""
        self.stepChanged.emit('BLUE|Экспорт списков URL из раздела "Библиотеки/Списки URL".')

        err, data = self.utm.get_nlist_list('url')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списков URL.')
            self.error = 1
            return

        if data:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {'threat_level': x['value'] for x in item['attributes']}
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id', None)

                json_file = os.path.join(path, f'{item["name"].translate(self.trans_filename)}.json')
                with open(json_file, 'w') as fh:
                    json.dump(item, fh, indent=4, ensure_ascii=False)
                self.stepChanged.emit(f'BLACK|    Список URL "{item["name"]}" выгружен в файл "{json_file}".')

            self.stepChanged.emit(f'GREEN|    Экспорт списков URL завершён.')
        else:
            self.stepChanged.emit('GRAY|    Нет списков URL для экспорта.')


    def export_time_restricted_lists(self, path):
        """Экспортируем содержимое календарей и преобразует формат атрибутов списков к версии 7"""
        self.stepChanged.emit('BLUE|Экспорт списка "Календари" из раздела "Библиотеки/Календари".')

        err, data = self.utm.get_nlist_list('timerestrictiongroup')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка "Календари".')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {}
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id', None)
                    if self.utm.float_version < 6:
                        content.pop('fixed_date_from', None)
                        content.pop('fixed_date_to', None)
                        content.pop('fixed_date', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_calendars.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список "Календари" выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет календарей для экспорта.')


    def export_shaper_list(self, path):
        """Экспортируем список Полосы пропускания"""
        self.stepChanged.emit('BLUE|Экспорт списка "Полосы пропускания" из раздела "Библиотеки/Полосы пропускания".')

        err, data = self.utm.get_shaper_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка "Полосы пропускания".')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_shaper_list.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список "Полосы пропускания" выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет полос пропускания для экспорта.')


    def export_scada_profiles(self, path):
        """Экспортируем список профилей АСУ ТП"""
        self.stepChanged.emit('BLUE|Экспорт списка профилей АСУ ТП из раздела "Библиотеки/Профили АСУ ТП".')

        err, data = self.utm.get_scada_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка "Профили АСУ ТП".')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_scada_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список "Профили АСУ ТП" выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей АСУ ТП для экспорта.')


    def export_templates_list(self, path):
        """
        Экспортируем список шаблонов страниц.
        Выгружает файл HTML только для изменённых страниц шаблонов.
        """
        self.stepChanged.emit('BLUE|Экспорт шаблонов страниц из раздела "Библиотеки/Шаблоны страниц".')

        err, data = self.utm.get_templates_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте шаблонов страниц.')
            self.error = 1
            return

        if data:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return

            for item in data:
                err, html_data = self.utm.get_template_data(item['type'], item['id'])
                if html_data:
                    with open(os.path.join(path, f'{item["name"]}.html'), "w") as fh:
                        fh.write(html_data)
                    self.stepChanged.emit(f'BLACK|    Страница HTML для шаблона "{item["name"]}" выгружена в файл "{item["name"]}.html".')

                item.pop('id', None)
                item.pop('last_update', None)
                item.pop('cc', None)

            json_file = os.path.join(path, 'config_templates_list.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Шаблоны страниц выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет шаблонов страниц для экспорта.')


    def export_url_categories(self, path):
        """Экспортируем категории URL"""
        self.stepChanged.emit('BLUE|Экспорт категорий URL из раздела "Библиотеки/Категории URL".')

        err, data = self.utm.get_nlist_list('urlcategorygroup')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте категорий URL.')
            self.error = 1
            return

        if data:
            revert_urlcategorygroup = {v: k for k, v in default_urlcategorygroup.items()}
            for item in data:
                item['name'] = default_urlcategorygroup.get(item['name'], self.get_transformed_name(item['name'], descr='Имя категории')[1])
                item.pop('id', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                if self.utm.float_version < 6:
                    item['guid'] = revert_urlcategorygroup.get(item['name'], item['guid'])
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {}
                    item['list_type_update'] = 'static'
                    item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    if self.utm.float_version < 6:
                        content['category_id'] = content.pop('value')
                        content['name'] = self.ngfw_data['url_categories'][int(content['category_id'])]
                    content.pop('id', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_url_categories.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Категории URL выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет категорий URL для экспорта.')


    def export_custom_url_category(self, path):
        """Экспортируем изменённые категории URL"""
        self.stepChanged.emit('BLUE|Экспорт изменённых категорий URL из раздела "Библиотеки/Изменённые категории URL".')

        err, data = self.utm.get_custom_url_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте изменённых категорий URL.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['categories'] = [self.ngfw_data['url_categories'][x] for x in item['categories']]
                item['default_categories'] = [self.ngfw_data['url_categories'][x] for x in item['default_categories']]
                item['change_date'] = dt.strptime(item['change_date'], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'custom_url_categories.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Изменённые категории URL выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет изменённых категорий URL для экспорта.')


    def export_applications(self, path):
        """Экспортируем список пользовательских приложений для версии 7.1 и выше."""
        self.stepChanged.emit('BLUE|Экспорт пользовательских приложений из раздела "Библиотеки/Приложения".')

        err, data = self.utm.get_version71_apps(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|{data}\n    Произошла ошибка при экспорте пользовательских приложений.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('attributes', None)
                item.pop('cc', None)
                item['l7categories'] = [self.ngfw_data['l7_categories'][x[1]] for x in item['l7categories']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_applications.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Пользовательские приложения выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет пользовательских приложений для экспорта.')


    def export_app_profiles(self, path):
        """Экспортируем профили приложений. Только для версии 7.1 и выше."""
        self.stepChanged.emit('BLUE|Экспорт профилей приложений из раздела "Библиотеки/Профили приложений".')

        err, data = self.utm.get_l7_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей приложений.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                for app in item['overrides']:
                    app['id'] = self.ngfw_data['l7_apps'][app['id']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_app_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили приложений выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей приложений для экспорта.')


    def export_application_groups(self, path):
        """Экспортируем группы приложений."""
        self.stepChanged.emit('BLUE|Экспорт групп приложений из раздела "Библиотеки/Группы приложений".')

        err, data = self.utm.get_nlist_list('applicationgroup')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте групп приложений.')
            self.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('version', None)
            item.pop('global', None)
            item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
            if self.utm.float_version < 6:
                item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                item['attributes'] = {}
                item['list_type_update'] = 'static'
                item['schedule'] = 'disabled'
            else:
                item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
            for content in item['content']:
                content.pop('id', None)
                content.pop('item_id', None)
                content.pop('attributes', None)
                content.pop('cc', None)
                content.pop('description', None)
                if self.utm.float_version < 6:
                    content['name'] = self.ngfw_data['l7_apps'][content['value']]
                elif self.utm.float_version < 7.1:
                    content['category'] = [self.ngfw_data['l7_categories'][x] for x in content['category']]
                else:
                    try:
                        content['l7categories'] = [self.ngfw_data['l7_categories'][x[1]] for x in content['l7categories']]
                    except KeyError:
                        pass    # Ошибка бывает если ранее было не корректно добавлено приложение через API в версии 7.1.

        if data:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_application_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы приложений выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп приложений для экспорта.')


    def export_email_groups(self, path):
        """Экспортируем группы почтовых адресов."""
        self.stepChanged.emit('BLUE|Экспорт групп почтовых адресов из раздела "Библиотеки/Почтовые адреса".')

        err, data = self.utm.get_nlist_list('emailgroup')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте групп почтовых адресов.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {}
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_email_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы почтовых адресов выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп почтовых адресов для экспорта.')


    def export_phone_groups(self, path):
        """Экспортируем группы телефонных номеров."""
        self.stepChanged.emit('BLUE|Экспорт групп телефонных номеров из раздела "Библиотеки/Номера телефонов".')

        err, data = self.utm.get_nlist_list('phonegroup')
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте групп телефонных номеров.')
            self.error = 1
            return

        if data:
            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item['attributes'] = {}
                    if item['url']:
                        item['list_type_update'] = 'dynamic'
                        item['schedule'] = '0 0-23/1 * * *'
                        item['attributes']['readonly_data'] = True
                    else:
                        item['list_type_update'] = 'static'
                        item['schedule'] = 'disabled'
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id')

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_phone_groups.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Группы телефонных номеров выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет групп телефонных номеров для экспорта.')


    def export_custom_idps_signatures(self, path):
        """Экспортируем пользовательские сигнатуры СОВ для версии 7.1 и выше."""
        self.stepChanged.emit('BLUE|Экспорт пользовательских сигнатур СОВ из раздела "Библиотеки/Сигнатуры СОВ".')

        err, data = self.utm.get_idps_signatures_list(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте пользовательских сигнатур СОВ.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('attributes', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'custom_idps_signatures.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Пользовательские сигнатуры СОВ выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет пользовательских сигнатур СОВ для экспорта.')


    def export_idps_profiles(self, path):
        """Экспортируем список профилей СОВ"""
        self.stepChanged.emit('BLUE|Экспорт профилей СОВ из раздела "Библиотеки/Профили СОВ".')
        data = []

        if self.utm.float_version < 7.1:
            err, data = self.utm.get_nlist_list('ipspolicy')
            if err:
                self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей СОВ.')
                self.error = 1
                return

            for item in data:
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя списка')[1]
                if self.utm.float_version < 6:
                    item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                    item.pop('attributes', None)
                else:
                    item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
                for content in item['content']:
                    content.pop('id', None)
                    content.pop('l10n', None)
                    content.pop('bugtraq', None)
                    content.pop('nessus', None)
                    if 'threat_level' in content.keys():
                        content['threat'] = content.pop('threat_level')
        else:
            err, data = self.utm.get_idps_profiles_list()
            if err:
                self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей СОВ.')
                self.error = 1
                return

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                overrides = []
                for app in item['overrides']:
                    err, result = self.utm.get_idps_signature_fetch(app['id'])
                    if err:
                        self.stepChanged.emit(f'RED|    {result}\n    Не переопределена сигнатура "{app}" для профиля СОВ "{item["name"]}".')
                        error = 1
                    else:
                        app['signature_id'] = result['signature_id']
                        app['msg'] = result['msg']
                        overrides.append(app)
                item['overrides'] = overrides

        if data:
            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_idps_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список профилей СОВ выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей СОВ для экспорта.')


    def export_notification_profiles(self, path):
        """Экспортируем список профилей оповещения"""
        self.stepChanged.emit('BLUE|Экспорт профилей оповещений из раздела "Библиотеки/Профили оповещений".')

        err, data = self.utm.get_notification_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей оповещений.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_notification_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили оповещений выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей оповещений для экспорта.')


    def export_netflow_profiles(self, path):
        """Экспортируем список профилей netflow"""
        self.stepChanged.emit('BLUE|Экспорт профилей netflow из раздела "Библиотеки/Профили netflow".')

        err, data = self.utm.get_netflow_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей netflow.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_netflow_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили netflow выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей netflow для экспорта.')


    def export_ssl_profiles(self, path):
        """Экспортируем список профилей SSL"""
        self.stepChanged.emit('BLUE|Экспорт профилей SSL из раздела "Библиотеки/Профили SSL".')

        err, data = self.utm.get_ssl_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей SSL.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_ssl_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили SSL выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей SSL для экспорта.')


    def export_lldp_profiles(self, path):
        """Экспортируем список профилей LLDP"""
        self.stepChanged.emit('BLUE|Экспорт профилей LLDP из раздела "Библиотеки/Профили LLDP".')

        err, data = self.utm.get_lldp_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей LLDP.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                aelf.error = 1
                return
            json_file = os.path.join(path, 'config_lldp_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили LLDP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей LLDP для экспорта.')


    def export_ssl_forward_profiles(self, path):
        """Экспортируем профили пересылки SSL"""
        self.stepChanged.emit('BLUE|Экспорт профилей пересылки SSL из раздела "Библиотеки/Профили пересылки SSL".')

        err, data = self.utm.get_ssl_forward_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей пересылки SSL.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['name'] = self.get_transformed_name(item['name'], descr='Имя профиля')[1]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили пересылки SSL выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей пересылки SSL для экспорта.')


    def export_hip_objects(self, path):
        """Экспортируем HIP объекты"""
        self.stepChanged.emit('BLUE|Экспорт HIP объектов из раздела "Библиотеки/HIP объекты".')

        err, data = self.utm.get_hip_objects_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте HIP объектов.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_hip_objects.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    HIP объекты выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет HIP объектов для экспорта.')


    def export_hip_profiles(self, path):
        """Экспортируем HIP профили"""
        self.stepChanged.emit('BLUE|Экспорт HIP профилей из раздела "Библиотеки/HIP профили".')

        err, data = self.utm.get_hip_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте HIP профилей.')
            self.error = 1
            return

        if data:
            err, result = self.utm.get_hip_objects_list()
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте HIP профилей.')
                self.error = 1
                return
            hip_objects = {x['id']: x['name'] for x in result}

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                for obj in item['hip_objects']:
                    obj['id'] = hip_objects[obj['id']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_hip_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    HIP профили выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет HIP профилей для экспорта.')


    def export_bfd_profiles(self, path):
        """Экспортируем профили BFD"""
        self.stepChanged.emit('BLUE|Экспорт профилей BFD из раздела "Библиотеки/Профили BFD".')

        err, data = self.utm.get_bfd_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей BFD.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_bfd_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили BFD выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей BFD для экспорта.')


    def export_useridagent_syslog_filters(self, path):
        """Экспортируем syslog фильтры UserID агента"""
        self.stepChanged.emit('BLUE|Экспорт syslog фильтров UserID агента из раздела "Библиотеки/Syslog фильтры UserID агента".')

        err, data = self.utm.get_useridagent_filters_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте syslog фильтров UserID агента.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Syslog фильтры UserID агента выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет syslog фильтров UserID агента для экспорта.')


    def export_tags(self, path):
        """Экспортируем список тэгов"""
        if self.utm.float_version < 7.3:
            return

        self.stepChanged.emit('BLUE|Экспорт тэгов из раздела "Библиотеки/Тэги".')

        err, data = self.utm.get_tags_list()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка тэгов.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_tags.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Тэги выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет тэгов для экспорта.')


    #-------------------------------------- Оповещения ----------------------------------------
    def export_snmp_rules(self, path):
        """Экспортируем список правил SNMP"""
        self.stepChanged.emit('BLUE|Экспорт списка правил SNMP из раздела "Диагностика и мониторинг/Оповещения/SNMP".')

        err, data = self.utm.get_snmp_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте списка правил SNMP.')
            self.error = 1
            return

        if data:
            if self.utm.float_version >= 7.1:
                err, result = self.utm.get_snmp_security_profiles()
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте списка правил SNMP.')
                    self.error = 1
                    return
                snmp_security_profiles = {x['id']: x['name'] for x in result}

            for item in data:
                item['name'] = self.get_transformed_name(item['name'], descr='Имя правила')[1]
                item.pop('id', None)
                item.pop('cc', None)
                if self.utm.float_version >= 7.1:
                    item['snmp_security_profile'] = snmp_security_profiles.get(item['snmp_security_profile'], 0)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_snmp_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Список правил SNMP выгружен в файл "{json_file}".')
        else:
            self.stepChanged.emit(f'GRAY|    Нет правил SNMP для экспорта.')


    def export_notification_alert_rules(self, path):
        """Экспортируем список правил оповещений"""
        self.stepChanged.emit('BLUE|Экспорт правил оповещений из раздела "Диагностика и мониторинг/Оповещения/Правила оповещений".')

        err, data = self.utm.get_notification_alert_rules()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте правил оповещений.')
            self.error = 1
            return

        if data:
            if 'notification_profiles' not in self.ngfw_data:
                if self.get_notification_profiles():    # Заполняем self.ngfw_data['notification_profiles']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка MFA профилей.')
                    return
            list_notifications = self.ngfw_data['notification_profiles']

            err, result = self.utm.get_nlist_list('emailgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил оповещений.')
                self.error = 1
                return
            email_group = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            err, result = self.utm.get_nlist_list('phonegroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при экспорте правил оповещений.')
                self.error = 1
                return
            phone_group = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}

            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item['notification_profile_id'] = list_notifications[item['notification_profile_id']]
                item['emails'] = [[x[0], email_group[x[1]]] for x in item['emails']]
                item['phones'] = [[x[0], phone_group[x[1]]] for x in item['phones']]

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_alert_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Правила оповещений выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет правил оповещений для экспорта.')


    def export_snmp_security_profiles(self, path):
        """Экспортируем профили безопасности SNMP. Для версии 7.1 и выше"""
        self.stepChanged.emit('BLUE|Экспорт профилей безопасности SNMP из раздела "Диагностика и мониторинг/Оповещения/Профили безопасности SNMP".')

        err, data = self.utm.get_snmp_security_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте профилей безопасности SNMP.')
            self.error = 1
            return

        if data:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                item.pop('readonly', None)

            err, msg = self.create_dir(path)
            if err:
                self.stepChanged.emit(f'RED|    {msg}')
                self.error = 1
                return
            json_file = os.path.join(path, 'config_snmp_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            self.stepChanged.emit(f'GREEN|    Профили безопасности SNMP выгружены в файл "{json_file}".')
        else:
            self.stepChanged.emit('GRAY|    Нет профилей безопасности SNMP для экспорта.')


    def export_snmp_settings(self, path):
        """Экспортируем параметры SNMP. Для версии 7.1 и выше"""
        self.stepChanged.emit('BLUE|Экспорт параметров SNMP из раздела "Диагностика и мониторинг/Оповещения/Параметры SNMP".')
        error = 0

        err, msg = self.create_dir(path)
        if err:
            self.stepChanged.emit(f'RED|    {msg}\n    Произошла ошибка при экспорте параметров SNMP.')
            self.error = 1
            return

        error += self.export_snmp_engine(path)
        error += self.export_snmp_sys_name(path)
        error += self.export_snmp_sys_location(path)
        error += self.export_snmp_sys_description(path)

        if error:
            self.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте параметров SNMP.')
            self.error = 1
        else:
            self.stepChanged.emit(f'GREEN|    Параметры SNMP выгружены в каталог "{path}".')


    def export_snmp_engine(self, path):
        err, data = self.utm.get_snmp_engine()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте SNMP Engine ID.')
            return 1

        json_file = os.path.join(path, 'config_snmp_engine.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    SNMP Engine ID выгружено в файл "{json_file}".')
        return 0


    def export_snmp_sys_name(self, path):
        err, data = self.utm.get_snmp_sysname()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте значения SNMP SysName.')
            return 1

        json_file = os.path.join(path, 'config_snmp_sysname.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    Значение SNMP SysName выгружено в файл "{json_file}".')
        return 0


    def export_snmp_sys_location(self, path):
        err, data = self.utm.get_snmp_syslocation()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте значения SNMP SysLocation.')
            return 1

        json_file = os.path.join(path, 'config_snmp_syslocation.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    Значение SNMP SysLocation выгружено в файл "{json_file}".')
        return 0


    def export_snmp_sys_description(self, path):
        err, data = self.utm.get_snmp_sysdescription()
        if err:
            self.stepChanged.emit(f'RED|    {data}\n    Произошла ошибка при экспорте значения SNMP SysDescription.')
            return 1

        json_file = os.path.join(path, 'config_snmp_sysdescription.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        self.stepChanged.emit(f'BLACK|    Значение SNMP SysDescription выгружено в файл "{json_file}".')
        return 0


    def pass_function(self, path):
        """Функция заглушка"""
        self.stepChanged.emit(f'GRAY|Экспорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')


    ###################################### Служебные функции ##########################################
    def get_ips_name(self, rule_ips, rule):
        """Получаем имена списков IP-адресов, URL-листов и GeoIP. Если списки не существует на NGFW, то они пропускаются."""
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
                    new_rule_ips.append(['urllist_id', self.ngfw_data['url_lists'][ips[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список "{ips[0]}".')
                rule['error'] = True
        return new_rule_ips


    def get_zones_name(self, zones, rule):
        """Получаем имена зон. Если зона не существует на NGFW, то она пропускается."""
        new_zones = []
        for zone_id in zones:
            try:
                new_zones.append(self.ngfw_data['zones'][zone_id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена зона c ID: {zone_id}.')
                rule['error'] = True
        return new_zones


    def get_urls_name(self, urls, rule):
        """Получаем имена списков URL. Если список не существует на NGFW, то он пропускается."""
        new_urls = []
        for url_id in urls:
            try:
                new_urls.append(self.ngfw_data['url_lists'][url_id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список URL c ID: {url_id}.')
                rule['error'] = True
        return new_urls


    def get_url_categories_name(self, url_categories, rule):
        """Получаем имена категорий URL и групп категорий URL. Если список не существует на NGFW, то он пропускается."""
        new_urls = []
        for arr in url_categories:
            try:
                if arr[0] == 'list_id':
                    new_urls.append(['list_id', self.ngfw_data['url_categorygroups'][arr[1]]])
                elif arr[0] == 'category_id':
                    new_urls.append(['category_id', self.ngfw_data['url_categories'][arr[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория URL {arr}.')
                rule['error'] = True
        return new_urls


    def get_time_restrictions_name(self, times, rule):
        """Получаем имена календарей. Если не существуют на NGFW, то пропускаются."""
        new_times = []
        for cal_id in times:
            try:
                new_times.append(self.ngfw_data['calendars'][cal_id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден календарь c ID: {cal_id}.')
                rule['error'] = True
        return new_times


    def get_names_users_and_groups(self, users, rule_name):
        """
        Получаем имена групп и пользователей по их GUID.
        Заменяет GUID локальных/доменных пользователей и групп на имена.
        """
        new_users = []
        for item in users:
            match item[0]:
                case 'special':
                    new_users.append(item)
                case 'user':
                    try:
                        user_name = self.ngfw_data['local_users'][item[1]]
                    except KeyError:
                        err, user_name = self.utm.get_ldap_user_name(item[1])
                        if err:
                            self.stepChanged.emit(f'bRED|    {user_name}  [Правило "{rule_name}"]')
                        elif not user_name:
                            self.stepChanged.emit(f'NOTE|    Warning: [Правило "{rule_name}"] Нет LDAP-коннектора для домена! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                        else:
                            new_users.append(['user', user_name])
                    else:
                        new_users.append(['user', user_name])
                case 'group':
                    try:
                        group_name = self.ngfw_data['local_groups'][item[1]]
                    except KeyError:
                        err, group_name = self.utm.get_ldap_group_name(item[1])
                        if err:
                            self.stepChanged.emit(f'bRED|    {group_name}  [Правило "{rule_name}"]')
                        elif not group_name:
                            self.stepChanged.emit(f'NOTE|    Warning: [Правило "{rule_name}"] Нет LDAP-коннектора для домена "{item[1].split(":")[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                        else:
                            new_users.append(['group', group_name])
                    else:
                        new_users.append(['group', group_name])
        return new_users


    def get_services(self, service_list, rule):
        """Получаем имена сервисов по их ID. Если сервис не найден, то он пропускается."""
        new_service_list = []
        if self.utm.float_version < 7:
            for item in service_list:
                try:
                    new_service_list.append(['service', self.ngfw_data['services'][item]])
                except TypeError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не корректное значение в поле "services" - {err}.')
                    rule['error'] = True
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден сервис "{item}".')
                    rule['error'] = True
        else:
            for item in service_list:
                try:
                    new_service_list.append(['service', self.ngfw_data['services'][item[1]]] if item[0] == 'service' else ['list_id', self.ngfw_data['service_groups'][item[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа сервисов "{item}".')
                    rule['error'] = True
        return new_service_list


    def get_apps(self, array_apps, rule):
        """Определяем имя приложения или группы приложений по ID."""
        new_app_list = []
        for app in array_apps:
            if app[0] == 'ro_group':
                if app[1] == 0:
                    new_app_list.append(['ro_group', 'All'])
                else:
                    try:
                        new_app_list.append(['ro_group', self.ngfw_data['l7_categories'][app[1]]])
                    except KeyError as err:
                        message = '    Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.'
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория l7 "{app}".\n{message}')
                        rule['error'] = True
            elif app[0] == 'group':
                try:
                    new_app_list.append(['group', self.ngfw_data['application_groups'][app[1]]])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа приложений l7 №{err}.')
                    rule['error'] = True
            elif app[0] == 'app':
                try:
                    new_app_list.append(['app', self.ngfw_data['l7_apps'][app[1]]])
                except KeyError as err:
                    message = '    Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.'
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдено приложение №{err}.\n{message}')
                    rule['error'] = True
        return new_app_list


    def get_scenarios_rules(self):
        """Устанавливаем значение  self.ngfw_data['scenarios_rules']"""
        err, result = self.utm.get_scenarios_rules()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['scenarios_rules'] = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}
        return 0


    def get_client_certificate_profiles(self):
        """
        Получаем список профилей пользовательских сертификатов и
        устанавливаем значение self.ngfw_data['client_cert_profiles']
        """
        if self.utm.float_version < 7.1:
            return 0
        err, result = self.utm.get_client_certificate_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['client_cert_profiles'] = {x['id']: x['name'] for x in result}
        return 0


    def get_templates_list(self):
        """Получаем список шаблонов страниц и устанавливаем значение self.ngfw_data['list_templates']"""
        err, result = self.utm.get_templates_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['list_templates'] = {x['id']: x['name'] for x in result}
        return 0


    def get_notification_profiles(self):
        """Получаем список профилей оповещения и устанавливаем значение self.ngfw_data['notification_profiles']"""
        err, result = self.utm.get_notification_profiles_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['notification_profiles'] = {x['id']: self.get_transformed_name(x['name'], mode=0)[1] for x in result}
        return 0


    def get_upstreamproxies_servers(self):
        """Получаем список серверов вышестоящих прокси и устанавливаем значение self.ngfw_data['upstreamproxies_servers']"""
        err, result = self.utm.get_cascade_proxy_servers()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['upstreamproxies_servers'] = {x['id']: x['name'] for x in result}
        return 0


    def get_upstreamproxies_profiles(self):
        """Получаем список профилей вышестоящих прокси и устанавливаем значение self.ngfw_data['upstreamproxies_profiles']"""
        err, result = self.utm.get_cascade_proxy_profiles()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.ngfw_data['upstreamproxies_profiles'] = {x['id']: x['name'] for x in result}
        return 0


    def translate_iface_name(self, path, data):
        """Преобразуем имена интерфейсов для версии 5 (eth меняется на port, так же меняются имена vlan)"""
        if self.utm.float_version < 6:
            iface_name = {x['name']: x['name'].replace('eth', 'port', 1) if x['name'].startswith('eth') else x['name'].replace('rename', 'port', 1) for x in data}
            ports_num = max([int(x[4:5]) if x.startswith('port') else 0 for x in iface_name.values()])
            for key in sorted(iface_name.keys()):
                if key.startswith('slot'):
                    try:
                        name, vlan = iface_name[key].split('.')
                    except ValueError:
                        ports_num += 1
                        iface_name[key] = f'port{ports_num}'
                    else:
                        iface_name[key] = f'port{ports_num}.{vlan}'
            json_file = os.path.join(path, 'iface_translate.json')
            with open(json_file, 'w') as fh:
                json.dump(iface_name, fh, indent=4, ensure_ascii=False)
        else:
            iface_name = {x['name']: x['name'] for x in data}
        return iface_name


    def add_tags_for_rules(self, data, list_ids, object_type=None):
        if self.utm.float_version >= 7.3 and self.utm.product != 'dcfw':
            err, result = self.utm.get_tags_by_objects(list_ids, object_type)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return
            for item in data:
                if object_type == 'interfaces':
                    item_id = item.pop('full_id', '')
                else:
                    item_id = str(item.pop('id', ''))
                if item_id in result:
                    item['tags'] = [self.ngfw_data['tags'][x] for x in result[item_id]]


