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
# Класс импорта разделов конфигурации в шаблон NGFW UserGate Management Center версии 7 и выше.
# Версия 3.18   17.10.2025  (только для ug_ngfw_converter)
#

import os, sys, json
import copy
from PyQt6.QtCore import QThread, pyqtSignal
from common_classes import ReadWriteBinFile, MyMixedService, BaseObject, BaseAppObject


class ImportMcNgfwSelectedPoints(QThread, ReadWriteBinFile, MyMixedService):
    """Импортируем разделы конфигурации в шаблон МС"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm, config_path, template_id, templates, arguments, node_name, all_points=None, selected_path=None, selected_points=None):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.all_points = all_points
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.template_id = template_id
        self.templates = templates      # Список шаблонов {template_id: template_name}
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']

        self.waf_custom_layers = {}
        self.users_signatures = {}
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
            'SCADAProfiles': self.pass_function, # import_scada_profiles
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
            'Zones': self.import_zones,
            'Interfaces': self.import_interfaces,
            'Gateways': self.import_gateways,
            'DNS': self.import_dns_config,
            'DHCP': self.import_dhcp_subnets,
            'VRF': self.import_vrf,
            'WCCP': self.import_wccp_rules,
            'Certificates': self.import_certificates,
            'UserCertificateProfiles': self.import_client_certificate_profiles,
            'MFAProfiles': self.import_2fa_profiles,
            'AuthServers': self.import_auth_servers,
            'AuthProfiles': self.import_auth_profiles,
            'GeneralSettings': self.import_general_settings,
            'DeviceManagement': self.pass_function,
            'Administrators': self.import_administrators,
            'Groups': self.import_local_groups,
            'Users': self.import_local_users,
            'CaptiveProfiles': self.import_captive_profiles,
            'CaptivePortal': self.import_captive_portal_rules,
            'TerminalServers': self.import_terminal_servers,
            'UserIDagent': self.import_userid_agent,
            'BYODPolicies': self.pass_function, # import_byod_policy,
            'BYODDevices': self.pass_function,
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
            'IntrusionPrevention': self.pass_function, # import_idps_rules,
            'MailSecurity': self.import_mailsecurity,
            'ICAPRules': self.import_icap_rules,
            'DoSProfiles': self.import_dos_profiles,
            'DoSRules': self.import_dos_rules,
            'SCADARules': self.pass_function, # import_scada_rules,
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
            'SecurityProfiles': self.pass_function, # import_vpn_security_profiles,
            'VPNNetworks': self.import_vpn_networks,
            'ServerRules': self.import_vpn_server_rules,
            'ClientRules': self.import_vpn_client_rules,
            'AlertRules': self.import_notification_alert_rules,
            'SNMPSecurityProfiles': self.import_snmp_security_profiles,
            'SNMPParameters': self.import_snmp_settings,
            'SNMP': self.import_snmp_rules,
        }


    def run(self):
        """Импортируем разделы конфигурации"""
        # Читаем бинарный файл библиотечных данных.
        err, self.mc_data = self.read_bin_file()
        if err:
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось прочитать служебные данные.')
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
#                else:
#                    self.error = 1
#                    self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')

        # Сохраняем бинарный файл библиотечных данных после изменений во время работы.
        if self.write_bin_file(self.mc_data):
            self.stepChanged.emit('iRED|Импорт конфигурации в шаблон Management Center прерван! Не удалось записать служебные данные.')
            return

        if self.error:
            self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Импорт конфигурации завершён.\n')


    #--------------------------------------- Библиотека -------------------------------------------------
    def import_morphology_lists(self, path):
        """Импортируем списки морфологии"""
        json_file = os.path.join(path, 'config_morphology_lists.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
        error = 0

        if not self.mc_data['morphology']:
            if self.get_morphology_list():        # Заполняем self.mc_data['morphology']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
                return
        morphology = self.mc_data['morphology']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in morphology:
                if self.template_id == morphology[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список морфологии "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_nlist(self.template_id, morphology[item['name']].id, item)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result}  [Список морфологии "{item["name"]}"]')
                        error = 1
                        continue
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}')
                    else:
                        self.stepChanged.emit(f'uGRAY|       Список морфологии "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список морфологии "{item["name"]}" уже существует в шаблоне "{morphology[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Список морфологии "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    morphology[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    for value in content:
                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, morphology[item['name']].id, value)
                        if err2 == 3:
                            self.stepChanged.emit(f'GRAY|       {result2}')
                        elif err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Список морфологии "{item["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Список морфологии "{item["name"]}" не найден в шаблоне "{morphology[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Добавлено "{value["value"]}".')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он обновляется удалённо.')

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

        services = self.mc_data['services']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервиса')
            if item['name'] in services:
                if self.template_id == services[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сервис "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сервис "{item["name"]}" уже существует в шаблоне "{services[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_service(self.template_id, item)
                if err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                elif err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Сервис "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    services[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" импортирован.')
            self.msleep(3)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сервисов завершён')


    def import_services_groups(self, path):
        """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
        json_file = os.path.join(path, 'config_services_groups_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')
        out_message = 'GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
        error = 0

        servicegroups = self.mc_data['service_groups']
    
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in servicegroups:
                if self.template_id == servicegroups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_nlist(self.template_id, servicegroups[item['name']].id, item)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result} [Группа сервисов "{item["name"]}"]')
                        error = 1
                        continue
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}.')
                    else:
                        self.stepChanged.emit(f'uGRAY|       Группа сервисов "{item["name"]}" обновлена.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа сервисов "{item["name"]}" уже существует в шаблоне "{servicegroups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}.')
                else:
                    servicegroups[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for service in content:
                        try:
                            tmp = self.mc_data['services'][service['name']]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|       Error: [Группа сервисов "{item["name"]}"] Не найден сервис {err}. Загрузите сервисы в шаблон и повторите попытку.')
                            error = 1
                            continue
                        if tmp.template_id == self.template_id:
                            service['value'] = tmp.id
                        else:
                            self.stepChanged.emit(f'RED|       Error: [Группа сервисов "{item["name"]}"] Сервис "{service["name"]}" не добавлен так как находиться в другом шаблоне ("{tmp.template_name}"). Можно добавлять сервисы только из текущего шаблона.')
                            error = 1
                            continue
                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, servicegroups[item['name']].id, service)
                        if err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Сервис "{service["name"]}" уже существует в этой группе сервисов.')
                        elif err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Группа сервисов "{item["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Группа сервисов "{item["name"]}" не найдена в шаблоне "{servicegroups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Добавлен сервис "{service["name"]}".')
                else:
                    self.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы сервисов "{item["name"]}" не обновлено так как она обновляется удалённо.')
            self.msleep(1)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп сервисов завершён.')


    def import_ip_lists(self, path):
        """Импортируем списки IP адресов"""
        self.stepChanged.emit('BLUE|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

        if not os.path.isdir(path):
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
            return
        files_list = os.listdir(path)
        if not files_list:
            self.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
            return

        error = 0
        ip_lists = self.mc_data['ip_lists']

        # Импортируем все списки IP-адресов без содержимого (пустые).
        self.stepChanged.emit('LBLUE|    Импортируем списки IP-адресов без содержимого.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            content = data.pop('content')
            data.pop('last_update', None)

            if data['name'] in ip_lists:
                if self.template_id == ip_lists[data['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список IP-адресов "{data["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список IP-адресов "{data["name"]}" уже существует в шаблоне "{ip_lists[data["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, data)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}.')
                else:
                    ip_lists[data['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')

        # Импортируем содержимое в уже добавленные списки IP-адресов.
        self.stepChanged.emit('LBLUE|    Импортируем содержимое списков IP-адресов.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file)
            if err:
                continue

            _, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка', mode=0)
            self.stepChanged.emit(f'BLACK|    Импортируем содержимое списка IP-адресов "{data["name"]}".')

            if data['name'] not in ip_lists:
                self.stepChanged.emit(f'RED|       Не найден список IP-адресов "{data["name"]}". Содержимое не импортировано]')
                error = 1
                continue

            if self.template_id == ip_lists[data['name']].template_id:
                if data['list_type_update'] == 'static':
                    if data['content']:
                        new_content = []
                        for item in data['content']:
                            if 'list' in item:
                                item_list = self.get_transformed_name(item['list'], descr='Имя списка', mode=0)[1]
                                item_value = f'IP-лист "{item_list}"'
                                try:
                                    item['list'] = ip_lists[item_list].id
                                    new_content.append(item)
                                except KeyError:
                                    self.stepChanged.emit(f'RED|       Error: [Список IP-адресов "{data["name"]}"] {item_value} не добавлен в список так как не найден в данной группе шаблонов. ')
                                    error = 1
                            else:
                                new_content.append(item)
#                                item_value = f'IP-адрес "{item["value"]}"'
                        if not new_content:
                            self.stepChanged.emit(f'uGRAY|       Список "{data["name"]}" не имеет содержимого.')
                            continue

#                            err, result = self.utm.add_template_nlist_item(self.template_id, iplist['id'], item)
#                            if err == 1:
#                                self.stepChanged.emit(f'RED|       {result} [{item_value}] не добавлен в список IP-адресов "{data["name"]}"')
#                                error = 1
#                            elif err == 3:
#                                self.stepChanged.emit(f'uGRAY|       {item_value} уже существует.')
#                            else:
#                                self.stepChanged.emit(f'BLACK|       Добавлен {item_value}.')
                        err, result = self.utm.add_template_nlist_items(self.template_id, ip_lists[data['name']].id, new_content)
                        if err == 1:
                            self.stepChanged.emit(f'RED|       {result} [Список IP-адресов "{data["name"]}" содержимое не импортировано]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|       Содержимое списка IP-адресов "{data["name"]}" обновлено.')
                    else:
                        self.stepChanged.emit(f'GRAY|       Список "{data["name"]}" пуст.')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка IP-адресов "{data["name"]}" не обновлено так как он обновляется удалённо.')
            else:
                self.stepChanged.emit(f'sGREEN|       Содержимое списка IP-адресов "{data["name"]}" не обновлено так как он находится в другом шаблоне.')
            self.msleep(2)

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

        if not self.mc_data['useragents']:
            if self.get_useragent_list():        # Заполняем self.mc_data['useragents']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
                return
        useragents = self.mc_data['useragents']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in useragents:
                if self.template_id == useragents[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список Useragent "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_nlist(self.template_id, useragents[item['name']].id, item)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result}  [Список Useragent {item["name"]}]')
                        error = 1
                        continue
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}')
                    else:
                        self.stepChanged.emit(f'uGRAY|       Список Useragent "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список Useragent "{item["name"]}" уже существует в шаблоне "{useragents[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Список Useragent "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    useragents[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    err2, result2 = self.utm.add_template_nlist_items(self.template_id, useragents[item['name']].id, content)
                    if err2 == 3:
                        self.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        self.stepChanged.emit(f'RED|       {result2}  [Список Useragent: "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Содержимое списка Useragent "{item["name"]}" импортировано.')
                else:
                    self.stepChanged.emit(f'GRAY|       Список Useragent "{item["name"]}" пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка Useragent "{item["name"]}" не импортировано так как он обновляется удалённо.')
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

        mimes = self.mc_data['mime']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя списка')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in mimes:
                if self.template_id == mimes[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список Типов контента "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_nlist(self.template_id, mimes[item['name']].id, item)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result}  [Список Типов контента "{item["name"]}"]')
                        error = 1
                        continue
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}')
                    else:
                        self.stepChanged.emit(f'uGRAY|       Список Типов контента "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список Типов контента "{item["name"]}" уже существует в шаблоне "{mimes[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Список Типов контента "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    mimes[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    err2, result2 = self.utm.add_template_nlist_items(self.template_id, mimes[item['name']].id, content)
                    if err2 == 3:
                        self.stepChanged.emit(f'GRAY|       {result2}')
                    elif err2 == 1:
                        self.stepChanged.emit(f'RED|       {result2}  [Список Типов контента "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Содержимое списка Типов контента "{item["name"]}" импортировано.')
                else:
                    self.stepChanged.emit(f'GRAY|       Список Типов контента "{item["name"]}" пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое списка Типов контента "{item["name"]}" не импортировано так как он обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Типы контента" завершён.')


    def import_url_lists(self, path):
        """Импортировать списки URL в шаблон МС"""
        self.stepChanged.emit('BLUE|Импорт списков URL раздела "Библиотеки/Списки URL".')
        
        if not os.path.isdir(path):
            self.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
            return
        files_list = os.listdir(path)
        if not files_list:
            self.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
            return

        error = 0
        url_lists = self.mc_data['url_lists']

        # Импортируем все списки URL без содержимого (пустые).
        self.stepChanged.emit('LBLUE|    Импортируем списки URL без содержимого.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file, mode=2)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка')
            content = data.pop('content')
            data.pop('last_update', None)
            if not data['attributes'] or 'threat_level' in data['attributes']:
                data['attributes'] = {'list_compile_type': 'case_insensitive'}

            if data['name'] in url_lists:
                if self.template_id == url_lists[data['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Список URL "{data["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Список URL "{data["name"]}" уже существует в шаблоне "{url_lists[data["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, data)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Список URL "{data["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    url_lists[data['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

        # Импортируем содержимое в уже добавленные списки URL.
        self.stepChanged.emit('LBLUE|    Импортируем содержимое списков URL.')
        for file_name in files_list:
            json_file = os.path.join(path, file_name)
            err, data = self.read_json_file(json_file)
            if err:
                continue

            error, data['name'] = self.get_transformed_name(data['name'], err=error, descr='Имя списка URL')
            self.stepChanged.emit(f'BLACK|    Импортируем содержимое списка URL "{data["name"]}".')

            if self.template_id == url_lists[data['name']].template_id:
                if data['list_type_update'] == 'static':
                    if data['content']:
                        err, result = self.utm.add_template_nlist_items(self.template_id, url_lists[data['name']].id, data['content'])
                        if err == 1:
                            self.stepChanged.emit(f'RED|       {result} [Список URL "{data["name"]}" - содержимое не импортировано]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|       Содержимое списка URL "{data["name"]}" обновлено.')
                    else:
                        self.stepChanged.emit(f'GRAY|      Список URL "{data["name"]}" пуст.')
                else:
                    self.stepChanged.emit(f'GRAY|       Содержимое списка URL "{data["name"]}" не импортировано так как он обновляется удалённо.')
            else:
                self.stepChanged.emit(f'sGREEN|       Содержимое списка URL "{data["name"]}" не обновлено так как он находится в другом шаблоне.')
            self.msleep(1)

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

        calendars = self.mc_data['calendars']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя календаря')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in calendars:
                if self.template_id == calendars[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Календарь "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Календарь "{item["name"]}" уже существует в шаблоне "{calendars[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Календарь "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    calendars[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

            if item['list_type_update'] == 'static':
                if content:
                    for value in content:
                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, calendars[item['name']].id, value)
                        if err2 == 1:
                            error = 1
                            self.stepChanged.emit(f'RED|       {result2}  [TimeSet "{value["name"]}"] не импортирован')
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       TimeSet "{value["name"]}" уже существует.')
                        elif err2 == 7:
                            message = f'       Error: Календарь "{item["name"]}" не найден в шаблоне "{calendars[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       TimeSet "{value["name"]}" импортирован.')
                else:
                    self.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое календаря "{item["name"]}" не импортировано так как он обновляется удалённо.')

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

        shapers = self.mc_data['shapers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя Полосы пропускания')
            if item['name'] in shapers:
                if self.template_id == shapers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Полоса пропускания "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_shaper(self.template_id, shapers[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}  [Полоса пропускания "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Полоса пропускания "{item["name"]}" обновлена.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Полоса пропускания "{item["name"]}" уже существует в шаблоне "{shapers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_shaper(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Полоса пропускания "{item["name"]}" не импортирована]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    shapers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка "Полосы пропускания" завершён.')


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
        self.stepChanged.emit('LBLUE|    Импортируются только шаблоны страниц у которых есть HTML-файл страницы.')
        error = 0
        html_files = os.listdir(path)

        response_pages = self.mc_data['response_pages']

#        n = 0
        for item in data:
#            if f"{item['name']}.html" in html_files:
#                n += 1
            if item['name'] in response_pages:
                if self.template_id == response_pages[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Шаблон страницы "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_responsepage(self.template_id, response_pages[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}  [Шаблон страницы "{item["name"]}" не импортирован]')
                        error = 1
                        continue
                    else:
                        self.stepChanged.emit(f'uGRAY|    Шаблон страницы "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Шаблон страницы "{item["name"]}" уже существует в шаблоне "{response_pages[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_responsepage(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Шаблон страницы "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                else:
                    response_pages[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

            if f"{item['name']}.html" in html_files:
                upload_file = os.path.join(path, f"{item['name']}.html")
                err, result = self.utm.get_realm_upload_session(upload_file)
                if err:
                    self.stepChanged.emit(f'RED|       {result}')
                    error = 1
                elif result['success']:
                    err2, result2 = self.utm.set_template_responsepage_data(self.template_id, response_pages[item['name']].id, result['storage_file_uid'])
                    if err2:
                        self.stepChanged.emit(f'RED|       {result2} [Страница "{item["name"]}.html" не импортирована]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирована.')
                else:
                    error = 1
                    self.stepChanged.emit(f'ORANGE|       Error: Не удалось импортировать страницу "{item["name"]}.html".')
#        if not n:
#            self.stepChanged.emit('GRAY|    Нет шаблонов страниц у которых есть HTML-файл страницы.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шаблонов страниц.')
        else:
            self.stepChanged.emit('GREEN|    Импорт шаблонов страниц завершён.')


    def import_url_categories(self, path):
        """Импортировать группы URL категорий с содержимым"""
        json_file = os.path.join(path, 'config_url_categories.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')
        error = 0

        url_category_groups = self.mc_data['url_categorygroups']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)
            item.pop('guid', None)

            if item['name'] in url_category_groups:
                if self.template_id == url_category_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа URL категорий "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа URL категорий "{item["name"]}" уже существует в шаблоне "{url_category_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа URL категорий "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    url_category_groups[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for category in content:
                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, url_category_groups[item['name']].id, category)
                        if err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Категория "{category["name"]}" уже существует.')
                        elif err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Категория "{category["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Группа URL категорий "{item["name"]}" не найдена в шаблоне "{url_category_groups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Добавлена категория "{category["name"]}".')
                else:
                    self.stepChanged.emit(f'GRAY|       Группа URL категорий "{item["name"]}" не содержит категорий.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы URL категорий "{item["name"]}" не импортировано так как она обновляется удалённо.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп URL категорий.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп URL категорий завершён.')


    def import_custom_url_category(self, path):
        """Импортируем изменённые категории URL"""
        json_file = os.path.join(path, 'custom_url_categories.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
        error = 0

        custom_url = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_custom_url_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте изменённых категорий URL.')
                self.error = 1
                return
            for x in result:
                if x['name'] in custom_url:
                    self.stepChanged.emit('ORANGE|    Warning: Категория для URL "{x["name"]}" изменена в нескольких шаблонах группы. Запись из шаблона "{name}" не будет испольована.')
                else:
                    custom_url[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            item.pop('user', None)
            item.pop('change_date', None)
            item.pop('default_categories', None)
            try:
                item['categories'] = [self.mc_data['url_categories'][x] for x in item['categories']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {err}. Правило  не добавлено.')
                error = 1
                continue

            if item['name'] in custom_url:
                if self.template_id == custom_url[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Изменение категории URL "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_custom_url(self.template_id, custom_url[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}  [URL категория "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       URL категория "{item["name"]}" updated.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Изменение категории URL "{item["name"]}" уже существует в шаблоне "{custom_url[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_custom_url(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Изменение категорий для URL "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    custom_url[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Изменение категории для URL "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт изменённых категорий URL завершён.')


    def import_application_signature(self, path):
        """Импортируем список Приложения"""
        json_file = os.path.join(path, 'config_applications.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
        error = 0

        users_apps = {}
        err, result = self.utm.get_realm_l7_signatures(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return
        for x in result:
            users_apps[x['name']] = BaseObject(id=x['id'], template_id=x['template_id'], template_name=self.templates.get(x['template_id'], None))

        for item in data:
            item.pop('signature_id', None)

            new_l7categories = []
            for category in item['l7categories']:
                try:
                    new_l7categories.append(self.mc_data['l7_categories'][category])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Категория {err} не существует. Категория не добавлена.')
                    error = 1
            item['l7categories'] = new_l7categories

            if item['name'] in users_apps:
                if self.template_id == users_apps[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Пользовательское приложение "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_app_signature(self.template_id, users_apps[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Приложение "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Пользовательское приложение "{item["name"]}" обновлено.')
                else:
                    if users_apps[item['name']].template_name:
                        self.stepChanged.emit(f'sGREEN|    Пользовательское приложение "{item["name"]}" уже существует в шаблоне "{users_apps[item["name"]].template_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|    Пользовательское приложение "{item["name"]}" уже существует в шаблоне, отсутствующем в данной группе шаблонов.')
            else:
                err, result = self.utm.add_template_app_signature(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Пользовательское приложение "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    users_apps[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
            self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт пользовательских приложений завершён.')


    def import_app_profiles(self, path):
        """Импортируем профили приложений"""
        json_file = os.path.join(path, 'config_app_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
        error = 0

        if not self.mc_data['l7_apps']:
            if self.get_app_signatures():        # Заполняем self.mc_data['l7_apps']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
                return
        l7_apps = self.mc_data['l7_apps']

        if not self.mc_data['l7_profiles']:
            if self.get_l7_profiles():        # Заполняем self.mc_data['l7_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
                return
        l7_profiles = self.mc_data['l7_profiles']

        for item in data:
            new_overrides = []
            for app in item['overrides']:
                try:
                    app['id'] = l7_apps[app['id']].id
                    new_overrides.append(app)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдено приложение {err}. Приложение не добавлено.')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in l7_profiles:
                if self.template_id == l7_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль приложений "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_l7_profile(self.template_id, l7_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль приложений "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль приложений "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль приложений "{item["name"]}" уже существует в шаблоне "{l7_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_l7_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль приложений "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    l7_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')
            self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей приложений завершён.')


    def import_application_groups(self, path):
        """Импортировать группы приложений на UTM"""
        json_file = os.path.join(path, 'config_application_groups.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт групп приложений в раздел "Библиотеки/Группы приложений".')

        if not self.mc_data['l7_apps']:
            if self.get_app_signatures():        # Заполняем self.mc_data['l7_apps']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
                return

        l7_apps = self.mc_data['l7_apps']
        apps_groups = self.mc_data['apps_groups']

        error = 0
        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in apps_groups:
                if self.template_id == apps_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа приложений "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа приложений "{item["name"]}" уже существует в шаблоне "{apps_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа приложений "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    apps_groups[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Группа приложений "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for app in content:
                        if 'name' not in app:   # Так бывает при некорректном добавлении приложения через API
                            self.stepChanged.emit(f'RED|       Error: [Группа приложений "{item["name"]}"] Приложение "{app}" не добавлено, так как не содержит имя.')
                            error = 1
                            continue
                        try:
                            app['value'] = l7_apps[app['name']].signature_id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|       Error: [Группа приложений "{item["name"]}"] Приложение "{app["name"]}" не импортировано. Такого приложения нет на UG MC.')
                            error = 1
                            continue

                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, apps_groups[item['name']].id, app) 
                        if err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2}  [Группа приложений "{item["name"]}"]')
                            error = 1
                        elif err2 == 7:
                            message = f'       Error: Группа приложений "{item["name"]}" не найдена в шаблоне "{apps_groups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Приложение "{app["name"]}" уже существует в группе приложений "{item["name"]}".')
                        else:
                            self.stepChanged.emit(f'BLACK|       Приложение "{app["name"]}" импортировано.')
                else:
                    self.stepChanged.emit(f'GRAY|       Группа приложений "{item["name"]}" не имеет содержимого.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы приложений "{item["name"]}" не импортировано так как она обновляется удалённо.')
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

        if not self.mc_data['email_groups']:
            if self.get_email_groups():        # Заполняем self.mc_data['email_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
                return
        email_groups = self.mc_data['email_groups']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in email_groups:
                if self.template_id == email_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа почтовых адресов "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа почтовых адресов "{item["name"]}" уже существует в шаблоне "{email_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа почтовых адресов "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    email_groups[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Группа почтовых адресов "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for email in content:
                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, email_groups[item['name']].id, email)
                        if err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2} [Группа почтовых адресов "{item["name"]}"]')
                            error = 1
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Адрес "{email["value"]}" уже существует.')
                        elif err2 == 7:
                            message = f'       Error: Группа почтовых адресов "{item["name"]}" не найдена в шаблоне "{email_groups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Адрес "{email["value"]}" импортирован.')
                else:
                    self.stepChanged.emit(f'GRAY|       Группа почтовых адресов "{item["name"]}" не имеет содержимого.')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы почтовых адресов "{item["name"]}" не импортировано так как она обновляется удалённо.')

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

        if not self.mc_data['phone_groups']:
            if self.get_phone_groups():        # Заполняем self.mc_data['phone_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
                return

        phone_groups = self.mc_data['phone_groups']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            content = item.pop('content')
            item.pop('last_update', None)

            if item['name'] in phone_groups:
                if self.template_id == phone_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа телефонных номеров "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа телефонных номеров "{item["name"]}" уже существует в шаблоне "{phone_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_nlist(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result}  [Группа телефонных номеров "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'uGRAY|    {result}')
                else:
                    phone_groups[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Группа телефонных номеров "{item["name"]}" импортирована.')

            if item['list_type_update'] == 'static':
                if content:
                    for number in content:
                        err2, result2 = self.utm.add_template_nlist_item(self.template_id, phone_groups[item['name']].id, number)
                        if err2 == 1:
                            self.stepChanged.emit(f'RED|       {result2} [Группа телефонных номеров "{item["name"]}"]')
                            error = 1
                        elif err2 == 3:
                            self.stepChanged.emit(f'GRAY|       Номер "{number["value"]}" уже существует.')
                        elif err2 == 7:
                            message = f'       Error: Группа телефонных номеров "{item["name"]}" не найдена в шаблоне "{phone_groups[item["name"]].template_name}".'
                            self.stepChanged.emit(f'RED|{message}\n          Импорт прерван. Перелогиньтесь в МС и повторите попытку.')
                            self.error = 1
                            return
                        else:
                            self.stepChanged.emit(f'BLACK|       Номер "{number["value"]}" импортирован.')
                else:
                    self.stepChanged.emit(f'GRAY|       Нет содержимого в группе телефонных номеров "{item["name"]}".')
            else:
                self.stepChanged.emit(f'GRAY|       Содержимое группы телефонных номеров "{item["name"]}" не импортировано так как она обновляется удалённо.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп телефонных номеров завершён.')


    def import_custom_idps_signature(self, path):
        """Импортируем пользовательские сигнатуры СОВ."""
        json_file = os.path.join(path, 'custom_idps_signatures.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
        error = 0

        if not self.mc_data['realm_users_signatures']:
            if self.get_idps_realm_users_signatures():        # Заполняем атрибут self.mc_data['realm_users_signatures']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте импорте пользовательских сигнатур СОВ.')
                return
        users_signatures = self.mc_data['realm_users_signatures']

        for item in data:
            if item['msg'] in users_signatures:
                if self.template_id == users_signatures[item['msg']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сигнатура СОВ "{item["msg"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_idps_signature(self.template_id, users_signatures[item['msg']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Сигнатура СОВ "{item["msg"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Сигнатура СОВ "{item["msg"]}" обновлена.')
                else:
                    if users_signatures[item['msg']].template_name:
                        self.stepChanged.emit(f'sGREEN|    Сигнатура СОВ "{item["msg"]}" уже существует в шаблоне "{users_signatures[item["msg"]].template_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|    Сигнатура СОВ "{item["msg"]}" существует в шаблоне, отсутствующем в данной группе.')
            else:
                err, result = self.utm.add_template_idps_signature(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ "{item["msg"]}" не импортирована]')
                    error = 1
                else:
                    users_signatures[item['msg']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
            self.msleep(1)
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

        # Получаем пользовательские сигнатуры СОВ.
        if not self.mc_data['realm_users_signatures']:
            if self.get_idps_realm_users_signatures():        # Заполняем атрибут self.mc_data['realm_users_signatures']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
                return

        self.stepChanged.emit(f'NOTE|    Получаем список сигнатур СОВ с МС, это может быть долго...')
        err, result = self.utm.get_template_idps_signatures_list(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей СОВ.')
            self.error = 1
            return
        idps_signatures = {x['msg']: BaseObject(id=x['id'], template_id=self.template_id, template_name=self.templates[self.template_id]) for x in result}
        idps_signatures.update(self.mc_data['realm_users_signatures'])

        if not self.mc_data['idps_profiles']:
            if self.get_idps_profiles():        # Заполняем self.mc_data['idps_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
                return
        idps_profiles = self.mc_data['idps_profiles']

        for item in data:
            if 'filters' not in item:
                self.stepChanged.emit('RED|    Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
                error = 1
                break

            # Исключаем отсутствующие сигнатуры. И получаем ID сигнатур по имени так как ID может не совпадать.
            new_overrides = []
            for signature in item['overrides']:
                try:
                    signature['id'] = idps_signatures[signature['msg']].id
                    new_overrides.append(signature)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль СОВ "{item["name"]}"] Не найдена сигнатура СОВ: {err}.')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in idps_profiles:
                if self.template_id == idps_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль СОВ "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_idps_profile(self.template_id, idps_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль СОВ "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль СОВ "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль СОВ "{item["name"]}" уже существует в шаблоне "{idps_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_idps_profile(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль СОВ "{item["name"]}" не импортирован]')
                else:
                    idps_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['notification_profiles']:
            if self.get_notification_profiles():        # Заполняем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
                return
        notification_profiles = self.mc_data['notification_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in notification_profiles:
                if self.template_id == notification_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль оповещения "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_notification_profile(self.template_id, notification_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль оповещения "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль оповещения "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль оповещения "{item["name"]}" уже существует в шаблоне "{notification_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_notification_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль оповещения "{item["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    notification_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['netflow_profiles']:
            if self.get_netflow_profiles():        # Заполняем self.mc_data['netflow_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
                return
        netflow_profiles = self.mc_data['netflow_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in netflow_profiles:
                if self.template_id == netflow_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль netflow "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_netflow_profile(self.template_id, netflow_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль netflow "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль netflow "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль netflow "{item["name"]}" уже существует в шаблоне "{netflow_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_netflow_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль netflow "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    netflow_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['lldp_profiles']:
            if self.get_lldp_profiles():        # Заполняем self.mc_data['lldp_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
                return
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in lldp_profiles:
                if self.template_id == lldp_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль LLDP "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_lldp_profile(self.template_id, lldp_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль LLDP "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль LLDP "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль LLDP "{item["name"]}" уже существует в шаблоне "{lldp_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_lldp_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль LLDP "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    lldp_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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
        ssl_profiles = self.mc_data['ssl_profiles']

        for item in data:
            if 'supported_groups' not in item:
                item['supported_groups'] = []
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')

            if item['name'] in ssl_profiles:
                if self.template_id == ssl_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль SSL "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_ssl_profile(self.template_id, ssl_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль SSL "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль SSL "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль SSL "{item["name"]}" уже существует в шаблоне "{ssl_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_ssl_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль SSL "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ssl_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей SSL завершён.')


    def import_ssl_forward_profiles(self, path):
        """Импортируем профили пересылки SSL"""
        json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
        error = 0

        if not self.mc_data['ssl_forward_profiles']:
            if self.get_ssl_forward_profiles():        # Заполняем self.mc_data['ssl_forward_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
                return
        ssl_forward_profiles = self.mc_data['ssl_forward_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in ssl_forward_profiles:
                if self.template_id == ssl_forward_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль пересылки SSL "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_ssl_forward_profile(self.template_id, ssl_forward_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль пересылки SSL "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль пересылки SSL "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль пересылки SSL "{item["name"]}" уже существует в шаблоне "{ssl_forward_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_ssl_forward_profile(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL "{item["name"]}" не импортирован]')
                else:
                    ssl_forward_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['hip_objects']:
            if self.get_hip_objects():        # Заполняем self.mc_data['hip_objects']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
                return
        hip_objects = self.mc_data['hip_objects']

        for item in data:
            if item['name'] in hip_objects:
                if self.template_id == hip_objects[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    HIP объект "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_hip_object(self.template_id, hip_objects[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [HIP объект "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       HIP объект "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    HIP объект "{item["name"]}" уже существует в шаблоне "{hip_objects[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_hip_object(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [HIP объект "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    hip_objects[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['hip_objects']:
            if self.get_hip_objects():        # Заполняем self.mc_data['hip_objects']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
                return
        hip_objects = self.mc_data['hip_objects']

        if not self.mc_data['hip_profiles']:
            if self.get_hip_profiles():        # Заполняем self.mc_data['hip_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
                return
        hip_profiles = self.mc_data['hip_profiles']

        for item in data:
            for obj in item['hip_objects']:
                obj['id'] = hip_objects[obj['id']].id
            if item['name'] in hip_profiles:
                if self.template_id == hip_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    HIP профиль "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_hip_profile(self.template_id, hip_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [HIP профиль "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       HIP профиль "{item["name"]}" updated.')
                else:
                    self.stepChanged.emit(f'sGREEN|    HIP профиль "{item["name"]}" уже существует в шаблоне "{hip_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_hip_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [HIP профиль "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    hip_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['bfd_profiles']:
            if self.get_bfd_profiles():        # Заполняем self.mc_data['bfd_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте BFD профилей.')
                return
        bfd_profiles = self.mc_data['bfd_profiles']

        for item in data:
            if item['name'] in bfd_profiles:
                if self.template_id == bfd_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль BFD "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_bfd_profile(self.template_id, bfd_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль BFD "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль BFD "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль BFD "{item["name"]}" уже существует в шаблоне "{bfd_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_bfd_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    bfd_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['userid_filters']:
            if self.get_useridagent_filters():        # Заполняем self.mc_data['userid_filters']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
                return
        userid_filters = self.mc_data['userid_filters']

        for item in data:
            if item['name'] in userid_filters:
                if self.template_id == userid_filters[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Фильтр агента UserID "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_useridagent_filter(self.template_id, userid_filters[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Фильтр "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Фильтр "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Фильтр агента UserID "{item["name"]}" уже существует в шаблоне "{userid_filters[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_useridagent_filter(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Фильтр "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    userid_filters[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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
        scenarios = self.mc_data['scenarios']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сценария')
            for condition in item['conditions']:
                if condition['kind'] == 'application':
                    for x in condition['apps']:
                        try:
                            if x[0] == 'ro_group':
                                x[1] = 0 if x[1] == 'All' else self.mc_data['l7_categories'][x[1]]
                            elif x[0] == 'group':
                                x[1] = self.mc_data['apps_groups'][x[1]].id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найдена группа приложений {err}. Загрузите группы приложений и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найдена группа приложений {err}.'
                            condition['apps'] = []
                            error = 1
                            break
                elif condition['kind'] == 'mime_types':
                    try:
                        condition['content_types'] = [self.mc_data['mime'][x].id for x in condition['content_types']]
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найден тип контента {err}. Загрузите типы контента и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден тип контента {err}.'
                        condition['content_types'] = []
                        error = 1
                elif condition['kind'] == 'url_category':
                    for x in condition['url_categories']:
                        try:
                            if x[0] == 'list_id':
                                x[1] = self.mc_data['url_categorygroups'][x[1]].id
                            elif x[0] == 'category_id':
                                x[1] = self.mc_data['url_categories'][x[1]]
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Сценарий "{item["name"]}"] Не найдена группа URL категорий {err}. Загрузите категории URL и повторите попытку.')
                            item['description'] = f'{item["description"]}\nError: Не найдена группа URL категорий {err}.'
                            condition['url_categories'] = []
                            error = 1
                            break

            if item['name'] in scenarios:
                if self.template_id == scenarios[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сценарий "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_scenarios_rule(self.template_id, scenarios[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Сценарий "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Сценарий "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сценарий "{item["name"]}" уже существует в шаблоне "{scenarios[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_scenarios_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сценарий "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    scenarios[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сценариев завершён.')


    #----------------------------------------- Сеть ------------------------------------------------
    def import_zones(self, path):
        """Импортируем зоны на NGFW, если они есть."""
        json_file = os.path.join(path, 'config_zones.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')
        mc_zones = self.mc_data['zones']
        error = 0

        for zone in data:
            error, zone['name'] = self.get_transformed_name(zone['name'], err=error, descr='Имя зоны')
            if zone['name'] in mc_zones:
                if self.template_id == mc_zones[zone['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Зона "{zone["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Зона "{zone["name"]}" уже существует в шаблоне "{mc_zones[zone["name"]].template_name}".')
                continue

            current_zone = Zone(self, zone)
            zone['services_access'] = current_zone.services_access
            zone['enable_antispoof'] = current_zone.enable_antispoof
            zone['antispoof_invert'] = current_zone.antispoof_invert
            zone['networks'] = current_zone.networks
            zone['sessions_limit_enabled'] = current_zone.sessions_limit_enabled
            zone['sessions_limit_exclusions'] = current_zone.sessions_limit_exclusions
            zone['description'] = current_zone.description
            error = current_zone.error

            err, result = self.utm.add_template_zone(self.template_id, zone)
            if err == 3:
                self.stepChanged.emit(f'uGRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [Зона "{zone["name"]}" не импортирована]')
                error = 1
            else:
                mc_zones[zone['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                self.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
        else:
            self.stepChanged.emit('GREEN|    Импорт Зон завершён.')


    def import_interfaces(self, path):
        """Импортируем интерфейсы."""
        json_file = os.path.join(path, 'config_interfaces.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit(f'BLUE|Импорт интерфейсов на узел кластера "{self.node_name}"')
        if not self.mc_data['interfaces']:
            if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return

        if not self.mc_data['netflow_profiles']:
            if self.get_netflow_profiles():        # Заполняем self.mc_data['netflow_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return

        if not self.mc_data['lldp_profiles']:
            if self.get_lldp_profiles():        # Заполняем self.mc_data['lldp_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов.')
                return

        kinds = set()
        for item in data:
            kinds.add(item['kind'])

        if 'adapter' in kinds:
            self.import_adapter_interfaces(path, data)
        if kinds.intersection({'bond', 'bridge'}):
            self.import_bond_interfaces(path, data)
        if 'tunnel' in kinds:
            self.import_ipip_interfaces(path, data)
        if 'vpn' in kinds:
            self.import_vpn_interfaces(path, data)
        if 'vlan' in kinds:
            self.import_vlan_interfaces(path, data)


    def import_adapter_interfaces(self, path, data):
        """Импортируем интерфесы типа ADAPTER."""
        self.stepChanged.emit('BLUE|    Импорт сетевых адаптеров в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] == 'adapter':
                if 'node_name' in item:
                     if item['node_name'] != self.node_name:
                        continue
                else:
                    item['node_name'] = self.node_name

                iface_name = f'{item["name"]}:{self.node_name}'
                if iface_name in mc_ifaces:
                    if self.template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{self.node_name}".')
                    continue
                if item['name'] == 'port0':
                    self.stepChanged.emit(f'LBLUE|       Интерфейс "{item["name"]}" не может быть импортирован в шаблон МС.')
                    continue

                item.pop('running', None)
                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                if 'config_on_device' not in item:
                    item['config_on_device'] = False

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4:
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Сетевой адаптер "{item["name"]}" импортирован на узел кластера "{self.node_name}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании сетевых адаптеров.')
        else:
            self.stepChanged.emit('GREEN|       Импорт сетевых адаптеров завершён.')


    def import_bond_interfaces(self, path, data):
        """Импортируем Бонд-интерфесы."""
        self.stepChanged.emit('BLUE|    Импорт агрегированных интерфейсов в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] in ('bond', 'bridge'):
                if 'node_name' in item:
                     if item['node_name'] != self.node_name:
                        continue
                else:
                    item['node_name'] = self.node_name

                iface_name = f'{item["name"]}:{self.node_name}'
                if iface_name in mc_ifaces:
                    if self.template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{self.node_name}".')
                    continue
                if item['kind'] == 'bond':
                    if 'port0' in item['bonding']['slaves']:
                        self.stepChanged.emit(f'RED|       Error: Интерфейс "{item["name"]}" не импортирован в шаблон МС так как содержит "port0".')
                        error = 1
                        continue
                elif item['kind'] == 'bridge':
                    if 'port0' in item['bridging']['ports']:
                        self.stepChanged.emit(f'RED|       Error: Интерфейс "{item["name"]}" не импортирован в шаблон МС так как содержит "port0".')
                        error = 1
                        continue

                item.pop('running', None)
#                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                if 'config_on_device' not in item:
                    item['config_on_device'] = False

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4:
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Интерфейс "{item["name"]}" импортирован на узел кластера "{self.node_name}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании агрегированных интерфейсов.')
        else:
            self.stepChanged.emit('GREEN|       Импорт агрегированных интерфейсов завершён.')


    def import_ipip_interfaces(self, path, data):
        """Импортируем интерфесы IP-IP."""
        # Проверяем что есть интерфейсы IP-IP для импорта.
        is_gre = False
        for item in data:
            if 'kind' in item and item['kind'] == 'tunnel' and item['name'][:3] == 'gre':
                is_gre = True
        if not is_gre:
            return

        self.stepChanged.emit('BLUE|    Импорт интерфейсов GRE/IPIP/VXLAN в раздел "Сеть/Интерфейсы".')
        mc_ifaces = self.mc_data['interfaces']
        mc_gre = [int(aa[0][3:]) for x in mc_ifaces if (aa := x.split(':'))[0].startswith('gre') and aa[1] == self.node_name]
        gre_num = max(mc_gre) if mc_gre else 0
        if gre_num:
            self.stepChanged.emit(f'uGRAY|       Для интерфейсов GRE будут использованы номера начиная с {gre_num + 1} так как меньшие номера уже существует в этой группе шаблонов для узла кластера "{self.node_name}".')
        error = 0

        for item in data:
            if 'kind' in item and item['kind'] == 'tunnel' and item['name'].startswith('gre'):
                gre_num += 1
                item['name'] = f'gre{gre_num}'
                item.pop('id', None)          # удаляем readonly поле
                item.pop('master', None)      # удаляем readonly поле
                item.pop('mac', None)
                if 'node_name' in item:
                     if item['node_name'] != self.node_name:
                        continue
                else:
                    item['node_name'] = self.node_name

                iface_name = f'{item["name"]}:{self.node_name}'
                if iface_name in mc_ifaces:
                    if self.template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{self.node_name}".')
                    continue

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4:
                    item['config_on_device'] = True
                item['ipv4'] = new_ipv4

                err, result = self.utm.add_template_interface(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["tunnel"]["mode"]} - {item["name"]}" не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Интерфейс {item["tunnel"]["mode"]} - {item["name"]} импортирован на узел кластера "{self.node_name}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов GRE/IPIP/VXLAN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов GRE/IPIP/VXLAN завершён.')


    def import_vpn_interfaces(self, path, data):
        """Импортируем интерфесы VPN."""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов VPN в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] == 'vpn':
                item['node_name'] = 'cluster'
                item.pop('running', None)
                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                iface_name = f'{item["name"]}:cluster'
                if iface_name in mc_ifaces:
                    if self.template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{self.node_name}".')
                    continue

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4:
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс {item["name"]} не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Интерфейс VPN "{item["name"]}" импортирован на узел кластера "cluster".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов VPN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов VPN завершён.')


    def import_vlan_interfaces(self, path, data):
        """Импортируем интерфесы VLAN."""
        self.stepChanged.emit('BLUE|    Импорт интерфейсов VLAN в раздел "Сеть/Интерфейсы"')
        error = 0

        mc_ifaces = self.mc_data['interfaces']
        netflow_profiles = self.mc_data['netflow_profiles']
        lldp_profiles = self.mc_data['lldp_profiles']

        for item in data:
            if 'kind' in item and item['kind'] == 'vlan':
                if 'node_name' in item:
                     if item['node_name'] != self.node_name:
                        continue
                else:
                    item['node_name'] = self.node_name

                iface_name = f'{item["name"]}:{self.node_name}'
                if iface_name in mc_ifaces:
                    if self.template_id == mc_ifaces[iface_name].template_id:
                        self.stepChanged.emit(f'uGRAY|       Интерфейс "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    else:
                        self.stepChanged.emit(f'sGREEN|       Интерфейс "{item["name"]}" уже существует в шаблоне "{mc_ifaces[iface_name].template_name}" на узле кластера "{self.node_name}".')
                    continue
                if item['link'] == 'port0':
                    self.stepChanged.emit(f'LBLUE|       Интерфейс "{item["name"]}" не может быть импортирован в шаблон МС так как привязан к port0.')
                    continue

                item.pop('running', None)
                item.pop('master', None)
                item.pop('mac', None)
                item.pop('id', None)

                if 'config_on_device' not in item:
                    item['config_on_device'] = False

                if item['zone_id']:
                    try:
                        item['zone_id'] = self.mc_data['zones'][item['zone_id']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найдена зона {err}. Импортируйте зоны и повторите попытку.')
                        item['zone_id'] = 0
                        error = 1

                new_ipv4 = []
                for ip in item['ipv4']:
                    err, result = self.unpack_ip_address(ip)
                    if err:
                        self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не удалось преобразовать IP: "{ip}". IP-адрес использован не будет. {result}')
                        error = 1
                    else:
                        new_ipv4.append(result)
                if not new_ipv4:
                    item['mode'] = 'manual'
                item['ipv4'] = new_ipv4

                try:
                    item['lldp_profile'] = lldp_profiles[item['lldp_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили LLDP и повторите попытку.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
                try:
                    item['netflow_profile'] = netflow_profiles[item['netflow_profile']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|       Error: [Интерфейс "{item["name"]}"] Не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow и повторите попытку.')
                    item['netflow_profile'] = 'undefined'
                    error = 1

                err, result = self.utm.add_template_interface(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Интерфейс "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    mc_ifaces[iface_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Интерфейс VLAN "{item["name"]}" импортирован на узел кластера "{self.node_name}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|       Произошла ошибка при создании интерфейсов VLAN.')
        else:
            self.stepChanged.emit('GREEN|       Импорт интерфейсов VLAN завершён.')


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
        if isinstance(self.ngfw_ports, int):
            if self.ngfw_ports == 1:
                self.error = 1
                return
            elif self.ngfw_ports == 3:
                self.stepChanged.emit(f'NOTE|    Интерфейсы будут установлены в значение "Автоматически" так как порты отсутствуют на узле {self.node_name} шаблона.')
        error = 0

        if not self.mc_data['interfaces']:
            if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
                return
        mc_ifaces = self.mc_data['interfaces'].keys()

        self.mc_data['gateways'].clear()
        if self.get_gateways_list():           # Получаем все шлюзы группы шаблонов и заполняем: self.mc_data['gateways']
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            return
        gateways = self.mc_data['gateways']

        self.mc_data['vrf'].clear()
        if self.get_vrf_list():                # Получаем все VRF группы шаблонов и заполняем: self.mc_data['vrf']
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            return
        mc_vrf = self.mc_data['vrf']

        gateways_vrf = {item['vrf']: [] for item in data}
        for item in data:
            if f'{item["iface"]}:{self.node_name}' in mc_ifaces:
                gateways_vrf[item['vrf']].append(item['iface'])

        for item in data:
            item['is_automatic'] = False
            item.pop('mac', None)

#            if 'node_name' in item:
#                if item['node_name'] != self.node_name:
#                    self.stepChanged.emit(f'rNOTE|    Шлюз "{item["name"]}" не импортирован так как имя узла в настройках не совпало с указанным.')
#                    continue
#            else:
            item['node_name'] = self.node_name

            # Создаём новый VRF если такого ещё нет для этого узла кластера с интерфейсами, которые используются в шлюзах.
            vrf_name = f'{item["vrf"]}:{self.node_name}'
            if vrf_name not in mc_vrf:
                err, result = self.add_empty_vrf(item['vrf'], gateways_vrf[item['vrf']])
                if err:
                    self.stepChanged.emit(f'RED|    {result}\n    Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.')
                    item['vrf'] = 'default'
                    item['default'] = False
                    error = 1
                else:
                    self.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}" на узле кластера "{self.node_name}".')
                    mc_vrf[vrf_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])

            if item['iface'] not in gateways_vrf[item['vrf']]:
                item['iface'] = 'undefined'

            gateway_name = f'{item["name"]}:{self.node_name}'
            if gateway_name in gateways:
                if self.template_id == gateways[gateway_name].template_id:
                    self.stepChanged.emit(f'uGRAY|    Шлюз "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    err, result = self.utm.update_template_gateway(self.template_id, gateways[gateway_name].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|    Error: Шлюз "{item["name"]}" не обновлён. {result}')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|    Шлюз "{item["name"]}" на узле кластера "{self.node_name}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Шлюз "{item["name"]}" уже существует в шаблоне "{gateways[gateway_name].template_name}" на узле кластера "{self.node_name}".')
            else:
                err, result = self.utm.add_template_gateway(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Шлюз "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    gateways[gateway_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован на узел кластера "{self.node_name}".')
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

        err, result = self.utm.update_template_gateway_failover(self.template_id, data)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при обновлении настроек проверки сети.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Настройки проверки сети обновлены.')


    def import_dhcp_subnets(self, path):
        """Импортируем настойки DHCP"""
        self.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
        if isinstance(self.ngfw_ports, int):
            self.stepChanged.emit(self.dhcp_settings)
            if self.ngfw_ports == 1:
                self.error = 1
            return

        if isinstance(self.ngfw_ports, list) and not self.dhcp_settings:
            json_file = os.path.join(path, 'config_dhcp_subnets.json')
            err, self.dhcp_settings = self.read_json_file(json_file)
            if err:
                return
            if not self.mc_data['interfaces']:
                if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                    self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
                    return
            self.ngfw_ports = [x.split(':')[0] for x in self.mc_data['interfaces'] if x.split(':')[1] == self.node_name]

        mc_dhcp_subnets = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_dhcp_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек DHCP.')
                self.error = 1
                return
            mc_dhcp_subnets.update({f'{x["name"]}:{x["node_name"]}': name for x in result})
        error = 0

        for item in self.dhcp_settings:
            if 'node_name' in item:
                if item['node_name'] != self.node_name:
                    self.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не импортирован так как имя узла в настройках не совпало с указанным.')
                    continue
            else:
                item['node_name'] = self.node_name

            if item['iface_id'] == 'Undefined':
                self.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
                continue

            if item['iface_id'] not in self.ngfw_ports:
                self.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт "{item["iface_id"]}" не существует для узла "{self.node_name}" в группе шаблонов.')
                continue

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя DHCP subnet')
            full_name = f'{item["name"]}:{item["node_name"]}'
            if full_name in mc_dhcp_subnets:
                self.stepChanged.emit(f'sGREEN|    DHCP subnet "{item["name"]}" уже существует в шаблоне "{mc_dhcp_subnets[full_name]}" на узле кластера "{self.node_name}".')
                continue

            err, result = self.utm.add_template_dhcp_subnet(self.template_id, item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}  [subnet "{item["name"]}" не импортирован]')
                error = 1
            elif err == 3:
                self.stepChanged.emit(f'GRAY|    {result}.')
            else:
                self.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован на узел кластера "{self.node_name}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт настроек DHCP завершён.')


    def import_dns_config(self, path):
        """Импортируем раздел 'UserGate/DNS'."""
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

        self.stepChanged.emit('BLUE|Импорт системных DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".')
        error = 0

        for item in data:
            item.pop('is_bad', None)
            err, result = self.utm.add_template_dns_server(self.template_id, item)
            if err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [DNS сервер "{item["dns"]}" не импортирован]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" импортирован.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте DNS-серверов.')
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

        for key, value in result.items():
            value = {'enabled': True, 'code': key, 'value': value}
            err, result = self.utm.update_template_dns_setting(self.template_id, key, value)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                error = 1
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DNS-прокси!')
        else:
            self.stepChanged.emit('GREEN|    Настройки DNS-прокси импортированы.')


    def import_dns_rules(self, path):
        """Импортируем правила DNS-прокси"""
        json_file = os.path.join(path, 'config_dns_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил DNS-прокси в раздел "Сеть/DNS/DNS-прокси/Правила DNS".')
        error = 0

        for item in data:
            err, result = self.utm.add_template_dns_rule(self.template_id, item)
            if err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [Правило DNS-прокси "{item["name"]}" не импортировано]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Правило DNS-прокси "{item["name"]}" импортировано.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил DNS-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил DNS-прокси завершён.')


    def import_dns_static(self, path):
        """Импортируем статические записи DNS"""
        json_file = os.path.join(path, 'config_dns_static.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт статических записей DNS в раздел "Сеть/DNS/DNS-прокси/Статические записи".')
        error = 0

        for item in data:
            err, result = self.utm.add_template_dns_static_record(self.template_id, item)
            if err == 3:
                self.stepChanged.emit(f'GRAY|    {result}')
            elif err == 1:
                self.stepChanged.emit(f'RED|    {result} [Статическая запись DNS "{item["name"]}" не импортирована]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт статических записей DNS завершён.')


    def import_vrf(self, path):
        """Импортируем виртуальный маршрутизатор по умолчанию"""
        json_file = os.path.join(path, 'config_vrf.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
        self.stepChanged.emit('LBLUE|    Если вы используете BGP, после импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.')
        error = 0
    
        self.mc_data['vrf'].clear()
        if self.get_vrf_list():                # Получаем все VRF группы шаблонов и заполняем: self.mc_data['vrf']
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
            return
        mc_vrf = self.mc_data['vrf']

        if not self.mc_data['interfaces']:
            if self.get_interfaces_list():        # Получаем все интерфейсы группы шаблонов и заполняем: self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
                return
        mc_ifaces = self.mc_data['interfaces'].keys()

        if not self.mc_data['bfd_profiles']:
            if self.get_bfd_profiles():                # Получаем все профили BFD группы шаблонов и заполняем: self.mc_data['bfd_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
                return
        bfd_profiles = self.mc_data['bfd_profiles']
        bfd_profiles[-1] = BaseObject(id=-1, template_id='', template_name='')

        vrfnames = []
        for item in data:
            if item['name'] in vrfnames:
                self.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как VRF с таким именем уже был импортирован выше.')
                continue
            else:
                vrfnames.append(item['name'])

            if 'node_name' in item:
                if item['node_name'] != self.node_name:
                    self.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как имя узла в настройках не совпало с указанным.')
                    continue
            else:
                item['node_name'] = self.node_name

            vrf_name = f'{item["name"]}:{self.node_name}'
            if vrf_name in mc_vrf:
                if self.template_id != mc_vrf[vrf_name].template_id:
                    self.stepChanged.emit(f'sGREEN|    VRF "{item["name"]}" уже существует в шаблоне "{mc_vrf[vrf_name].template_name}" на узле кластера "{self.node_name}".')
                    continue

            new_interfaces = []
            for x in item['interfaces']:
                if f'{x}:{self.node_name}' in mc_ifaces:
                    new_interfaces.append(x)
                else:
                    self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Из VRF удалён интерфейс "{x}" так как отсутствует на узле кластера "{self.node_name}".')
                    error = 1
            item['interfaces'] = new_interfaces

            for x in item['routes']:
                x['name'] = self.get_transformed_name(x['name'], descr='Имя route')[1]
                if x['ifname'] != 'undefined':
                    if f'{x["ifname"]}:{self.node_name}' not in mc_ifaces:
                        if f'{x["ifname"]}:cluster' not in mc_ifaces:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс "{x["ifname"]}" удалён из статического маршрута "{x["name"]}" так как отсутствует на узле кластера "{self.node_name}".')
                            x['ifname'] = 'undefined'
                            error = 1

            if item['ospf']:
                # Переделываем для версии 7.4 со старых версий
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

                ids = set()
                new_interfaces = []
                for iface in item['ospf']['interfaces']:
                    iface['network_type'] = iface.get('network_type', '')   # Добавляем поле, отсутствующее с старых версиях
                    iface['is_passive'] = iface.get('is_passive', False)    # Добавляем поле, отсутствующее с старых версиях
                    if item['name'] != 'default' and iface['iface_id'] not in item['interfaces']:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс OSPF "{iface["iface_id"]}" удалён из настроек OSPF так как отсутствует в этом VRF.')
                        ids.add(iface['id'])
                        error = 1
                    else:
                        try:
                            iface['bfd_profile'] = bfd_profiles[iface['bfd_profile']].id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Для OSPF не найден профиль BFD {err}. Установлено значение по умолчанию.')
                            iface['bfd_profile'] = -1
                            error = 1
                        new_interfaces.append(iface)
                item['ospf']['interfaces'] = new_interfaces

                new_areas = []
                for area in item['ospf']['areas']:
                    err, result = self.unpack_ip_address(area['area_id'])
                    if err:
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

            if item['bgp']:
                for x in item['bgp']['neighbors']:
                    x['filter_in'] = []
                    x['filter_out'] = []
                    x['routemap_in'] = []
                    x['routemap_out'] = []
                    try:
                        x['bfd_profile'] = bfd_profiles[x['bfd_profile']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Для BGP не найден профиль BFD {err}. Установлено значение по умолчанию.')
                        x['bfd_profile'] = -1
                        error = 1
            if item['rip']:
                # Проверяем сети RIP
                new_networks = []
                for net in item['rip']['networks']:
                    if 'ifname' in net and net['ifname'] not in item['interfaces']:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Сеть RIP "{net["ifname"]}" удалёна из настроек RIP так как этот интерфейс отсутствует в этом VRF.')
                        error = 1
                    else:
                        new_networks.append(net)
                item['rip']['networks'] = new_networks
                # Проверяем интерфейсы RIP
                new_interfaces = []
                for iface in item['rip']['interfaces']:
                    if iface['name'] not in item['interfaces']:
                        self.stepChanged.emit(f'RED|    Error: [VRF "{item["name"]}"] Интерфейс RIP "{iface["name"]}" удалён из настроек RIP так как он отсутствует в этом VRF.')
                        error = 1
                    else:
                        new_interfaces.append(iface)
                item['rip']['interfaces'] = new_interfaces

            try:
                if vrf_name in mc_vrf:
                    self.stepChanged.emit(f'uGRAY|    VRF "{item["name"]}" уже существует в текущем шаблоне на узле кластера "{self.node_name}".')
                    err, result = self.utm.update_template_vrf(self.template_id, mc_vrf[vrf_name].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result} [VRF "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       VRF "{item["name"]}" обновлён.')
                else:
                    err, result = self.utm.add_template_vrf(self.template_id, item)
                    if err:
                        self.stepChanged.emit(f'RED|    {result} [VRF "{item["name"]}" не импортирован]')
                        error = 1
                    else:
                        mc_vrf[vrf_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                        self.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}" для узла кластера "{self.node_name}".')
            except OverflowError as err:
                self.stepChanged.emit(f'RED|    Произошла ошибка при импорте виртуального маршрутизатора "{item["name"]}" [{err}].')
                error = 1
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

        self.stepChanged.emit('BLUE|Импорт правил WCCP в раздел "Сеть/WCCP".')
        error = 0

        wccp_rules = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_wccp_rules(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил WCCP.')
                self.error = 1
                return
            for x in result:
                if x['name'] in wccp_rules:
                    self.stepChanged.emit(f'ORANGE|    Warning: Правило WCCP "{x["name"]}" обнаружено в нескольких шаблонах группы шаблонов. Правило из шаблона "{name}" не будет использовано.')
                else:
                    wccp_rules[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            item.pop('cc_network_devices', None)    # Если конфиг был экспортирован с МС.
            item.pop('cc_network_devices_negate', None)
            if item['routers']:
                routers = []
                for x in item['routers']:
                    if x[0] == 'list_id':
                        try:
                            x[1] = self.mc_data['ip_lists'][x[1]].id
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список {err} в группе шаблонов. Загрузите списки IP-адресов и повторите попытку.')
                            error = 1
                            continue
                    routers.append(x)
                item['routers'] = routers

            if item['name'] in wccp_rules:
                if self.template_id == wccp_rules[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Правило WCCP "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_wccp_rule(self.template_id, wccp_rules[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result} [Правило WCCP "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Правило WCCP "{item["name"]}" обновлено.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Правило WCCP "{item["name"]}" уже существует в шаблоне "{wccp_rules[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_wccp_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Правило WCCP "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" импортировано.')
                    wccp_rules[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил WCCP завершён.')


    #------------------------------------------ UserGate --------------------------------------------------
    def import_certificates(self, path):
        """Импортируем сертификаты"""
        self.stepChanged.emit('BLUE|Импорт сертификатов в раздел "UserGate/Сертификаты".')

        if not os.path.isdir(path):
            return
        certificates = {entry.name: entry.path for entry in os.scandir(path) if entry.is_dir()}
        if not certificates:
            self.stepChanged.emit('GRAY|    Нет сертификатов для импорта.')
            return
        error = 0
        mc_certs = self.mc_data['certs']

        for cert_name, cert_path in certificates.items():
            files = [entry.name for entry in os.scandir(cert_path) if entry.is_file()]

            json_file = os.path.join(cert_path, 'certificate_list.json')
            err, data = self.read_json_file(json_file)
            if err:
                continue

            if 'cert.pem' in files:
                with open(os.path.join(cert_path, 'cert.pem'), mode='rb') as fh:
                    cert_data = fh.read()
            elif 'cert.der' in files:
                with open(os.path.join(cert_path, 'cert.der'), mode='rb') as fh:
                    cert_data = fh.read()
            else:
                if data['name'] in mc_certs:
                    if self.template_id == mc_certs[data['name']].template_id:
                        message = f'       Cертификат "{cert_name}" не обновлён так как не найден файл сертификата "cert.pem" или "cert.der".'
                        self.stepChanged.emit(f'uGRAY|{message}\n    Сертификат "{cert_name}" уже существует в текущем шаблоне.')
                    else:
                        self.stepChanged.emit(f'sGREEN|    Cертификат "{cert_name}" уже существует в шаблоне "{mc_certs[data["name"]].template_name}".')
                    continue
                else:
                    self.stepChanged.emit(f'BLACK|    Не найден файл сертификата "{cert_name}" для импорта. Будет сгенерирован новый сертификат "{cert_name}".')
                    data.update(data['issuer'])
                    err, result = self.utm.new_template_certificate(self.template_id, data)
                    if err == 1:
                        self.stepChanged.emit(f'RED|       {result}')
                        error = 1
                    elif err == 3:
                        self.stepChanged.emit(f'GRAY|       {result}')
                    else:
                        self.mc_data['certs'][cert_name] = result
                        self.stepChanged.emit(f'BLACK|       Создан новый сертификат "{cert_name}". Назначьте роль новому сертификату')
                    continue

            if 'key.der' in files:
                with open(os.path.join(cert_path, 'key.der'), mode='rb') as fh:
                    key_data = fh.read()
            elif 'key.pem' in files:
                with open(os.path.join(cert_path, 'key.pem'), mode='rb') as fh:
                    key_data = fh.read()
            else:
                key_data = None

            if data['name'] in mc_certs:
                if self.template_id == mc_certs[data['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сертификат "{cert_name}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_certificate(self.template_id, mc_certs[data['name']].id, data, cert_data, private_key=key_data)
                    if err:
                        self.stepChanged.emit(f'RED|       {result} [Сертификат "{cert_name}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Cертификат "{cert_name}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Cертификат "{cert_name}" уже существует в шаблоне "{mc_certs[data["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_certificate(self.template_id, data, cert_data, private_key=key_data)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Сертификат "{cert_name}" не импортирован]')
                    error = 1
                else:
                    mc_certs[cert_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Сертификат "{cert_name}" импортирован.')
            self.msleep(1)
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте сертификатов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт сертификатов завершён.')


    def import_client_certificate_profiles(self, path):
        """Импортируем профили пользовательских сертификатов в шаблон"""
        json_file = os.path.join(path, 'users_certificate_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Профили клиентских сертификатов".')

        if not self.mc_data['client_certs_profiles']:
            if self.get_client_certificate_profiles(): # Заполняем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей клиентских сертификатов.')
                return

        error = 0
        client_certs_profiles = self.mc_data['client_certs_profiles']

        for item in data:
            if item['name'] in client_certs_profiles:
                if self.template_id == client_certs_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль клиентского сертификата "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль клиентского сертификата "{item["name"]}" уже существует в шаблоне "{client_certs_profiles[item["name"]].template_name}".')
            else:
                item['ca_certificates'] = [self.mc_data['certs'][x].id for x in item['ca_certificates']]

                err, result = self.utm.add_template_client_certificate_profile(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Профиль клиентского сертификата "{item["name"]}" не импортирован]')
                    error = 1
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}')
                else:
                    client_certs_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль клиентского сертификата "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей клиентских сертификатов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей клиентских сертификатов завершён.')


    def import_general_settings(self, path):
        """Импортируем раздел 'UserGate/Настройки'."""
        self.import_ui(path)
        self.import_ntp_settings(path)
        self.import_proxy_port(path)
        self.import_modules(path)
        self.import_cache_settings(path)
        self.import_proxy_exceptions(path)
        self.import_web_portal_settings(path)
        self.import_upstream_proxy_settings(path)
        self.import_upstream_update_proxy_settings(path)


    def import_ui(self, path):
        """Импортируем раздел UserGate/Настройки/Настройки интерфейса"""
        json_file = os.path.join(path, 'config_settings_ui.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')

        if not self.mc_data['client_certs_profiles']:
            if self.get_client_certificate_profiles(): # Заполняем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
                return

        params = {
            'ui_timezone': 'Часовой пояс',
            'ui_language': 'Язык интерфейса по умолчанию',
            'web_console_ssl_profile_id': 'Профиль SSL для веб-консоли',
            'response_pages_ssl_profile_id': 'Профиль SSL для страниц блокировки/аутентификации',
            'endpoint_ssl_profile_id': 'Профиль SSL конечного устройства',
            'endpoint_certificate_id': 'Сертификат конечного устройства',
            'webui_auth_mode': 'Режим аутентификации веб-консоли'
        }
        error = 0

        for key in data:
            if key in params:
                value = data[key]
                if key == 'webui_auth_mode':
                    if isinstance(value, dict):
                        if value['type'] == 'pki':
                            try:
                                value['client_certificate_profile_id'] = self.mc_data['client_certs_profiles'][value['client_certificate_profile_id']].id
                            except KeyError as err:
                                self.stepChanged.emit(f'RED|    Error: Не найден профиль клиентского сертификата {err} для "{params[key]}". Загрузите профили клиентских сертификатов и повторите попытку.')
                                error = 1
                                continue
                if key == 'web_console_ssl_profile_id':
                    try:
                        value = self.mc_data['ssl_profiles'][data[key]].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                if key == 'response_pages_ssl_profile_id':
                    try:
                        value = self.mc_data['ssl_profiles'][data[key]].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                if key == 'endpoint_ssl_profile_id':
                    try:
                        value = self.mc_data['ssl_profiles'][data[key]].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден профиль SSL {err} для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                        error = 1
                        continue
                if key == 'endpoint_certificate_id':
                    try:
                        value = self.mc_data['certs'][data[key]].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найден сертификат {err} для "{params[key]}". Загрузите сертификаты и повторите попытку.')
                        error = 1
                        continue
                setting = {}
                setting[key] = {'value': value}
                err, result = self.utm.set_template_settings(self.template_id, setting)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Параметр "{params[key]}" не импортирован]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    "{params[key]}" установлен в значение "{data[key]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек интерфейса.')
        else:
            self.stepChanged.emit('GREEN|    Импорт настроек интерфейса завершён.')


    def import_ntp_settings(self, path):
        """Импортируем настройки NTP в шаблон"""
        json_file = os.path.join(path, 'config_ntp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройки времени сервера".')
        error = 0

        for i, ntp_server in enumerate(data['ntp_servers']):
            settings = {f'ntp_server{i+1}': {'value': ntp_server, 'enabled': True}}
            err, result = self.utm.set_template_settings(self.template_id, settings)
            if err:
                self.stepChanged.emit(f'RED|    {result} [NTP-сервер "{ntp_server}" не импортирован]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    NTP-сервер "{ntp_server}" добавлен.')
            if i >= 1:
                break

        settings = {
            'ntp_enabled': {
                'value': data['ntp_enabled'],
                'enabled': True if data['ntp_synced'] else False
            }
        }
        err, result = self.utm.set_template_settings(self.template_id, settings)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Параметр "Использовать NTP" не установлен]')
            error = 1
        else:
            self.stepChanged.emit(f'BLACK|    Использование NTP {"включено" if data["ntp_enabled"] else "отключено"}.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произоша ошибка при импорте настроек NTP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов NTP завершён.')


    def import_proxy_port(self, path):
        """Импортируем HTTP(S)-прокси порт в шаблон"""
        json_file = os.path.join(path, 'config_proxy_port.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули/HTTP(S)-прокси порт".')

        err, result = self.utm.set_template_settings(self.template_id, {'proxy_server_port': {'value': data}})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте HTTP(S)-прокси порта.')
            self.error = 1
        else:
            self.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт установлен в значение "{data}"')


    def import_modules(self, path):
        """Импортируем модули"""
        json_file = os.path.join(path, 'config_settings_modules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули".')
        params = {
            'auth_captive': 'Домен Auth captive-портала',
            'logout_captive': 'Домен Logout captive-портала',
            'block_page_domain': 'Домен страницы блокировки',
            'ftpclient_captive': 'FTP поверх HTTP домен',
            'ftp_proxy_enabled': 'FTP поверх HTTP',
            'tunnel_inspection_zone_config': 'Зона для инспектируемых туннелей',
            'lldp_config': 'Настройка LLDP',
        }
        error = 0
    
        for key in data:
            if key in params:
                value = copy.deepcopy(data[key])
                if key == 'tunnel_inspection_zone_config':
                    try:
                        value['target_zone'] = self.mc_data['zones'][value['target_zone']].id
                        value.pop('cc', None)
                        data[key].pop('cc', None)   # Удаляем для корректного вывода в лог.
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: Не найдена зона {err} для "{params[key]}". Загрузите зоны и повторите попытку.')
                        error = 1
                        continue
                setting = {}
                setting[key] = {'value': value}
                err, result = self.utm.set_template_settings(self.template_id, setting)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Параметр "{params[key]}" не установлен]')
                    error = 1
                else:
                    self.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в знчение "{data[key]}".')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Импорт модулей прошёл с ошибками.')
        else:
            self.stepChanged.emit('GREEN|    Импорт модулей завершён.')


    def import_cache_settings(self, path):
        """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
        json_file = os.path.join(path, 'config_proxy_settings.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт разделов "Расширенные настройки" и "Настройки кэширования HTTP" из "UserGate/Настройки".')
        error = 0
        settings = {
            'Настройки кэширования HTTP': {
                'http_cache': {
                    'value': {},
                    'enabled': False if data['http_cache_mode'] == 'off' else True
                }
            },
            'Расширенные настройки': {
                'advanced': {
                    'value': {},
                    'enabled': False
                }
            }
        }
        for key, value in data.items():
            if key in {'http_cache_mode', 'http_cache_docsize_max', 'http_cache_precache_size'}:
                settings['Настройки кэширования HTTP']['http_cache']['value'][key] = value
            else:
                settings['Расширенные настройки']['advanced']['value'][key] = value
    
        for key in settings:
            err, result = self.utm.set_template_settings(self.template_id, settings[key])
            if err:
                self.stepChanged.emit(f'RED|    {result} [{key} не импортированы]')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    {key} импортированы.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек.')
        else:
            self.stepChanged.emit('GREEN|    Импортированы "Расширенные настройки" и "Настройки кэширования HTTP".')


    def import_proxy_exceptions(self, path):
        """Импортируем раздел UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования"""
        json_file = os.path.join(path, 'config_proxy_exceptions.json')
        err, exceptions = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования".')
        error = 0

        err, result = self.utm.get_template_nlists_list(self.template_id, 'httpcwl')
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте исключений кэширования HTTP.')
            self.error = 1
            return
        if result:
            list_id = result[0]['id']
        else:
            httpcwl_list = {'name': 'HTTP Cache Exceptions', 'type': 'httpcwl'}
            err, list_id = self.utm.add_template_nlist(self.template_id, httpcwl_list)
            if err:
                self.stepChanged.emit(f'RED|    {list_id}\n    Произошла ошибка при импорте исключений кэширования HTTP.')
                self.error = 1
                return
    
        for item in exceptions:
            err, result = self.utm.add_template_nlist_item(self.template_id, list_id, item)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result} [URL "{item["value"]}" не импортирован]')
                error = 1
            elif err == 3:
                self.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
            else:
                self.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

        if exceptions:
            err, result = self.utm.set_template_settings(self.template_id, {'http_cache_exceptions': {'enabled': True}})
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при установке статуса исключения кэширования.')
                error = 1
            else:
                self.stepChanged.emit(f'BLACK|    Исключения кэширования включено.')

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте исключений кэширования HTTP.')
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

        response_pages = self.mc_data['response_pages']

        if not self.mc_data['client_certs_profiles']:
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек Веб-портала.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        try:
            data['user_auth_profile_id'] = self.mc_data['auth_profiles'][data['user_auth_profile_id']].id
        except KeyError as err:
            message = f'    Error: Не найден профиль аутентификации {err}. Загрузите профили аутентификации и повторите попытку.'
            self.stepChanged.emit(f'RED|{message}\n    Произошла ошибка при импорте настроек Веб-портала.')
            self.error = 1
            return

        try:
            data['ssl_profile_id'] = self.mc_data['ssl_profiles'][data['ssl_profile_id']].id
        except KeyError as err:
            message = f'    Error: Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.'
            self.stepChanged.emit(f'RED|{massage}\n    Произошла ошибка при импорте настроек Веб-портала.')
            self.error = 1
            return

        if data['client_certificate_profile_id']:
            try:
                data['client_certificate_profile_id'] = client_certs_profiles[data['client_certificate_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден профиль клиентского сертификата {err}. Укажите его вручную или загрузите профили клиентских сертификатов и повторите попытку.')
                data['client_certificate_profile_id'] = 0
                data['cert_auth_enabled'] = False
                error = 1

        if data['certificate_id']:
            try:
                data['certificate_id'] = self.mc_data['certs'][data['certificate_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден сертификат {err}. Укажите сертификат вручную или загрузите сертификаты и повторите попытку.')
                data['certificate_id'] = -1
                error = 1
        else:
            data['certificate_id'] = -1

        if data['proxy_portal_template_id'] != -1:
            try:
                data['proxy_portal_template_id'] = response_pages[data['proxy_portal_template_id']].id
            except KeyError as err:
                data['proxy_portal_template_id'] = -1
                self.stepChanged.emit(f'RED|    Error: Не найден шаблон портала {err}. Укажите шаблон портала вручную или загрузите шаблоны страниц и повторите попытку.')
                error = 1

        if data['proxy_portal_login_template_id'] != -1:
            try:
                data['proxy_portal_login_template_id'] = response_pages[data['proxy_portal_login_template_id']].id
            except KeyError as err:
                data['proxy_portal_login_template_id'] = -1
                self.stepChanged.emit(f'RED|    Error: Не найден шаблон страницы аутентификации {err}. Укажите её вручную или загрузите шаблоны страниц и повторите попытку.')
                error = 1

        settings = {
            'proxy_portal': {
                'value': data,
                'enabled': False if not data['enabled'] else True
            }
        }
    
        err, result = self.utm.set_template_settings(self.template_id, settings)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]\n    Произошла ошибка при импорте настроек Веб-портала.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Веб-портал".')


    def import_upstream_proxy_settings(self, path):
        """Импортируем настройки вышестоящего прокси"""
        json_file = os.path.join(path, 'upstream_proxy_settings.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

        settings = {
            'upstream_proxy': {
                'value': data,
                'enabled': False if not data['enabled'] else True
            }
        }
    
        err, result = self.utm.set_template_settings(self.template_id, settings)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]\n    Произошла ошибка при импорте настроек вышестоящего прокси.')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Настройки вышестоящего прокси импортировны.')


    def import_upstream_update_proxy_settings(self, path):
        """Импортируем настройки вышестоящего прокси для проверки лицензий и обновлений"""
        json_file = os.path.join(path, 'upstream_update_proxy.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси для проверки лицензий и обновлений".')

        settings = {
            'upstream_update_proxy': {
                'value': data,
                'enabled': False if not data['enabled'] else True
            }
        }
    
        err, result = self.utm.set_template_settings(self.template_id, settings)
        if err:
            message = 'Произошла ошибка при импорте настроек вышестоящего прокси для проверки лицензий и обновлений.'
            self.stepChanged.emit(f'RED|    {result} [Настройки не импортированы]\n    {message}')
            self.error = 1
        else:
            self.stepChanged.emit('GREEN|    Импортированы настройки вышестоящего прокси для проверки лицензий и обновлений".')


    def import_administrators(self, path):
        """Импортируем профили администраторов и список администраторов."""
        self.stepChanged.emit('BLUE|Импорт раздела "UserGate/Администраторы".')
        error = 0

        # Импортируем настройки аутентификации.
        json_file = os.path.join(path, 'auth_settings.json')
        err, auth_config = self.read_json_file(json_file, mode=2)
        if err:
            return
        err, result = self.utm.set_template_admin_config(self.template_id, auth_config)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Настройки аутентификации не импортированы.')
            error = 1
        else:
            self.stepChanged.emit('BLACK|    Импортированы настройки аутентификации.')

        # Импортируем профили администраторов.
        admin_profiles = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_admins_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей администраторов.')
                self.error = 1
                return
            for x in result:
                if x['name'] in admin_profiles:
                    self.stepChanged.emit(f'ORANGE|    Профиль администраторов "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    admin_profiles[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        json_file = os.path.join(path, 'administrator_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in admin_profiles:
                if self.template_id == admin_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль администраторов "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль администраторов "{item["name"]}" уже существует в шаблоне "{admin_profiles[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_admins_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Профиль администратора "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    admin_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль администратора "{item["name"]}" импортирован.')

        # Импортируем администраторов.
        err, result = self.utm.get_template_admins(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте администраторов.')
            self.error = 1
            return
        admins = {x['login']: x['id'] for x in result}

        json_file = os.path.join(path, 'administrators_list.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        for item in data:
            if item['is_root']:
                continue
            if item['type'] == 'auth_profile':
                item['display_name'] = item['login']
                try:
                    item['user_auth_profile_id'] = self.mc_data['auth_profiles'][item['user_auth_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Администратор "{item["login"]}" не импортирован] Нет найден профиль аутентификации "{item["user_auth_profile_id"]}".')
                    error = 1
                    continue
            else:
                item.pop('user_auth_profile_id', None)
                item.pop('locked', None)
                item.pop('is_root', None)
                item.pop('password', None)

            if item['type'] == 'local':
                item['login'] = self.get_transformed_userlogin(item['login'])
                item['display_name'] = item['login']
                item['password'] = 'Q12345678@'
            if item['type'] in ['ldap_user', 'ldap_group']:
                if item['type'] == 'ldap_user':
                    ldap_domain, _, login_name = item['login'].partition("\\")
                    item['display_name'] = f'{login_name} ({item["login"]})'
                else:
                    tmp_arr1 = [x.split('=') for x in item['login'].split(',')]
                    tmp_arr2 = [b for a, b in tmp_arr1 if a in ('dc', 'DC')]
                    ldap_domain = '.'.join(tmp_arr2)
                    login_name = tmp_arr1[0][1] if tmp_arr1[0][0] == 'CN' else None
                    item['display_name'] = f'{login_name} ({ldap_domain}\\{login_name})'
                if login_name:
                    try:
                        ldap_id = self.mc_data['ldap_servers'][ldap_domain.lower()]
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [Администратор "{item["display_name"]}" не импортирован.] Нет LDAP-коннектора для домена "{ldap_domain}".')
                        error = 1
                        continue

                    if item['type'] == 'ldap_user':
                        err, result = self.utm.get_usercatalog_ldap_user_guid(ldap_id, login_name)
                    else:
                        err, result = self.utm.get_usercatalog_ldap_group_guid(ldap_id, login_name)
                    if err:
                        self.stepChanged.emit(f'RED|    {result}\n       Администратор "{item["display_name"]}" не импортирован.')
                        error = 1
                        continue
                    elif not result:
                        self.stepChanged.emit(f'RED|    Error: [Администратор "{item["display_name"]}" не импортирован] Нет такого пользователя в домене или LDAP-коннектора для домена "{ldap_domain}".')
                        error = 1
                        continue
                    else:
                        item['guid'] = result
                else:
                    self.stepChanged.emit(f'RED|    Error: [Администратор "{item["login"]}" не импортирован] Нет такого пользователя в домене "{ldap_domain}".')
                    error = 1
                    continue

            item['profile_id'] = admin_profiles[item['profile_id']].id
            if item['login'] in admins:
                self.stepChanged.emit(f'uGRAY|    Администратор "{item["display_name"]}" уже существует в текущем шаблоне.')
            else:
                err, result = self.utm.add_template_admin(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Администратор "{item["display_name"]}" не импортирован]')
                    error = 1
                else:
                    admins[item['login']] = result
                    self.stepChanged.emit(f'BLACK|    Администратор "{item["display_name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте раздела "UserGate/Администраторы".')
        else:
            self.stepChanged.emit('GREEN|    Импорт раздела "UserGate/Администраторы" завершён.')
            self.stepChanged.emit('LBLUE|    Установите пароли для локальных администраторов.')


    #------------------------------------ Пользователи и устройства -------------------------------------------------
    def import_local_groups(self, path):
        """Импортируем список локальных групп пользователей"""
        json_file = os.path.join(path, 'config_groups.json')
        err, groups = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
        self.stepChanged.emit(f'LBLUE|    Если используются доменные пользователи, необходимы настроенные LDAP-коннекторы в "Управление областью/Каталоги пользователей"')
        error = 0

        local_groups = self.mc_data['local_groups']

        for item in groups:
            users = item.pop('users')
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя группы')
            if item['name'] in local_groups:
                if self.template_id == local_groups[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Группа пользователей "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Группа пользователей "{item["name"]}" уже существует в шаблоне "{local_groups[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_group(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Группа пользователей "{item["name"]}" не импортирована]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}') # В версиях 6 и выше проверяется что группа уже существует.
                else:
                    local_groups[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Группа пользователей "{item["name"]}" импортирована.')

            # Добавляем доменных пользователей в группу.
            self.stepChanged.emit(f'NOTE|       Добавляем доменных пользователей в группу "{item["name"]}".')
            n = 0
            for user_name in users:
                user_array = user_name.split(' ')
                if len(user_array) > 1 and ('\\' in user_array[1]):
                    n += 1
                    domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                    try:
                        ldap_id = self.mc_data['ldap_servers'][domain.lower()]
                    except KeyError:
                        self.stepChanged.emit(f'bRED|       Warning: Доменный пользователь "{user_name}" не импортирован в группу "{item["name"]}". Нет LDAP-коннектора для домена "{domain}".')
                    else:
                        err1, result1 = self.utm.get_usercatalog_ldap_user_guid(ldap_id, name)
                        if err1:
                            self.stepChanged.emit(f'RED|       {result1}')
                            error = 1
                            continue
                        elif not result1:
                            self.stepChanged.emit(f'bRED|       Warning: Нет пользователя "{user_name}" в домене "{domain}". Доменный пользователь не импортирован в группу "{item["name"]}".')
                            continue
                        err2, result2 = self.utm.add_user_in_template_group(self.template_id, local_groups[item['name']].id, result1)
                        if err2:
                            self.stepChanged.emit(f'RED|       {result2}  [{user_name}]')
                            error = 1
                        else:
                            self.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
            if not n:
                self.stepChanged.emit(f'GRAY|       Нет доменных пользователей в группе "{item["name"]}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных групп пользователей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт групп пользователей завершён.')


    def import_local_users(self, path):
        """Импортируем локальных пользователей и добавляем их в группы"""
        json_file = os.path.join(path, 'config_users.json')
        err, users = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
        error = 0
        local_users = self.mc_data['local_users']

        for item in users:
            user_groups = item.pop('groups', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя пользователя')
            item['auth_login'] = self.get_transformed_userlogin(item['auth_login'])

            if item['name'] in local_users:
                if self.template_id == local_users[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Пользователь "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Пользователь "{item["name"]}" уже существует в шаблоне "{local_users[item["name"]].template_name}".')
                    continue
            else:
                err, result = self.utm.add_template_user(self.template_id, item)
                if err == 1:
                    self.stepChanged.emit(f'RED|    {result} [Пользователь "{item["name"]}" не импортирован]')
                    error = 1
                    continue
                elif err == 3:
                    self.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
                else:
                    local_users[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Локальный пользователь "{item["name"]}" импортирован.')

            # Добавляем пользователя в группу.
            for group in user_groups:
                try:
                    group_guid = self.mc_data['local_groups'][group].id
                except KeyError as err:
                    self.stepChanged.emit(f'bRED|       Warning: Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
                else:
                    err2, result2 = self.utm.add_user_in_template_group(self.template_id, group_guid, local_users[item['name']].id)
                    if err2:
                        self.stepChanged.emit(f'RED|       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей.')
        else:
            self.stepChanged.emit('GREEN|    Импорт локальных пользователей завершён.')


    def import_auth_servers(self, path):
        """Импортируем список серверов аутентификации"""
        self.stepChanged.emit('BLUE|Импорт раздела "Пользователи и устройства/Серверы аутентификации".')

        if not self.mc_data['auth_servers']:
            if self.get_auth_servers():    # Устанавливаем self.mc_data['auth_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов аутентификации.')
                return
        auth_servers = self.mc_data['auth_servers']

        self.import_ldap_servers(path, auth_servers['ldap'])
        self.import_ntlm_server(path, auth_servers['ntlm'])
        self.import_radius_server(path, auth_servers['radius'])
        self.import_tacacs_server(path, auth_servers['tacacs_plus'])
        self.import_saml_server(path, auth_servers['saml_idp'])
    

    def import_ldap_servers(self, path, ldap_servers):
        """Импортируем список серверов LDAP"""
        json_file = os.path.join(path, 'config_ldap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта Необходимо ввести пароль и импортировать keytab файл в LDAP-коннекторы.')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in ldap_servers:
                if self.template_id == ldap_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       LDAP-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       LDAP-сервер "{item["name"]}" уже существует в шаблоне "{ldap_servers[item["name"]].template_name}".')
            else:
                item['keytab_exists'] = False
                item['type'] = 'ldap'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [LDAP-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ldap_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации LDAP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов LDAP завершён.')


    def import_ntlm_server(self, path, ntlm_servers):
        """Импортируем список серверов NTLM"""
        json_file = os.path.join(path, 'config_ntlm_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in ntlm_servers:
                if self.template_id == ntlm_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       NTLM-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       NTLM-сервер "{item["name"]}" уже существует в шаблоне "{ntlm_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'ntlm'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [NTLM-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ntlm_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации NTLM "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов NTLM завершён.')


    def import_radius_server(self, path, radius_servers):
        """Импортируем список серверов RADIUS"""
        json_file = os.path.join(path, 'config_radius_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта необходимо ввести пароль на серверах RADIUS.')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in radius_servers:
                if self.template_id == radius_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       RADIUS-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       RADIUS-сервер "{item["name"]}" уже существует в шаблоне "{radius_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'radius'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [RADIUS-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    radius_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов RADIUS завершён.')


    def import_tacacs_server(self, path, tacacs_servers):
        """Импортируем список серверов TACACS+"""
        json_file = os.path.join(path, 'config_tacacs_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта необходимо ввести секретный ключ на серверах TACACS+ .')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in tacacs_servers:
                if self.template_id == tacacs_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       TACACS-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       TACACS-сервер "{item["name"]}" уже существует в шаблоне "{tacacs_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'tacacs_plus'
                item.pop("cc", None)
                err, result = self.utm.add_template_auth_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Сервер TACACS+ "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    tacacs_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверов TACACS+ завершён.')


    def import_saml_server(self, path, saml_servers):
        """Импортируем список серверов SAML"""
        json_file = os.path.join(path, 'config_saml_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|    Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
        self.stepChanged.emit(f'LBLUE|       После импорта необходимо  загрузить SAML metadata на каждый сервер SAML.')
        error = 0

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in saml_servers:
                if self.template_id == saml_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|       SAML-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|       SAML-сервер "{item["name"]}" уже существует в шаблоне "{saml_servers[item["name"]].template_name}".')
            else:
                item['type'] = 'saml_idp'
                item.pop("cc", None)
                if item['certificate_id']:
                    try:
                        item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                    except KeyError:
                        self.stepChanged.emit(f'RED|       Error: [Сервер SAML "{item["name"]}"] Не найден сертификат "{item["certificate_id"]}".')
                        item['certificate_id'] = 0
                        error = 1
                err, result = self.utm.add_template_auth_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Сервер SAML "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    saml_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|       Сервер аутентификации SAML "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML.')
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

        if not self.mc_data['notification_profiles']:
            if self.get_notification_profiles():      # Устанавливаем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
                return
        notification_profiles = self.mc_data['notification_profiles']

        if not self.mc_data['profiles_2fa']:
            if self.get_profiles_2fa():      # Устанавливаем self.mc_data['profiles_2fa']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
                return
        profiles_2fa = self.mc_data['profiles_2fa']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in profiles_2fa:
                if self.template_id == profiles_2fa[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль MFA "{item["name"]}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль MFA "{item["name"]}" уже существует в шаблоне "{profiles_2fa[item["name"]].template_name}".')
            else:
                if item['type'] == 'totp':
                    if item['init_notification_profile_id'] not in notification_profiles:
                        self.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                        error = 1
                        continue
                    item['init_notification_profile_id'] = notification_profiles[item['init_notification_profile_id']].id
                else:
                    if item['auth_notification_profile_id'] not in notification_profiles:
                        self.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                        error = 1
                        continue
                    item['auth_notification_profile_id'] = notification_profiles[item['auth_notification_profile_id']].id

                err, result = self.utm.add_template_2fa_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    profiles_2fa[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['auth_servers']:
            if self.get_auth_servers():    # Устанавливаем self.mc_data['auth_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
                return
        auth_servers = self.mc_data['auth_servers']

        if not self.mc_data['profiles_2fa']:
            if self.get_profiles_2fa():      # Устанавливаем self.mc_data['profiles_2fa']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
                return
        profiles_2fa = self.mc_data['profiles_2fa']

        auth_profiles = self.mc_data['auth_profiles']
        auth_type = {
            'ldap': 'ldap_server_id',
            'radius': 'radius_server_id',
            'tacacs_plus': 'tacacs_plus_server_id',
            'ntlm': 'ntlm_server_id',
            'saml_idp': 'saml_idp_server_id'
        }

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['2fa_profile_id']:
                try:
                    item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Профиль аутентификации "{item["name"]}"] Не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                    item['2fa_profile_id'] = False
                    error = 1

            for auth_method in item['allowed_auth_methods']:
                if len(auth_method) == 2:
                    method_type = auth_method['type']
                    method_server_id = auth_type[method_type]
                    try:
                        auth_method[method_server_id] = auth_servers[method_type][auth_method[method_server_id]].id
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [Профиль аутентификации "{item["name"]}"] Не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                        auth_method.clear()
                        error = 1
            item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

            if item['name'] in auth_profiles:
                if self.template_id == auth_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_auth_profile(self.template_id, auth_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Profile: "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль аутентификации "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль аутентификации "{item["name"]}" уже существует в шаблоне "{auth_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_auth_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result} [Профиль аутентификации "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    auth_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        response_pages = self.mc_data['response_pages']

        if not self.mc_data['notification_profiles']:
            if self.get_notification_profiles():       # Устанавливаем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        notification_profiles = self.mc_data['notification_profiles']

        if not self.mc_data['client_certs_profiles']:
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        if not self.mc_data['captive_profiles']:
            if self.get_captive_profiles():            # Устанавливаем self.mc_data['captive_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return
        captive_profiles = self.mc_data['captive_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            item['captive_template_id'] = response_pages[item['captive_template_id']].id
            try:
                item['user_auth_profile_id'] = self.mc_data['auth_profiles'][item['user_auth_profile_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["user_auth_profile_id"]}".'
                item['user_auth_profile_id'] = 1
                error = 1

            if item['notification_profile_id'] != -1:
                try:
                    item['notification_profile_id'] = notification_profiles[item['notification_profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль оповещения "{item["notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль оповещения "{item["notification_profile_id"]}".'
                    item['notification_profile_id'] = -1
                    error = 1
            try:
                item['ta_groups'] = [self.mc_data['local_groups'][name].id for name in item['ta_groups']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Группа гостевых пользователей {err} не найдена в группе шаблонов. Загрузите локальные группы и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа гостевых пользователей {err}.'
                item['ta_groups'] = []
                error = 1

            if item['ta_expiration_date']:
                item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
            else:
                item.pop('ta_expiration_date', None)

            item.pop('use_https_auth', None)
            if item['captive_auth_mode'] != 'aaa':
                try:
                    item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Captive-profile "{item["name"]}"] Не найден профиль сертификата пользователя {err}. Загрузите профили сертификата пользователя и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                    item['captive_auth_mode'] = 'aaa'
                    item['client_certificate_profile_id'] = 0
                    error = 1

            if item['name'] in captive_profiles:
                if self.template_id == captive_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Captive-профиль "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_captive_profile(self.template_id, captive_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Captive-profile "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Captive-профиль "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Captive-профиль "{item["name"]}" уже существует в шаблоне "{captive_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_captive_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Captive-profile "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    captive_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['captive_profiles']:
            if self.get_captive_profiles():            # Устанавливаем self.mc_data['captive_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
                return
        captive_profiles = self.mc_data['captive_profiles']

        captive_portal_rules = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_captive_portal_rules(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил Captive-портала.')
                self.error = 1
                return
            for x in result:
                captive_portal_rules[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)
            if item['profile_id']:
                try:
                    item['profile_id'] = captive_profiles[item['profile_id']].id
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Captive-portal "{item["name"]}"] Captive-профиль "{item["profile_id"]}" не найден. Загрузите Captive-профили и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден Captive-профиль "{item["profile_id"]}".'
                    item['profile_id'] = 0
                    error = 1
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['time_restrictions'] = self.get_time_restrictions(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in captive_portal_rules:
                if self.template_id == captive_portal_rules[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Правило Captive-портала "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_captive_portal_rule(self.template_id, captive_portal_rules[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Captive-portal "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Правило Captive-портала "{item["name"]}" обновлено.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Правило Captive-портала "{item["name"]}" уже существует в шаблоне "{captive_portal_rules[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_captive_portal_rule(self.template_id, item)
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
        terminal_servers = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_terminal_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте списка терминальных серверов.')
                self.error = 1
                return
            for x in result:
                if x['name'] in terminal_servers:
                    self.stepChanged.emit('ORANGE|    Терминальный сервер обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
                else:
                    terminal_servers[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in terminal_servers:
                if self.template_id == terminal_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_terminal_server(self.template_id, terminal_servers[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Terminal Server "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Терминальный сервер "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Терминальный сервер "{item["name"]}" уже существует в шаблоне "{terminal_servers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_terminal_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    terminal_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте терминальных серверов.')
        else:
            self.stepChanged.emit('GREEN|    Импорт терминальных серверов завершён.')


    def import_userid_agent(self, path):
        """Импортируем настройки UserID агент"""
        if self.utm.float_version in (7.1, 8.0):
            self.import_agent_config_old_version(path)
            self.import_agent_servers_old(path)
        else:
            self.import_agent_config(path)
            self.import_agent_servers(path)


    def import_agent_config_old_version(self, path):
        """Импортируем настройки UserID агент (для версий МС 7.1 и 8.0)"""
        json_file = os.path.join(path, 'userid_agent_config.json')
        err, result = self.read_json_file(json_file, mode=2)
        if err:
            return

        error = 0
        self.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/Агент UserID".')
        self.stepChanged.emit(f'NOTE|    В МС версии {self.utm.float_version} не возможно указать сертификаты для TCP.')

        try:
            data = result[0]
        except Exception:
            self.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте свойств агента UserID. Ошибка формата файла конфигурации.')
            self.error = 1
            return

        data.pop('tcp_ca_certificate_id', None)
        data.pop('tcp_server_certificate_id', None)
        data.pop('radius_monitoring_interval', None)
        data['tcp_secure'] = False
        data['expiration_time'] = 2700

        new_networks = []
        for x in data['ignore_networks']:
            try:
                new_networks.append(['list_id', self.mc_data['ip_lists'][x[1]].id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
                error = 1
        data['ignore_networks'] = new_networks

        err, result = self.utm.set_template_useridagent_config(self.template_id, data)
        if err:
            self.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не импортированы]')
            error = 1

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте свойств агента UserID.')
        else:
            self.stepChanged.emit('GREEN|    Свойства агента UserID обновлены.')


    def import_agent_config(self, path):
        """Импортируем настройки UserID агент"""
        json_file = os.path.join(path, 'userid_agent_config.json')
        err, config_data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/Агент UserID".')
        json_file = os.path.join(self.config_path, 'version.json')
        err, source_version = self.read_json_file(json_file, mode=2)
        if err:
            if err == 1:
                self.stepChanged.emit(f'RED|Error: Проблема с файлом {json_file} при импорте свойств агента UserID.\n{source_version}')
                self.error = 1
                return
            source_version = {'device': 'NGFW', 'float_version': 7.1}

        error = 0
        
        useridagent_config = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_useridagent_config(uid)
            if err:
                self.stepChanged.emit('RED|    {result}\n       Произошла ошибка при импорте свойств агента UserID.')
                self.error = 1
                return
            for x in result:
                if x['name'] in useridagent_config:
                    self.stepChanged.emit('ORANGE|    Свойство агента UserID для узла кластера "{x["name"]}" обнаружено в нескольких шаблонах группы шаблонов. Свойство из шаблона "{name}" не будет использовано.')
                else:
                    useridagent_config[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        if source_version['device'] == 'MC' and source_version['float_version'] == 7.2:
            for data in config_data:
                error = self.set_useridagent_config(data, useridagent_config)
        else:
            try:
                data = config_data[0]
            except Exception:
                self.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте свойств агента UserID. Ошибка файла конфигурации.')
                self.error = 1
                return
            data['name'] = self.node_name
            error = self.set_useridagent_config(data, useridagent_config)

        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте свойств агента UserID.')
        else:
            self.stepChanged.emit('GREEN|    Импорт свойств агента UserID завершён.')


    def set_useridagent_config(self, data, useridagent_config):
        error = 0
        if data['tcp_ca_certificate_id']:
            try:
                data['tcp_ca_certificate_id'] = self.mc_data['certs'][data['tcp_ca_certificate_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден сертификат {err}. Загрузите сертификаты и повторите попытку.')
                data.pop('tcp_ca_certificate_id', None)
                error = 1
        else:
            data.pop('tcp_ca_certificate_id', None)

        if data['tcp_server_certificate_id']:
            try:
                data['tcp_server_certificate_id'] = self.mc_data['certs'][data['tcp_server_certificate_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден сертификат УЦ "{err}". Загрузите сертификаты и повторите попытку.')
                data.pop('tcp_server_certificate_id', None)
                error = 1
        else:
            data.pop('tcp_server_certificate_id', None)

        new_networks = []
        for x in data['ignore_networks']:
            try:
                new_networks.append(['list_id', self.mc_data['ip_lists'][x[1]].id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
                error = 1
        data['ignore_networks'] = new_networks

        if self.node_name in useridagent_config:
            if self.template_id == useridagent_config[self.node_name].template_id:
                self.stepChanged.emit(f'uGRAY|    Свойства агента UserID для узла "{self.node_name}" уже существуют в текущем шаблоне.')
                err, result = self.utm.update_template_useridagent_config(self.template_id, useridagent_config[data['name']].id, data)
                if err:
                    self.stepChanged.emit(f'RED|       {result} [Свойства агента UserID не обновлены]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Свойства агента UserID для узла "{self.node_name}" обновлены')
            else:
                self.stepChanged.emit(f'sGREEN|    Свойства агента UserID для узла "{self.node_name}" уже существует в шаблоне "{useridagent_config[self.node_name].template_name}".')
        else:
            err, result = self.utm.set_template_useridagent_config(self.template_id, data)
            if err:
                self.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не установлены]')
                error = 1
            else:
                useridagent_config[data['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                self.stepChanged.emit(f'BLACK|    Свойства агента UserID для узла "{self.node_name}" импортированы')
        return error


    def import_agent_servers_old(self, path):
        """Импортируем настройки AD и свойств отправителя syslog UserID агент (для версий МС 7.1 и 8.0)"""
        json_file = os.path.join(path, 'userid_agent_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
        self.stepChanged.emit(f'LBLUE|    Фильтры для коннеторов Syslog Агентов UserID в этой версии МС не переносятся. Необходимо добавить их руками.')
        error = 0

        useridagent_servers = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_useridagent_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте агентов UserID.')
                self.error = 1
                return
            for x in result:
                if x['name'] in useridagent_servers:
                    self.stepChanged.emit(f'ORANGE|    Коннектор UserID агента "{x["name"]}" для узла "{x["node_name"]}" обнаружен в нескольких шаблонах группы шаблонов. Коннектор из шаблона "{name}" не будет использован.')
                else:
                    useridagent_servers[x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            if item['type'] == 'radius':
                self.stepChanged.emit(f'NOTE|    Warning: Коннектор UserID агент "{item["name"]}" не импортирован так как RADIUS поддерживается только в версии МС-7.2 и выше.')
                continue
            item.pop('expiration_time', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя UserID')

            if item['name'] in useridagent_servers:
                if self.template_id == useridagent_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" уже существует в шаблоне "{useridagent_servers[item["name"]].template_name}".')
                    continue
            try:
                item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
                item['auth_profile_id'] = 1
                error = 1
            if 'filters' in item:
                self.stepChanged.emit(f'rNOTE|    Warning: [UserID агент "{item["name"]}"] Не импортированы Syslog фильтры. В вашей версии МС API для этого не работают.')
                for filter_name in item['filters']:
                    item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
                item['filters'] = []

            if item['name'] in useridagent_servers:
                err, result = self.utm.update_template_useridagent_server(self.template_id, useridagent_servers[item['name']].id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}" не обновлён]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" обновлён.')
            else:
                err, result = self.utm.add_template_useridagent_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" не импортирован]')
                    error = 1
                else:
                    useridagent_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" импортирован.')
            if item['type'] == 'ad':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннектора Microsoft AD.')
            elif item['type'] == 'radius':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннектора RADIUS.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
        else:
            self.stepChanged.emit('GREEN|    Импорт агентов UserID завершён.')


    def import_agent_servers(self, path):
        """Импортируем коннекторы UserID агент"""
        json_file = os.path.join(path, 'userid_agent_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
        self.stepChanged.emit(f'LBLUE|    Фильтры для коннеторов Syslog Агентов UserID в этой версии МС не переносятся. Необходимо добавить их руками.')
        error = 0

        if not self.mc_data['userid_filters']:
            if self.get_useridagent_filters():      # Заполняем self.mc_data['userid_filters']
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте агентов UserID.')
                return
        userid_filters = self.mc_data['userid_filters']

        useridagent_servers = {}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_useridagent_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте агентов UserID.')
                self.error = 1
                return
            for x in result:
                srv_name = f'{x["name"]}:{x["node_name"]}'
                if srv_name in useridagent_servers:
                    self.stepChanged.emit(f'ORANGE|    Коннектор UserID агента "{x["name"]}" для узла "{x["node_name"]}" обнаружен в нескольких шаблонах группы шаблонов. Коннектор из шаблона "{name}" не будет использован.')
                else:
                    useridagent_servers[srv_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя')
            item['node_name'] = self.node_name
            srv_name = f'{item["name"]}:{self.node_name}'
            if srv_name in useridagent_servers:
                if self.template_id == useridagent_servers[srv_name].template_id:
                    self.stepChanged.emit(f'uGRAY|    Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" уже существует в текущем шаблоне.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" уже существует в шаблоне "{useridagent_servers[srv_name].template_name}".')
                    continue
            try:
                item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']].id
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
                item['auth_profile_id'] = 1
                error = 1
            if 'filters' in item:
                new_filters = []
                for filter_name in item['filters']:
                    try:
                        new_filters.append(userid_filters[filter_name].id)
                    except KeyError:
                        self.stepChanged.emit(f'RED|    Error: [UserID агент "{item["name"]}"] Не найден Syslog фильтр "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
                        error = 1
                item['filters'] = new_filters

            if srv_name in useridagent_servers:
                err, result = self.utm.update_template_useridagent_server(self.template_id, useridagent_servers[srv_name].id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}" не обновлён]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" обновлён.')
            else:
                err, result = self.utm.add_template_useridagent_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" не импортирован]')
                    error = 1
                else:
                    useridagent_servers[srv_name] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Коннектор UserID агент "{item["name"]}" для узла "{self.node_name}" импортирован.')
            if item['type'] == 'ad':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннектора Microsoft AD.')
            elif item['type'] == 'radius':
                self.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннектора RADIUS.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте агентов UserID.')
        else:
            self.stepChanged.emit('GREEN|    Импорт раздела "Агенты UserID" завершён.')


#-------------------------------------- Политики сети ---------------------------------------------------------
    def import_firewall_rules(self, path):
        """Импортируем правила межсетевого экрана"""
        json_file = os.path.join(path, 'config_firewall_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

        if not self.mc_data['idps_profiles']:
            if self.get_idps_profiles():            # Устанавливаем self.mc_data['idps_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                return
        idps_profiles = self.mc_data['idps_profiles']

        if not self.mc_data['l7_profiles']:
            if self.get_l7_profiles():            # Устанавливаем self.mc_data['l7_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                return
        l7_profiles = self.mc_data['l7_profiles']

        if not self.mc_data['hip_profiles']:
            if self.get_hip_profiles():            # Устанавливаем self.mc_data['hip_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
                return
        hip_profiles = self.mc_data['hip_profiles']

        err, result = self.utm.get_template_firewall_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил межсетевого экрана.')
            self.error = 1
            return
        firewall_rules = {x['name']: x['id'] for x in result}

        error = 0
        for item in data:
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item.pop('apps', None)
            item.pop('apps_negate', None)

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True
            if 'ips_profile' in item and item['ips_profile']:
                try:
                    item['ips_profile'] = idps_profiles[item['ips_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
                    item['ips_profile'] = False
                    item['error'] = True
            else:
                item['ips_profile'] = False
            if 'l7_profile' in item and item['l7_profile']:
                try:
                    item['l7_profile'] = l7_profiles[item['l7_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль приложений {err}. Загрузите профили приложений и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                    item['l7_profile'] = False
                    item['error'] = True
            else:
                item['l7_profile'] = False
            if 'hip_profiles' in item:
                new_hip_profiles = []
                for hip in item['hip_profiles']:
                    try:
                        new_hip_profiles.append(hip_profiles[hip].id)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль HIP {err}. Загрузите профили HIP и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                        item['error'] = True
                item['hip_profiles'] = new_hip_profiles
            else:
                item['hip_profiles'] = []

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in firewall_rules:
                self.stepChanged.emit(f'uGRAY|    Правило МЭ "{item["name"]}" уже существует.')
                item.pop('position', None)
                err, result = self.utm.update_template_firewall_rule(self.template_id, firewall_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило МЭ "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило МЭ "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_firewall_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило МЭ "{item["name"]}" не импортировано]')
                else:
                    firewall_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|   Правило МЭ "{item["name"]}" импортировано.')
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

        if not self.mc_data['gateways']:
            if self.get_gateways_list():            # Устанавливаем self.mc_data['gateways']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
                return
        mc_gateways = self.mc_data['gateways']

        err, result = self.utm.get_template_traffic_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил NAT.')
            self.error = 1
            return
        nat_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('time_created', None)
            item.pop('time_updated', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item['zone_in'] = self.get_zones_id('src', item['zone_in'], item)
            item['zone_out'] = self.get_zones_id('dst', item['zone_out'], item)
            item['source_ip'] = self.get_ips_id('src', item['source_ip'], item)
            item['dest_ip'] = self.get_ips_id('dst', item['dest_ip'], item)
            item['service'] = self.get_services(item['service'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []

            gateway_exist = False
            if item['action'] == 'route':
                for key in mc_gateways:
                    gateway_name, node_name = key.split(':')
                    if gateway_name == item['gateway']:
                        item['gateway'] = mc_gateways[key].id
                        self.stepChanged.emit(f'rNOTE|    Для правила ПБР "{item["name"]}" установлен шлюз "{gateway_name}" для узла "{node_name}". Если нужен шлюз для другого узла, установите его вручную.')
                        gateway_exist = True
                        break
                if not gateway_exist:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шлюз "{item["gateway"]}" для правила ПБР в группе шаблонов.')
                    item['description'] = f'{item["description"]}\nError: Не найден шлюз "{item["gateway"]}" для правила ПБР в группе шаблонов.'
                    item['gateway'] = ''
                    item['error'] = True

            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True
            
            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in nat_rules:
                self.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
                item.pop('position', None)
                err, result = self.utm.update_template_traffic_rule(self.template_id, nat_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_traffic_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    nat_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил NAT завершён.')


    def import_loadbalancing_rules(self, path):
        """Импортируем правила балансировки нагрузки"""
        self.stepChanged.emit('BLUE|Импорт правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
        err, result = self.utm.get_template_loadbalancing_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил балансировки нагрузки.')
            self.error = 1
            return

        self.import_loadbalancing_tcpudp(path, result)
        self.import_loadbalancing_icap(path, result)
        self.import_loadbalancing_reverse(path, result)


    def import_loadbalancing_tcpudp(self, path, balansing_servers):
        """Импортируем балансировщики TCP/UDP"""
        self.stepChanged.emit('BLUE|    Импорт балансировщиков TCP/UDP.')
        json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|    Нет балансировщиков TCP/UDP для импорта.')
            return
        elif err == 1:
            return

        tcpudp_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'ipvs'}
        error = 0

        for item in data:
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['type'] = 'ipvs'

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in tcpudp_rules:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_loadbalancing_rule(self.template_id, tcpudp_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|          Правило балансировки TCP/UDP "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_template_loadbalancing_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    tcpudp_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки TCP/UDP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки TCP/UDP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил балансировки TCP/UDP завершён.')


    def import_loadbalancing_icap(self, path, balansing_servers):
        """Импортируем балансировщики ICAP"""
        json_file = os.path.join(path, 'config_loadbalancing_icap.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|    Нет балансировщиков ICAP для импорта.')
            return
        elif err == 1:
            return

        self.stepChanged.emit('BLUE|    Импорт балансировщиков ICAP.')
        error = 0

        if not self.mc_data['icap_servers']:
            if self.get_icap_servers():            # Устанавливаем self.mc_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
                return
        icap_servers = self.mc_data['icap_servers']

        icap_loadbalancing = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'icap'}

        for item in data:
            item['type'] = 'icap'
            new_profiles = []
            for profile in item['profiles']:
                try:
                    new_profiles.append(icap_servers[profile].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|       Error: [Правило "{item["name"]}"] Не найден сервер ICAP "{profile}" в группе шаблонов. Импортируйте серверы ICAP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP "{profile}".'
                    item['enabled'] = False
                    error = 1
            item['profiles'] = new_profiles

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in icap_loadbalancing:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки ICAP "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_loadbalancing_rule(self.template_id, icap_loadbalancing[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|          Правило балансировки ICAP "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_template_loadbalancing_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    icap_loadbalancing[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки ICAP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил балансировки ICAP завершён.')


    def import_loadbalancing_reverse(self, path, balansing_servers):
        """Импортируем балансировщики reverse-proxy"""
        json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err in (2, 3):
            self.stepChanged.emit(f'GRAY|    Нет балансировщиков Reverse-proxy для импорта.')
            return
        elif err == 1:
            return

        self.stepChanged.emit('BLUE|    Импорт балансировщиков Reverse-proxy.')
        error = 0

        if not self.mc_data['reverseproxy_servers']:
            if self.get_reverseproxy_servers():            # Устанавливаем self.mc_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
                return
        reverseproxy_servers = self.mc_data['reverseproxy_servers']

        reverse_rules = {x['name']: x['id'] for x in balansing_servers if x['type'] == 'rp'}

        for item in data:
            item['type'] = 'rp'
            new_profiles = []
            for profile in item['profiles']:
                try:
                    new_profiles.append(reverseproxy_servers[profile].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|       Error: [Правило "{item["name"]}"] Не найден сервер reverse-proxy {err} в группе шаблонов. Загрузите серверы reverse-proxy и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер reverse-proxy {err}.'
                    item['enabled'] = False
                    error = 1
            item['profiles'] = new_profiles

            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if item['name'] in reverse_rules:
                self.stepChanged.emit(f'uGRAY|       Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_loadbalancing_rule(self.template_id, reverse_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|          Правило балансировки reverse-proxy "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_template_loadbalancing_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    reverse_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|       Правило балансировки reverse-proxy "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил балансировки Reverse-proxy завершён.')


    def import_shaper_rules(self, path):
        """Импортируем список правил пропускной способности"""
        json_file = os.path.join(path, 'config_shaper_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
        error = 0

        err, result = self.utm.get_template_shaper_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил пропускной способности.')
            self.error = 1
            return
        shaper_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
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
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['apps'] = self.get_apps(item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            try:
                item['pool'] = self.mc_data['shapers'][item['pool']].id
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
                item.pop('position', None)
                err, result = self.utm.update_template_shaper_rule(self.template_id, shaper_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило пропускной способности "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_shaper_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    shaper_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил пропускной способности завершён.')


    #------------------------------------- Политики безопасности ------------------------------------------
    def import_content_rules(self, path):
        """Импортировать список правил фильтрации контента"""
        json_file = os.path.join(path, 'config_content_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
        error = 0

        if not self.mc_data['morphology']:
            if self.get_morphology_list():    # Устанавливаем self.mc_data['morphology']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
                return
        morphology_list = self.mc_data['morphology']

        if not self.mc_data['useragents']:
            if self.get_useragent_list():    # Устанавливаем self.mc_data['useragents']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
                return
        useragent_list = self.mc_data['useragents']

        err, result = self.utm.get_template_content_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил контентной фильтрации.')
            self.error = 1
            return
        content_rules = {x['name']: x['id'] for x in result}

        for item in data:
            item.pop('time_created', None)
            item.pop('time_updated', None)
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            try:
                item['blockpage_template_id'] = self.mc_data['response_pages'][item['blockpage_template_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
                item['blockpage_template_id'] = -1
                item['error'] = True

            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['referers'] = self.get_urls_id(item['referers'], item)
            item['referer_categories'] = self.get_url_categories_id(item, referer=1)
            item['time_restrictions'] = self.get_time_restrictions(item)

            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                    item['scenario_rule_id'] = False
                    item['error'] = True

            new_morph_categories = []
            for x in item['morph_categories']:
                if x in self.mc_data['ug_morphology']:
                    new_morph_categories.append(f'id-{x}')
                else:
                    try:
                        new_morph_categories.append(morphology_list[x].id)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список морфологии {err}. Загрузите списки морфологии и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден список морфологии {err}.'
                        item['error'] = True
            item['morph_categories'] = new_morph_categories

            new_user_agents = []
            for x in item['user_agents']:
                if x[1] in self.mc_data['ug_useragents']:
                    new_user_agents.append(['list_id', f'id-{x[1]}'])
                else:
                    try:
                        new_user_agents.append(['list_id', useragent_list[x[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список UserAgent {err}. Загрузите списки UserAgent браузеров и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден список UserAgent {err}.'
                        item['error'] = True
            item['user_agents'] = new_user_agents

            new_content_types = []
            for x in item['content_types']:
                try:
                    new_content_types.append(self.mc_data['mime'][x].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список типов контента {err}. Загрузите списки типов контента и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                    item['error'] = True
            item['content_types'] = new_content_types

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in content_rules:
                self.stepChanged.emit(f'uGRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
                item.pop('position', None)
                err, result = self.utm.update_template_content_rule(self.template_id, content_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило контентной фильтрации "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_content_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    content_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" импортировано.')

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

        err, result = self.utm.get_template_safebrowsing_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил веб-безопасности.')
            self.error = 1
            return
        safebrowsing_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['url_list_exclusions'] = self.get_urls_id(item['url_list_exclusions'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in safebrowsing_rules:
                self.stepChanged.emit(f'uGRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
                item.pop('position', None)
                err, result = self.utm.update_template_safebrowsing_rule(self.template_id, safebrowsing_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило веб-безопасности "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило веб-безопасности "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_safebrowsing_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности "{item["name"]}" не импортировано]')
                else:
                    safebrowsing_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" импортировано.')
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

        err, rules = self.utm.get_template_tunnel_inspection_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования туннелей.')
            self.error = 1
            return
        tunnel_inspect_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in tunnel_inspect_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования туннелей "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_tunnel_inspection_rule(self.template_id, tunnel_inspect_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило инспектирования туннелей "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило инспектирования туннелей "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_tunnel_inspection_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей "{item["name"]}" не импортировано]')
                else:
                    tunnel_inspect_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" импортировано.')
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

        if not self.mc_data['ssl_forward_profiles']:
            if self.get_ssl_forward_profiles():    # Устанавливаем self.mc_data['ssl_forward_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
                return
        ssl_forward_profiles = self.mc_data['ssl_forward_profiles']

        err, rules = self.utm.get_template_ssldecrypt_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSL.')
            self.error = 1
            return
        ssldecrypt_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            try:
                item['ssl_profile_id'] = self.mc_data['ssl_profiles'][item['ssl_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Загрузите профили SSL и повторите импорт.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}. Установлен Default SSL profile.'
                item['ssl_profile_id'] = self.mc_data['ssl_profiles']['Default SSL profile'].id
                item['error'] = True
            try:
                item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль пересылки SSL {err}. Загрузите профили пересылки SSL и повторите импорт.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
                item['ssl_forward_profile_id'] = -1
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in ssldecrypt_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_ssldecrypt_rule(self.template_id, ssldecrypt_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSL "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило инспектирования SSL "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_ssldecrypt_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
                else:
                    ssldecrypt_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')
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

        err, rules = self.utm.get_template_sshdecrypt_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил инспектирования SSH.')
            self.error = 1
            return
        sshdecrypt_rules = {x['name']: x['id'] for x in rules}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['protocols'] = self.get_services(item['protocols'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in sshdecrypt_rules:
                self.stepChanged.emit(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_sshdecrypt_rule(self.template_id, sshdecrypt_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSH "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило инспектирования SSH "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_sshdecrypt_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
                else:
                    sshdecrypt_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил инспектирования SSH завершён.')


    def import_mailsecurity(self, path):
        self.import_mailsecurity_rules(path)
        self.import_mailsecurity_antispam(path)


    def import_mailsecurity_rules(self, path):
        """Импортируем список правил защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
        error = 0

        if not self.mc_data['email_groups']:
            if self.get_email_groups():    # Устанавливаем self.mc_data['email_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
                return
        email = self.mc_data['email_groups']

        err, result = self.utm.get_template_mailsecurity_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты почтового трафика.')
            self.error = 1
            return
        mailsecurity_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            if not item['services']:
                item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
            item['services'] = self.get_services(item['services'], item)

            try:
                item['envelope_from'] = [[x[0], email[x[1]].id] for x in item['envelope_from']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
                item['envelope_from'] = []
                item['error'] = True

            try:
                item['envelope_to'] = [[x[0], email[x[1]].id] for x in item['envelope_to']]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
                item['envelope_to'] = []
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in mailsecurity_rules:
                self.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_mailsecurity_rule(self.template_id, mailsecurity_rules[item['name']], item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_mailsecurity_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                else:
                    mailsecurity_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил защиты почтового трафика завершён.')


    def import_mailsecurity_antispam(self, path):
        """Импортируем dnsbl и batv защиты почтового трафика"""
        json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')

        json_file = os.path.join(path, 'config_mailsecurity_batv.json')
        err, batv = self.read_json_file(json_file, mode=1)
        if err:
            data['enabled'] = False
            self.stepChanged.emit('ORANGE|       В настройках антиспама BATV будет отключено.')
        else:
            data['enabled'] = batv['enabled']

        data['white_list'] = self.get_ips_id('white_list', data['white_list'], {'name': 'antispam DNSBL'})
        data['black_list'] = self.get_ips_id('black_list', data['black_list'], {'name': 'antispam DNSBL'})

        err, result = self.utm.set_template_mailsecurity_antispam(self.template_id, data)
        if err:
            self.error = 1
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте настроек антиспама.')
        else:
            self.stepChanged.emit(f'GREEN|    Настройки антиспама импортированы.')


    def import_icap_servers(self, path):
        """Импортируем список серверов ICAP"""
        json_file = os.path.join(path, 'config_icap_servers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
        error = 0

        if not self.mc_data['icap_servers']:
            if self.get_icap_servers():      # Устанавливаем self.mc_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
                return
        icap_servers = self.mc_data['icap_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in icap_servers:
                if self.template_id == icap_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    ICAP-сервер "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_icap_server(self.template_id, icap_servers[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [ICAP-сервер "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       ICAP-сервер "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    ICAP-сервер "{item["name"]}" уже существует в шаблоне "{icap_servers[item["name"]].template_name}".')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_icap_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [ICAP-сервер "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    icap_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['icap_servers']:
            if self.get_icap_servers():      # Устанавливаем self.mc_data['icap_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
                return
        icap_servers = self.mc_data['icap_servers']

        err, result = self.utm.get_template_loadbalancing_rules(self.template_id, query={'query': 'type = icap'})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил ICAP.')
            self.error = 1
            return
        icap_loadbalancing = {x['name']: x['id'] for x in result}

        err, result = self.utm.get_template_icap_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил ICAP.')
            self.error = 1
            return
        icap_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
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
                        new_servers.append(['profile', icap_servers[server[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сервер ICAP {err}. Импортируйте сервера ICAP и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                        item['error'] = True
            item['servers'] = new_servers

            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            new_content_types = []
            for x in item['content_types']:
                try:
                    new_content_types.append(self.mc_data['mime'][x].id)
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список типов контента {err}. Загрузите списки типов контента и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                    item['error'] = True
            item['content_types'] = new_content_types

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in icap_rules:
                self.stepChanged.emit(f'uGRAY|    ICAP-правило "{item["name"]}" уже существует.')
                err, result = self.utm.update_template_icap_rule(self.template_id, icap_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [ICAP-правило "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       ICAP-правило "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_icap_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [ICAP-правило "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    icap_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" импортировано.')
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

        if not self.mc_data['dos_profiles']:
            if self.get_dos_profiles():      # Устанавливаем self.mc_data['dos_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
                return
        dos_profiles = self.mc_data['dos_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in dos_profiles:
                if self.template_id == dos_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль DoS "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_dos_profile(self.template_id, dos_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль DoS "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль DoS "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль DoS "{item["name"]}" уже существует в шаблоне "{dos_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_dos_profile(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль DoS "{item["name"]}" не импортирован]')
                else:
                    dos_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        if not self.mc_data['dos_profiles']:
            if self.get_dos_profiles():      # Устанавливаем self.mc_data['dos_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
                return
        dos_profiles = self.mc_data['dos_profiles']

        err, result = self.utm.get_template_dos_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил защиты DoS.')
            self.error = 1
            return
        dos_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['dst_zones'] = self.get_zones_id('dst', item['dst_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['services'] = self.get_services(item['services'], item)
            item['time_restrictions'] = self.get_time_restrictions(item)
            if item['dos_profile']:
                try:
                    item['dos_profile'] = dos_profiles[item['dos_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль DoS {err}. Импортируйте профили DoS и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль DoS {err}.'
                    item['dos_profile'] = False
                    item['error'] = True
            if item['scenario_rule_id']:
                try:
                    item['scenario_rule_id'] = self.mc_data['scenarios'][item['scenario_rule_id']].id
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
                err, result = self.utm.update_template_dos_rule(self.template_id, dos_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило защиты DoS "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило защиты DoS "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_dos_rule(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS "{item["name"]}" не импортировано]')
                else:
                    dos_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил защиты DoS завершён.')


    #---------------------------------------- WAF -------------------------------------------------
    def import_waf_custom_layers(self, path):
        """Импортируем Персональные слои WAF"""
        if self.utm.float_version >= 7.3:
            return

        json_file = os.path.join(path, 'config_waf_custom_layers.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт персональных слоёв в раздел "WAF/Персональные слои".')
        error = 0

        if not self.waf_custom_layers:
            if self.get_waf_custom_layers():      # Устанавливаем атрибут self.waf_custom_layers
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
                return

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя слоя')
            if item['name'] in self.waf_custom_layers:
                self.stepChanged.emit(f'uGRAY|    Персональный слой "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = self.utm.update_template_waf_custom_layer(self.template_id, self.waf_custom_layers[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Персональный слой "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Персональный слой "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_template_waf_custom_layer(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Персональный слой "{item["name"]}" не импортирован]')
                else:
                    self.waf_custom_layers[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Персональный слой "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
        else:
            self.stepChanged.emit('GREEN|    Импорт персональных слоёв WAF завершён.')


    def import_waf_profiles(self, path):
        """Импортируем профили WAF"""
        if self.utm.float_version >= 7.3:
            return

        json_file = os.path.join(path, 'config_waf_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт профилей WAF в раздел "WAF/Профили".')
        error = 0

        err, result = self.utm.get_waf_technology_list()
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей WAF.')
            self.error = 1
            return
        waf_technology = {x['name']: x['id'] for x in result}

        if not self.waf_custom_layers:
            if self.get_waf_custom_layers():      # Устанавливаем атрибут self.waf_custom_layers
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
                return

        err, result = self.utm.get_template_waf_system_layers(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте профилей WAF.')
            self.error = 1
            return
        waf_system_layers = {x['name']: x['id'] for x in result}

        if not self.mc_data['waf_profiles']:
            if self.get_waf_profiles(): # Устанавливаем self.mc_data['waf_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
                return
        waf_profiles = self.mc_data['waf_profiles']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя профиля')
            if item['name'] in waf_profiles and self.template_id != waf_profiles[item['name']].template_id:
                self.stepChanged.emit(f'sGREEN|    Профиль WAF "{item["name"]}" уже существует в шаблоне "{waf_profiles[item["name"]].template_name}".')
                continue

            rule_layers = []
            for layer in item['layers']:
                if layer['type'] == 'custom_layer':
                    try:
                        layer['id'] = self.waf_custom_layers[layer['id']]
                        rule_layers.append(layer)
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден персональный слой "{layer["id"]}".')
                        item['description'] = f'{item["description"]}\nError: Не найден персональный слой "{layer["id"]}"'
                        error = 1
                else:
                    protection_technologies = []
                    for x in layer['protection_technologies']:
                        try:
                            protection_technologies.append(waf_technology[x])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] В слое "{layer["id"]}" обнаружена не существующая технология защиты {err}.')
                            item['description'] = f'{item["description"]}\nError: В слое "{layer["id"]}" обнаружена не существующая технология защиты {err}.'
                            error = 1
                    layer['protection_technologies'] = protection_technologies
                    layer['id'] = waf_system_layers[layer['id']]
                    rule_layers.append(layer)
            item['layers'] = rule_layers

            if item['name'] in waf_profiles:
                if self.template_id == waf_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль WAF "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_waf_profile(self.template_id, waf_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль WAF "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль WAF "{item["name"]}" обновлён.')
            else:
                err, result = self.utm.add_template_waf_profile(self.template_id, item)
                if err:
                    error = 1
                    self.stepChanged.emit(f'RED|    {result}  [Профиль WAF "{item["name"]}" не импортирован]')
                else:
                    waf_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль WAF "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей WAF завершён.')


    #---------------------------------------- Глобальный портал ----------------------------------------
    def import_proxyportal_rules(self, path):
        """Импортируем список URL-ресурсов веб-портала"""
        json_file = os.path.join(path, 'config_web_portal.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка ресурсов веб-портала в раздел "Глобальный портал/Веб-портал".')
        error = 0

        err, result = self.utm.get_template_proxyportal_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте ресурсов веб-портала.')
            self.error = 1
            return
        list_proxyportal = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя ресурса')
            item['position_layer'] = 'pre'
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            try:
                if item['mapping_url_ssl_profile_id']:
                    item['mapping_url_ssl_profile_id'] = self.mc_data['ssl_profiles'][item['mapping_url_ssl_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                item['mapping_url_ssl_profile_id'] = 0
                item['error'] = True
            try:
                if item['mapping_url_certificate_id']:
                    item['mapping_url_certificate_id'] = self.mc_data['certs'][item['mapping_url_certificate_id']].id
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
                err, result = self.utm.update_template_proxyportal_rule(self.template_id, list_proxyportal[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Ресурс веб-портала "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Ресурс веб-портала "{item["name"]}" обновлён.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_proxyportal_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Ресурс веб-портала "{item["name"]}" не импортирован]')
                    error = 1
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

        if not self.mc_data['reverseproxy_servers']:
            if self.get_reverseproxy_servers():      # Устанавливаем self.mc_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
                return
        reverseproxy_servers = self.mc_data['reverseproxy_servers']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сервера')
            if item['name'] in reverseproxy_servers:
                if self.template_id == reverseproxy_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сервер reverse-прокси "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_reverseproxy_server(self.template_id, reverseproxy_servers[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Сервер reverse-прокси "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Сервер reverse-прокси "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сервер reverse-прокси "{item["name"]}" уже существует в шаблоне "{reverseproxy_servers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_reverseproxy_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сервер reverse-прокси "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    reverseproxy_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
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

        err, result = self.utm.get_template_loadbalancing_rules(self.template_id, query={'query': 'type = reverse'})
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        reverse_loadbalancing = {x['name']: x['id'] for x in result}

        if not self.mc_data['reverseproxy_servers']:
            if self.get_reverseproxy_servers():      # Устанавливаем self.mc_data['reverseproxy_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
        reverseproxy_servers = self.mc_data['reverseproxy_servers']

        if not self.mc_data['useragents']:
            if self.get_useragent_list():      # Устанавливаем self.mc_data['useragents']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
        useragent_list = self.mc_data['useragents']

        if not self.mc_data['client_certs_profiles']:
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        if self.utm.float_version < 7.3:
            if self.utm.waf_license:  # Проверяем что есть лицензия на WAF
                if not self.mc_data['waf_profiles']:
                    if self.get_waf_profiles(): # Устанавливаем self.mc_data['waf_profiles']
                        self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                        return
            else:
                self.stepChanged.emit('NOTE|    Нет лицензии на WAF. Защита приложений WAF будет выключена в правилах.')
            waf_profiles = self.mc_data['waf_profiles']

        err, result = self.utm.get_template_reverseproxy_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил reverse-прокси.')
            self.error = 1
            return
        reverseproxy_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []

            if not item['src_zones']:
                self.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не указана src-зона.')
                error = 1
                continue

            try:
                for x in item['servers']:
                    x[1] = reverseproxy_servers[x[1]].id if x[0] == 'profile' else reverse_loadbalancing[x[1]]
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не найден сервер reverse-прокси или балансировщик {err}. Импортируйте reverse-прокси или балансировщик и повторите попытку.')
                error = 1
                continue

            if item['ssl_profile_id']:
                try:
                    item['ssl_profile_id'] = self.mc_data['ssl_profiles'][item['ssl_profile_id']].id
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
                    item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
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
                if x[1] in self.mc_data['ug_useragents']:
                    new_user_agents.append(['list_id', f'id-{x[1]}'])
                else:
                    try:
                        new_user_agents.append(['list_id', useragent_list[x[1]].id])
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден список Useragent {err}. Импортируйте списки useragent браузеров и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден Useragent {err}.'
                        item['error'] = True
            item['user_agents'] = new_user_agents

            if item['client_certificate_profile_id']:
                try:
                    item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Импортируйте профили пользовательских сертификатов и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                    item['client_certificate_profile_id'] = 0
                    item['error'] = True

            if self.utm.float_version < 7.3:
                if item['waf_profile_id']:
                    if self.utm.waf_license:
                        try:
                            item['waf_profile_id'] = waf_profiles[item['waf_profile_id']].id
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
                err, result = self.utm.update_template_reverseproxy_rule(self.template_id, reverseproxy_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило reverse-прокси "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило reverse-прокси "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_reverseproxy_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило reverse-прокси "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    reverseproxy_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило reverse-прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил reverse-прокси завершён.')
        self.stepChanged.emit('LBLUE|    Проверьте флаг "Использовать HTTPS" во всех импортированных правилах! Если не установлен профиль SSL, выберите нужный.')


    #------------------------------- Вышестоящий прокси -----------------------------------------
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

        if not self.mc_data['upstreamproxies_servers']:
            if self.get_upstream_proxies_servers(): # Устанавливаем self.mc_data['upstreamproxies_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов вышестоящих прокси.')
                return
        proxies_servers = self.mc_data['upstreamproxies_servers']

        for item in data:
            if item['name'] in proxies_servers:
                if self.template_id == proxies_servers[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Cервер вышестоящих прокси "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_cascade_proxy_server(self.template_id, proxies_servers[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Cервер вышестоящих прокси "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Cервер вышестоящих прокси "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Cервер вышестоящих прокси "{item["name"]}" уже существует в шаблоне "{proxies_servers[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_cascade_proxy_server(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Cервер вышестоящих прокси "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    proxies_servers[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Cервер вышестоящих прокси "{item["name"]}" импортирован.')
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

        if not self.mc_data['upstreamproxies_servers']:
            if self.get_upstream_proxies_servers(): # Устанавливаем self.mc_data['upstreamproxies_servers']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
                return
        proxies_servers = self.mc_data['upstreamproxies_servers']

        if not self.mc_data['upstreamproxies_profiles']:
            if self.get_upstream_proxies_profiles(): # Устанавливаем self.mc_data['upstreamproxies_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей вышестоящих прокси.')
                return
        proxies_profiles = self.mc_data['upstreamproxies_profiles']

        for item in data:
            new_servers = []
            for x in item['servers']:
                try:
                    new_servers.append(proxies_servers[x].id)
                except KeyError:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден сервер "{x}". Импортируйте серверы и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер "{x}".'
                    error = 1
            item['servers'] = new_servers

            if item['name'] in proxies_profiles:
                if self.template_id == proxies_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль вышестоящих прокси "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_cascade_proxy_profile(self.template_id, proxies_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль вышестоящих прокси "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль вышестоящих прокси "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль вышестоящих прокси "{item["name"]}" уже существует в шаблоне "{proxies_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_cascade_proxy_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль вышестоящих прокси "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    proxies_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль вышестоящих прокси "{item["name"]}" импортирован.')
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

        if not self.mc_data['upstreamproxies_profiles']:
            if self.get_upstream_proxies_profiles(): # Устанавливаем self.mc_data['upstreamproxies_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
                return
        proxies_profiles = self.mc_data['upstreamproxies_profiles']

        err, result = self.utm.get_template_cascade_proxy_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил вышестоящих прокси.')
            self.error = 1
            return
        proxies_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('time_created', None)
            item.pop('time_updated', None)
            item['position_layer'] = 'pre'

            if item['proxy_profile']:
                try:
                    item['proxy_profile'] = proxies_profiles[item['proxy_profile']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль прокси {err}. Установлен режим работы: "Мимо прокси".')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль прокси {err}. Установлен режим работы: "Мимо прокси".'
                    item['proxy_profile'] = ''
                    item['action'] = 'direct'
                    item['fallback_action'] = 'direct'
                    item.pop('fallback_block_page', None)
                    error = 1
            if 'fallback_block_page' in item:
                try:
                    item['fallback_block_page'] = self.mc_data['response_pages'][item['fallback_block_page']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки "{item["fallback_block_page"]}".'
                    item['fallback_block_page'] = -1
                    error = 1

            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            item['time_restrictions'] = self.get_time_restrictions(item)
            item['url_categories'] = self.get_url_categories_id(item)
            item['urls'] = self.get_urls_id(item['urls'], item)
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['src_ips'] = self.get_ips_id('src', item['src_ips'], item)

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in proxies_rules:
                self.stepChanged.emit(f'uGRAY|    Правило вышестоящих прокси "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = self.utm.update_template_cascade_proxy_rule(self.template_id, proxies_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило вышестоящих прокси "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило вышестоящих прокси "{item["name"]}" обновлёно.')
            else:
                err, result = self.utm.add_template_cascade_proxy_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило вышестоящих прокси "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    proxies_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило вышестоящих прокси "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил вышестоящих прокси.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил вышестоящих прокси завершён.')


    #-------------------------------------- VPN -------------------------------------------------
    def import_vpnclient_security_profiles(self, path):
        """Импортируем клиентские профилей безопасности VPN"""
        json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт клиентских профилей безопасности VPN в раздел "VPN/Клиентские профили безопасности".')
        error = 0

        if not self.mc_data['vpn_client_security_profiles']:
            if self.get_vpn_client_security_profiles(): # Устанавливаем self.mc_data['vpn_client_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
                return
        security_profiles = self.mc_data['vpn_client_security_profiles']

        for item in data:
            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = 0
                    error = 1

            if item['name'] in security_profiles:
                if self.template_id == security_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_vpn_client_security_profile(self.template_id, security_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль безопасности VPN "{item["name"]}" уже существует в шаблоне "{security_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_vpn_client_security_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    security_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт клиентских профилей безопасности завершён.')


    def import_vpnserver_security_profiles(self, path):
        """Импортируем серверные профилей безопасности VPN"""
        json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт серверных профилей безопасности VPN в раздел "VPN/Серверные профили безопасности".')
        error = 0

        if not self.mc_data['client_certs_profiles']:
            if self.get_client_certificate_profiles(): # Устанавливаем self.mc_data['client_certs_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
                return
        client_certs_profiles = self.mc_data['client_certs_profiles']

        if not self.mc_data['vpn_server_security_profiles']:
            if self.get_vpn_server_security_profiles(): # Устанавливаем self.mc_data['vpn_server_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
                return
        security_profiles = self.mc_data['vpn_server_security_profiles']

        for item in data:
            if item['certificate_id']:
                try:
                    item['certificate_id'] = self.mc_data['certs'][item['certificate_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                    item['certificate_id'] = 0
                    error = 1
            if item['client_certificate_profile_id']:
                try:
                    item['client_certificate_profile_id'] = client_certs_profiles[item['client_certificate_profile_id']].id
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Профиль "{item["name"]}"] Не найден профиль сертификата пользователя {err}. Импортируйте профили пользовательских сертификатов и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя {err}.'
                    item['client_certificate_profile_id'] = 0
                    error = 1

            if item['name'] in security_profiles:
                if self.template_id == security_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_vpn_server_security_profile(self.template_id, security_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль безопасности VPN "{item["name"]}" уже существует в шаблоне "{security_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_vpn_server_security_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    security_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверных профилей безопасности завершён.')


    def get_networks(self, networks, rule):
        new_networks = []
        for x in networks:
            try:
                new_networks.append(['list_id', self.mc_data['ip_lists'][x[1]].id]  if x[0] == 'list_id' else x)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список IP-адресов {err}. Импортируйте списки IP-адресов и повторите попытку.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список IP-адресов {err}.'
                rule['error'] = True
        return new_networks


    def import_vpn_networks(self, path):
        """Импортируем список сетей VPN"""
        json_file = os.path.join(path, 'config_vpn_networks.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка сетей VPN в раздел "VPN/Сети VPN".')
        error = 0

        if not self.mc_data['vpn_networks']:
            if self.get_vpn_networks():        # Устанавливаем self.mc_data['vpn_networks']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
                return
        vpn_networks = self.mc_data['vpn_networks']

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя сети VPN')
            item['networks'] = self.get_networks(item['networks'], item)
            item['ep_routes_include'] = self.get_networks(item['ep_routes_include'], item)
            item['ep_routes_exclude'] = self.get_networks(item['ep_routes_exclude'], item)
            if item.pop('error', False):
                error = 1

            if item['name'] in vpn_networks:
                if self.template_id == vpn_networks[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Сеть VPN "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_vpn_network(self.template_id, vpn_networks[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Сеть VPN "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Сеть VPN "{item["name"]}" обновлена.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Сеть VPN "{item["name"]}" уже существует в шаблоне "{vpn_networks[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_vpn_network(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Сеть VPN "{item["name"]}" не импортирована]')
                    error = 1
                else:
                    vpn_networks[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Сеть VPN "{item["name"]}" импортирована.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт списка сетей VPN завершён.')


    def import_vpn_client_rules(self, path):
        """Импортируем список клиентских правил VPN"""
        json_file = os.path.join(path, 'config_vpn_client_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт клиентских правил VPN в раздел "VPN/Клиентские правила".')
        error = 0

        if not self.mc_data['interfaces']:
            if self.get_interfaces_list(): # Устанавливаем self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
                return

        if not self.mc_data['vpn_client_security_profiles']:
            if self.get_vpn_client_security_profiles(): # Устанавливаем self.mc_data['vpn_client_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
                return
        security_profiles = self.mc_data['vpn_client_security_profiles']

        err, result = self.utm.get_template_vpn_client_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте клиентских правил VPN.')
            self.error = 1
            return
        vpn_client_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item.pop('xauth_login', None)
            item.pop('xauth_password', None)
            item.pop('protocol', None)
            item.pop('subnet1', None)
            item.pop('subnet2', None)
            if f'{item["iface_id"]}:cluster' not in self.mc_data['interfaces']:
                self.stepChanged.emit(f'ORANGE|    Warning: [Правило "{item["name"]}"] Не найден интерфейс VPN "{item["iface_id"]}" в группе шаблонов.')
            try:
                item['security_profile_id'] = security_profiles[item['security_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности VPN {err}.'
                item['security_profile_id'] = ""
                item['enabled'] = False
                error = 1

            if item['name'] in vpn_client_rules:
                self.stepChanged.emit(f'uGRAY|    Клиентское правило VPN "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = self.utm.update_template_vpn_client_rule(self.template_id, vpn_client_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Клиентское правило VPN "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Клиентское правило VPN "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_template_vpn_client_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Клиентское правило VPN "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    vpn_client_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Клиентское правило VPN "{item["name"]}" импортировано.')
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

        if not self.mc_data['interfaces']:
            if self.get_interfaces_list(): # Устанавливаем self.mc_data['interfaces']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
                return

        if not self.mc_data['vpn_server_security_profiles']:
            if self.get_vpn_server_security_profiles(): # Устанавливаем self.mc_data['vpn_server_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
                return
        security_profiles = self.mc_data['vpn_server_security_profiles']

        if not self.mc_data['vpn_networks']:
            if self.get_vpn_networks():        # Устанавливаем self.mc_data['vpn_networks']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
                return
        vpn_networks = self.mc_data['vpn_networks']

        err, result = self.utm.get_template_vpn_server_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте серверных правил VPN.')
            self.error = 1
            return
        vpn_server_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            item['position_layer'] = 'pre'
            item['src_zones'] = self.get_zones_id('src', item['src_zones'], item)
            item['source_ips'] = self.get_ips_id('src', item['source_ips'], item)
            item['dst_ips'] = self.get_ips_id('dst', item['dst_ips'], item)
            item['users'] = self.get_guids_users_and_groups(item) if self.mc_data['ldap_servers'] else []
            message = '       Правило "{item["name"]}" не импортировано.'
            if f'{item["iface_id"]}:cluster' not in self.mc_data['interfaces']:
                self.stepChanged.emit(f'RED|    Eror: [Правило "{item["name"]}"] Не найден интерфейс VPN "{item["iface_id"]}" в группе шаблонов.\n{message}')
                error = 1
                continue
            try:
                item['security_profile_id'] = security_profiles[item['security_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.\n{message}')
                error = 1
                continue
            try:
                item['tunnel_id'] = vpn_networks[item['tunnel_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена сеть VPN "{err}". Загрузите сети VPN и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена сеть VPN "{err}".'
                item['tunnel_id'] = False
                item['error'] = True
            try:
                item['auth_profile_id'] = self.mc_data['auth_profiles'][item['auth_profile_id']].id
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль авторизации {err}. Загрузите профили авторизации и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль авторизации {err}.'
                item['auth_profile_id'] = False
                item['error'] = True

            if item.pop('error', False):
                item['enabled'] = False
                error = 1

            if item['name'] in vpn_server_rules:
                self.stepChanged.emit(f'uGRAY|    Серверное правило VPN "{item["name"]}" уже существует в текщем шаблоне.')
                err, result = self.utm.update_template_vpn_server_rule(self.template_id, vpn_server_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Серверное правило VPN "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Серверное правило VPN "{item["name"]}" обновлено.')
            else:
                item['position'] = 'last'
                err, result = self.utm.add_template_vpn_server_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Серверное правило VPN "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    vpn_server_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Серверное правило VPN "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        else:
            self.stepChanged.emit('GREEN|    Импорт серверных правил VPN завершён.')


    #------------------------------------------- Оповещения ----------------------------------------------
    def import_notification_alert_rules(self, path):
        """Импортируем список правил оповещений"""
        json_file = os.path.join(path, 'config_alert_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт правил оповещений в раздел "Диагностика и мониторинг/Правила оповещений".')
        error = 0

        if not self.mc_data['notification_profiles']:
            if self.get_notification_profiles():      # Устанавливаем self.mc_data['notification_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return

        if not self.mc_data['email_groups']:
            if self.get_email_groups():      # Устанавливаем self.mc_data['email_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return

        if not self.mc_data['phone_groups']:
            if self.get_phone_groups():      # Устанавливаем self.mc_data['phone_groups']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
                return

        err, result = self.utm.get_template_notification_alert_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил оповещений.')
            self.error = 1
            return
        alert_rules = {x['name']: x['id'] for x in result}

        for item in data:
            try:
                item['notification_profile_id'] = self.mc_data['notification_profiles'][item['notification_profile_id']].id
            except KeyError as err:
                message = f'Error: [Правило "{item["name"]}"] Не найден профиль оповещений {err}. Импортируйте профили оповещений и повторите попытку.'
                self.stepChanged.emit(f'RED|    {message}\n       Правило "{item["name"]}" не импортировано.')
                error = 1
                continue

            new_emails = []
            for x in item['emails']:
                try:
                    new_emails.append(['list_id', self.mc_data['email_groups'][x[1]].id])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена группа почтовых адресов {err}. Загрузите почтовые адреса и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найдена группа почтовых адресов {err}.'
                    item['enabled'] = False
                    error = 1
            item['emails'] = new_emails

            new_phones = []
            for x in item['phones']:
                try:
                    new_phones.append(['list_id', self.mc_data['phone_groups'][x[1]].id])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найдена группа телефонных номеров {err}. Загрузите номера телефонов и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найдена группа телефонных номеров {err}.'
                    item['enabled'] = False
                    error = 1
            item['phones'] = new_phones

            if item['name'] in alert_rules:
                self.stepChanged.emit(f'uGRAY|    Правило оповещения "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = self.utm.update_template_notification_alert_rule(self.template_id, alert_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило оповещения "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило оповещения "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_template_notification_alert_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило оповещения "{item["name"]}" не импортировано]')
                    error = 1
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

        self.stepChanged.emit('BLUE|Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Профили безопасности SNMP".')
        error = 0

        if not self.mc_data['snmp_security_profiles']:
            if self.get_snmp_security_profiles():      # Устанавливаем self.mc_data['snmp_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
                return
        snmp_security_profiles = self.mc_data['snmp_security_profiles']

        for item in data:
            if not isinstance(item['auth_password'], str):
                item['auth_password'] = ''
            if not isinstance(item['private_password'], str):
                item['private_password'] = ''

            if item['name'] in snmp_security_profiles:
                if self.template_id == snmp_security_profiles[item['name']].template_id:
                    self.stepChanged.emit(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует в текущем шаблоне.')
                    err, result = self.utm.update_template_snmp_security_profile(self.template_id, snmp_security_profiles[item['name']].id, item)
                    if err:
                        self.stepChanged.emit(f'RED|       {result}  [Профиль безопасности SNMP "{item["name"]}"]')
                        error = 1
                    else:
                        self.stepChanged.emit(f'uGRAY|       Профиль безопасности SNMP "{item["name"]}" обновлён.')
                else:
                    self.stepChanged.emit(f'sGREEN|    Профиль безопасности SNMP "{item["name"]}" уже существует в шаблоне "{snmp_security_profiles[item["name"]].template_name}".')
            else:
                err, result = self.utm.add_template_snmp_security_profile(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Профиль безопасности SNMP: "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    snmp_security_profiles[item['name']] = BaseObject(id=result, template_id=self.template_id, template_name=self.templates[self.template_id])
                    self.stepChanged.emit(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт профилей безопасности SNMP завершён.')


    def import_snmp_settings(self, path):
        """Импортируем параметры SNMP"""
        json_file = os.path.join(path, 'config_snmp_engine.json')
        err, engine = self.read_json_file(json_file, mode=2)
        if err:
            return
        json_file = os.path.join(path, 'config_snmp_sysname.json')
        err, sysname = self.read_json_file(json_file, mode=2)
        if err:
            return
        json_file = os.path.join(path, 'config_snmp_syslocation.json')
        err, syslocation = self.read_json_file(json_file, mode=2)
        if err:
            return
        json_file = os.path.join(path, 'config_snmp_sysdescription.json')
        err, sysdescription = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт параметров SNMP в раздел "Диагностика и мониторинг/Параметры SNMP".')

        data = {
            'name': self.node_name,
            'engine_id': engine,
            'sys_name': sysname,
            'sys_location': syslocation,
            'sys_description': sysdescription,
            'enabled_sync': False
        }
        err, result = self.utm.add_template_snmp_parameters(self.template_id, data)
        if err == 1:
            self.error = 1
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте параметров SNMP.')
        elif err == 3:
            self.stepChanged.emit(f'GRAY|    {result}')
        else:
            self.stepChanged.emit('GREEN|    Импорт параметров SNMP завершён.')


    def import_snmp_rules(self, path):
        """Импортируем список правил SNMP"""
        json_file = os.path.join(path, 'config_snmp_rules.json')
        err, data = self.read_json_file(json_file, mode=2)
        if err:
            return

        self.stepChanged.emit('BLUE|Импорт списка правил SNMP в раздел "Диагностика и мониторинг/SNMP".')
        error = 0

        if not self.mc_data['snmp_security_profiles']:
            if self.get_snmp_security_profiles():      # Устанавливаем self.mc_data['snmp_security_profiles']
                self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
                return
        snmp_security_profiles = self.mc_data['snmp_security_profiles']

        err, result = self.utm.get_template_snmp_rules(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}\n    Произошла ошибка при импорте правил SNMP.')
            self.error = 1
            return
        snmp_rules = {x['name']: x['id'] for x in result}

        for item in data:
            error, item['name'] = self.get_transformed_name(item['name'], err=error, descr='Имя правила')
            if 'snmp_security_profile' in item:
                if item['snmp_security_profile']:
                    try:
                        item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']].id
                    except KeyError as err:
                        self.stepChanged.emit(f'RED|    Error: [Правило "{item["name"]}"] Не найден профиль безопасности SNMP {err}. Импортируйте профили безопасности SNMP и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности SNMP {err}.'
                        item['snmp_security_profile'] = 0
                        item['enabled'] = False
                        error = 1
            else:
                item['snmp_security_profile'] = 0
                item.pop('username', None)
                item.pop('auth_type', None)
                item.pop('auth_alg', None)
                item.pop('auth_password', None)
                item.pop('private_alg', None)
                item.pop('private_password', None)

            if item['name'] in snmp_rules:
                self.stepChanged.emit(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует в текущем шаблоне.')
                err, result = self.utm.update_template_snmp_rule(self.template_id, snmp_rules[item['name']], item)
                if err:
                    self.stepChanged.emit(f'RED|       {result}  [Правило SNMP "{item["name"]}"]')
                    error = 1
                else:
                    self.stepChanged.emit(f'uGRAY|       Правило SNMP "{item["name"]}" обновлено.')
            else:
                err, result = self.utm.add_template_snmp_rule(self.template_id, item)
                if err:
                    self.stepChanged.emit(f'RED|    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
                    error = 1
                else:
                    snmp_rules[item['name']] = result
                    self.stepChanged.emit(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
        if error:
            self.error = 1
            self.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
        else:
            self.stepChanged.emit('GREEN|    Импорт правил SNMP завершён.')


    def pass_function(self, path):
        """Функция заглушка"""
        self.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')

    ###################################### Служебные функции ############################################
    def get_ips_id(self, mode, rule_ips, rule):
        """
        Получить UID-ы списков IP-адресов. Если список IP-адресов не существует на MC, то он пропускается.
        mode - принимает значения: src | dst (для формирования сообщений)
        """
        new_rule_ips = []
        for ips in rule_ips:
            if ips[0] == 'geoip_code':
                new_rule_ips.append(ips)
            try:
                if ips[0] == 'list_id':
                    new_rule_ips.append(['list_id', self.mc_data['ip_lists'][ips[1]].id])
                elif ips[0] == 'urllist_id':
                    new_rule_ips.append(['urllist_id', self.mc_data['url_lists'][ips[1]].id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список {mode}-адресов "{ips[1]}". Загрузите списки в библиотеку и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{ips[1]}".'
                rule['error'] = True
        return new_rule_ips


    def get_zones_id(self, mode, zones, rule):
        """
        Получить UID-ы зон. Если зона не существует на MC, то она пропускается.
        mode - принимает значения: src | dst (для формирования сообщений)
        """
        new_zones = []
        for zone in zones:
            try:
                new_zones.append(self.mc_data['zones'][zone].id)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена {mode}-зона "{zone}" в группе шаблонов. Импортируйте зоны и повторите попытку.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone}".'
                rule['error'] = True
        return new_zones


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
                        self.stepChanged.emit(f'ORANGE|    Warning: [Правило "{rule["name"]}"] Не указано имя пользователя в {item}.')
                    if user_name:
                        try:
                            ldap_id = self.mc_data['ldap_servers'][ldap_domain.lower()]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}".')
                            rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            err, result = self.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                            if err:
                                self.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                                rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                                rule['error'] = True
                            elif not result:
                                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет пользователя "{user_name}" в домене "{ldap_domain}".')
                                rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене "{ldap_domain}".'
                                rule['error'] = True
                            else:
                                new_users.append(['user', result])
                    else:
                        try:
                            new_users.append(['user', self.mc_data['local_users'][item[1]].id])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден локальный пользователь {err}. Импортируйте локальных пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь {err}.'
                            rule['error'] = True
                case 'group':
                    group_name = None
                    try:
                        ldap_domain, _, group_name = item[1].partition("\\")
                    except IndexError:
                        self.stepChanged.emit(f'ORANGE|    Warning: [Правило "{rule["name"]}"] Не указано имя группы в {item}')
                    if group_name:
                        try:
                            ldap_id = self.mc_data['ldap_servers'][ldap_domain.lower()]
                        except KeyError:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет LDAP-коннектора для домена "{ldap_domain}"')
                            rule['description'] = f'{rule["description"]}\nError: Нет LDAP-коннектора для домена "{ldap_domain}".'
                            rule['error'] = True
                        else:
                            err, result = self.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                            if err:
                                self.stepChanged.emit(f'RED|    {result}  [Правило "{rule["name"]}"]')
                                rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                                rule['error'] = True
                            elif not result:
                                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Нет группы "{group_name}" в домене "{ldap_domain}"!')
                                rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене "{ldap_domain}".'
                                rule['error'] = True
                            else:
                                new_users.append(['group', result])
                    else:
                        try:
                            new_users.append(['group', self.mc_data['local_groups'][item[1]].id])
                        except KeyError as err:
                            self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа пользователей {err}. Импортируйте группы пользователей.')
                            rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей {err}.'
                            rule['error'] = True
        return new_users


    def get_services(self, service_list, rule):
        """Получаем ID сервисов по из именам. Если сервис не найден, то он пропускается."""
        new_service_list = []
        for item in service_list:
            try:
                if item[0] == 'service':
                    _, service_name = self.get_transformed_name(item[1], descr='Имя сервиса')
                    new_service_list.append(['service', self.mc_data['services'][service_name].id])
                elif item[0] == 'list_id':
                    _, service_name = self.get_transformed_name(item[1], descr='Имя группы сервисов')
                    new_service_list.append(['list_id', self.mc_data['service_groups'][service_name].id])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден сервис или группа сервисов {err} в группе шаблонов. Загрузите сервисы и группы сервисов и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден сервис {err}.'
                rule['error'] = True
        return new_service_list


    def get_url_categories_id(self, rule, referer=0):
        """Получаем ID категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
        new_categories = []
        rule_data = rule['referer_categories'] if referer else rule['url_categories']
        for item in rule_data:
            try:
                if item[0] == 'list_id':
                    new_categories.append(['list_id', self.mc_data['url_categorygroups'][item[1]].id])
                elif item[0] == 'category_id':
                    new_categories.append(['category_id', self.mc_data['url_categories'][item[1]]])
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория URL "{item[1]}" в группе шаблонов. Загрузите категории URL и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найдена категория URL "{item[1]}".'
                rule['error'] = True
        return new_categories


    def get_urls_id(self, urls, rule):
        """Получаем ID списков URL. Если список не существует на MC, то он пропускается."""
        new_urls = []
        for item in urls:
            try:
                new_urls.append(self.mc_data['url_lists'][item].id)
            except KeyError as err:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден список URL "{item}" в группе шаблонов. Загрузите списки URL и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден список URL "{item}".'
                rule['error'] = True
        return new_urls


    def get_apps(self, rule):
        """Определяем ID приложения или группы приложений по именам."""
        new_app_list = []
        for app in rule['apps']:
            if app[0] == 'ro_group':
                if app[1] == 'All':
                    new_app_list.append(['ro_group', 0])
                else:
                    try:
                        new_app_list.append(['ro_group', self.mc_data['l7_categories'][app[1]]])
                    except KeyError as err:
                        message = 'Возможно нет лицензии и MC не получил список категорий l7. Установите лицензию и повторите попытку.'
                        self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена категория l7 "{app[1]}".\n    {message}')
                        rule['description'] = f'{rule["description"]}\nError: Не найдена категория l7 "{app[1]}".'
                        rule['error'] = True
            elif app[0] == 'group':
                try:
                    new_app_list.append(['group', self.mc_data['apps_groups'][app[1]].id])
                except KeyError as err:
                    self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найдена группа приложений l7 "{app[1]}".')
                    rule['description'] = f'{rule["description"]}\nError: Не найдена группа приложений l7 "{app[1]}".'
                    rule['error'] = True
        return new_app_list


    def get_time_restrictions(self, rule):
        """Получаем ID календарей шаблона по их именам. Если календарь не найден в шаблоне, то он пропускается."""
        new_schedules = []
        for name in rule['time_restrictions']:
            try:
                new_schedules.append(self.mc_data['calendars'][name].id)
            except KeyError:
                self.stepChanged.emit(f'RED|    Error: [Правило "{rule["name"]}"] Не найден календарь "{name}" в группе шаблонов.')
                rule['description'] = f'{rule["description"]}\nError: Не найден календарь "{name}".'
                rule['error'] = True
        return new_schedules


    def get_icap_servers(self):
        """Получаем список серверов ICAP и устанавливаем значение self.mc_data['icap_servers']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_icap_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['icap_servers']:
                    self.stepChanged.emit(f'ORANGE|    Сервер ICAP "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['icap_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_reverseproxy_servers(self):
        """Получаем список серверов reverse-proxy и устанавливаем значение self.mc_data['reverseproxy_servers']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_reverseproxy_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['reverseproxy_servers']:
                    self.stepChanged.emit(f'ORANGE|    Сервер Reverse-прокси "{x["name"]}" обнаружен в нескольких шаблонах группы. Сервер из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['reverseproxy_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_morphology_list(self):
        """Получаем список морфологии и устанавливаем значение self.mc_data['morphology']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'morphology')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['morphology']:
                    self.stepChanged.emit(f'ORANGE|    Список морфологии "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['morphology'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_useragent_list(self):
        """Получаем список UserAgents и устанавливаем значение self.mc_data['useragents']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'useragent')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['useragents']:
                    self.stepChanged.emit(f'ORANGE|    Список UserAgents "{x["name"]}" обнаружен в нескольких шаблонах группы. Список из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['useragents'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_app_signatures(self):
        """Получаем список приложений l7 MC и устанавливаем значение self.mc_data['l7_apps']"""
        err, result = self.utm.get_realm_l7_signatures()
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        for x in result:
            self.mc_data['l7_apps'][x['name']] = BaseAppObject(id=x['id'], owner=x['attributes']['owner'], signature_id=x['signature_id'])
        return 0


    def get_l7_profiles(self):
        """Получаем список профилей приложений группы шаблонов и устанавливаем значение self.mc_data['l7_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_l7_profiles_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['l7_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль приложений "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['l7_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0

    def get_email_groups(self):
        """Получаем список групп почтовых адресов группы шаблонов и устанавливаем значение self.mc_data['email_groups']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'emailgroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['email_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа почтовых адресов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['email_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_phone_groups(self):
        """Получаем список групп телефонных номеров группы шаблонов и устанавливаем значение self.mc_data['phone_groups']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_nlists_list(uid, 'phonegroup')
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['phone_groups']:
                    self.stepChanged.emit(f'ORANGE|    Группа почтовых адресов "{x["name"]}" обнаружена в нескольких шаблонах группы. Группа из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['phone_groups'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_idps_realm_users_signatures(self):
        """Получаем список пользовательских сигнатур СОВ всех шаблонов и устанавливаем значение self.mc_data['users_signatures']"""
        err, result = self.utm.get_realm_idps_signatures(query={'query': 'owner = You'})
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        for x in result:
            self.mc_data['realm_users_signatures'][x['msg']] = BaseObject(id=x['id'], template_id=x['template_id'], template_name=self.templates.get(x['template_id'], None))
        return 0


    def get_idps_profiles(self):
        """Получаем список профилей СОВ группы шаблонов и устанавливаем значение self.mc_data['idps_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_idps_profiles_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['idps_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль СОВ "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['idps_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_notification_profiles(self):
        """Получаем список профилей оповещения и устанавливаем значение атрибута self.mc_data['notification_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_notification_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['notification_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль оповещения "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['notification_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['notification_profiles'][-5] = BaseObject(id=-5, template_id='', template_name='')
        return 0


    def get_netflow_profiles(self):
        """Получаем список профилей netflow группы шаблонов и устанавливаем значение self.mc_data['netflow_profiles']"""
        self.mc_data['netflow_profiles']['undefined'] = BaseObject(id='undefined', template_id='', template_name='')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_netflow_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['netflow_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль netflow "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['netflow_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_lldp_profiles(self):
        """Получаем список профилей lldp группы шаблонов и устанавливаем значение self.mc_data['lldp_profiles']"""
        self.mc_data['lldp_profiles']['undefined'] = BaseObject(id='undefined', template_id='', template_name='')
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_lldp_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['lldp_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль lldp "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['lldp_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_ssl_forward_profiles(self):
        """Получаем список профилей пересылки SSL группы шаблонов и устанавливаем значение self.mc_data['ssl_forward_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_ssl_forward_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['ssl_forward_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль пересылки SSL "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['ssl_forward_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['ssl_forward_profiles'][-1] = BaseObject(id=-1, template_id='', template_name='')
        return 0


    def get_hip_objects(self):
        """Получаем список HIP объектов группы шаблонов и устанавливаем значение self.mc_data['hip_objects']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_hip_objects(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['hip_objects']:
                    self.stepChanged.emit(f'ORANGE|    HIP объект "{x["name"]}" обнаружен в нескольких шаблонах группы. HIP объект из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['hip_objects'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_hip_profiles(self):
        """Получаем список HIP профилей группы шаблонов и устанавливаем значение self.mc_data['hip_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_hip_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['hip_profiles']:
                    self.stepChanged.emit(f'ORANGE|    HIP профиль "{x["name"]}" обнаружен в нескольких шаблонах группы. HIP профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['hip_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_bfd_profiles(self):
        """Получаем список BFD профилей группы шаблонов и устанавливаем значение self.mc_data['bfd_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_bfd_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['bfd_profiles']:
                    self.stepChanged.emit(f'ORANGE|    BFD профиль "{x["name"]}" обнаружен в нескольких шаблонах группы. BFD профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['bfd_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_useridagent_filters(self):
        """Получаем Syslog фильтры агента UserID группы шаблонов и устанавливаем значение self.mc_data['userid_filters']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_useridagent_filters(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['userid_filters']:
                    self.stepChanged.emit(f'ORANGE|    Syslog фильтр агента UserID "{x["name"]}" обнаружен в нескольких шаблонах группы. Фильтр из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['userid_filters'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_gateways_list(self):
        """Получаем список всех шлюзов в группе шаблонов и устанавливаем значение self.mc_data['gateways']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_gateways(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                xname = x.get("name", x["ipv4"])
                gateway_name = f'{xname}:{x["node_name"]}'
                if gateway_name in self.mc_data['gateways']:
                    self.stepChanged.emit(f'ORANGE|    Шлюз "{xname}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. Шлюз из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['gateways'][gateway_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_interfaces_list(self):
        """Получаем список всех интерфейсов в группе шаблонов и устанавливаем значение self.mc_data['interfaces']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_interfaces_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['kind'] not in ('bridge', 'bond', 'adapter', 'vlan', 'tunnel', 'vpn') or x['master']:
                    continue
                iface_name = f'{x["name"]}:{x["node_name"]}'
                if iface_name in self.mc_data['interfaces'] and x['kind'] in ('vlan', 'tunnel'):
                    self.stepChanged.emit(f'ORANGE|    Интерфейс "{x["name"]}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. Интерфейс из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['interfaces'][iface_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vrf_list(self):
        """Получаем список всех VRF в группе шаблонов и устанавливаем значение self.mc_data['vrf']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_vrf_list(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                vrf_name = f'{x["name"]}:{x["node_name"]}'
                if vrf_name in self.mc_data['vrf']:
                    self.stepChanged.emit(f'ORANGE|    VRF "{x["name"]}" для узла кластера "{x["node_name"]}" обнаружен в нескольких шаблонах группы. VRF из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['vrf'][vrf_name] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_client_certificate_profiles(self):
        """
        Получаем список профилей клиентских сертификатов в группе шаблонов и устанавливаем значение self.mc_data['client_cert_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_client_certificate_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['client_certs_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль клиентского сертификата "{x["name"]}" обнаружен в нескольких шаблонах группы. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['client_certs_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_auth_servers(self):
        """Получаем список всех серверов аутентификации в группе шаблонов и устанавливаем значение self.mc_data['auth_servers']"""
        auth_servers = {'ldap': {}, 'ntlm': {}, 'radius': {}, 'tacacs_plus': {}, 'saml_idp': {}}
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_auth_servers(uid)
            if err == 1:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in auth_servers[x['type']]:
                    self.stepChanged.emit(f'ORANGE|    Сервер аутентификации "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сервер из шаблона "{name}" не будет использован.')
                else:
                    auth_servers[x['type']][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['auth_servers'] = auth_servers
        return 0


    def get_profiles_2fa(self):
        """Получаем список профилей MFA в группе шаблонов и устанавливаем значение self.mc_data['profiles_2fa']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_2fa_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['profiles_2fa']:
                    self.stepChanged.emit(f'ORANGE|    Профиль MFA "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['profiles_2fa'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_captive_profiles(self):
        """Получаем список Captive-профилей и устанавливаем значение self.mc_data['captive_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_captive_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['captive_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Captive-профиль "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['captive_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_dos_profiles(self):
        """Получаем список профилей DoS и устанавливаем значение self.mc_data['dos_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_dos_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['dos_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль DoS "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль DoS из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['dos_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_waf_custom_layers(self):
        """Получаем список персональных слоёв WAF и устанавливаем значение self.mc_data['waf_custom_layers']"""
        err, result = self.utm.get_template_waf_custom_layers(self.template_id)
        if err:
            self.stepChanged.emit(f'RED|    {result}')
            self.error = 1
            return 1
        self.waf_custom_layers = {x['name']: x['id'] for x in result}
        return 0


    def get_waf_profiles(self):
        """Получаем список профилей WAF и устанавливаем значение self.mc_data['waf_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_waf_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['waf_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль WAF "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['waf_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_upstream_proxies_servers(self):
        """Получаем сервера вышестоящих прокси и устанавливаем значение self.mc_data['upstreamproxies_servers']"""
        if self.utm.float_version < 7.4:
            return 0

        for uid, name in self.templates.items():
            err, result = self.utm.get_template_cascade_proxy_servers(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['upstreamproxies_servers']:
                    self.stepChanged.emit(f'ORANGE|    Сервер вышестоящих прокси "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Сервер из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['upstreamproxies_servers'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_upstream_proxies_profiles(self):
        """Получаем профили вышестоящих прокси и устанавливаем значение self.mc_data['upstreamproxies_profiles']"""
        if self.utm.float_version < 7.4:
            return 0

        for uid, name in self.templates.items():
            err, result = self.utm.get_template_cascade_proxy_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['upstreamproxies_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль вышестоящих прокси "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['upstreamproxies_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vpn_client_security_profiles(self):
        """Получаем клиентские профили безопасности VPN и устанавливаем значение self.mc_data['vpn_client_security_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_vpn_client_security_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['vpn_client_security_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Клиентский профиль безопасности VPN "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['vpn_client_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vpn_server_security_profiles(self):
        """Получаем серверные профили безопасности VPN и устанавливаем значение self.mc_data['vpn_server_security_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_vpn_server_security_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['vpn_server_security_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Серверный профиль безопасности VPN "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['vpn_server_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def get_vpn_networks(self):
        """Получаем сети VPN и устанавливаем значение self.mc_data['vpn_networks']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_vpn_networks(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['vpn_networks']:
                    self.stepChanged.emit(f'ORANGE|    Сеть VPN "{x["name"]}" обнаружена в нескольких шаблонах группы шаблонов. Сеть VPN из шаблона "{name}" не будет использована.')
                else:
                    self.mc_data['vpn_networks'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        self.mc_data['vpn_networks'][False] = BaseObject(id=False, template_id=uid, template_name=name)
        return 0


    def get_snmp_security_profiles(self):
        """Получаем сети VPN и устанавливаем значение self.mc_data['snmp_security_profiles']"""
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_snmp_security_profiles(uid)
            if err:
                self.stepChanged.emit(f'RED|    {result}')
                self.error = 1
                return 1
            for x in result:
                if x['name'] in self.mc_data['snmp_security_profiles']:
                    self.stepChanged.emit(f'ORANGE|    Профиль безопасности SNMP "{x["name"]}" обнаружен в нескольких шаблонах группы шаблонов. Профиль из шаблона "{name}" не будет использован.')
                else:
                    self.mc_data['snmp_security_profiles'][x['name']] = BaseObject(id=x['id'], template_id=uid, template_name=name)
        return 0


    def add_empty_vrf(self, vrf_name, ports):
        """Добавляем пустой VRF"""
        vrf = {
            'name': vrf_name,
            'description': '',
            'node_name': self.node_name,
            'interfaces': ports if vrf_name != 'default' else [],
            'routes': [],
            'ospf': {},
            'bgp': {},
            'rip': {},
            'pimsm': {}
        }
        err, result = self.utm.add_template_vrf(self.template_id, vrf)
        if err:
            return err, result
        return 0, result    # Возвращаем ID добавленного VRF


    def add_new_nlist(self, name, nlist_type, content):
        """Добавляем в библиотеку новый nlist с содержимым"""
        nlist = {
            'name': name,
            'description': '',
            'type': nlist_type,
            'list_type_update': 'static',
            'schedule': 'disabled',
            'attributes': {'threat_level': 3},
        }
        err, list_id = self.utm.add_template_nlist(self.template_id, nlist)
        if err:
            return err, list_id
        err, result = self.utm.add_template_nlist_items(self.template_id, list_id, content)
        if err:
            return err, result
        return 0, list_id


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
        self.service_ids = {
            'Ping': 'ffffff03-ffff-ffff-ffff-ffffff000001',
            'SNMP': 'ffffff03-ffff-ffff-ffff-ffffff000002',
            'Captive-портал и страница блокировки': 'ffffff03-ffff-ffff-ffff-ffffff000004',
            'XML-RPC для управления': 'ffffff03-ffff-ffff-ffff-ffffff000005',
            'Кластер': 'ffffff03-ffff-ffff-ffff-ffffff000006',
            'VRRP': 'ffffff03-ffff-ffff-ffff-ffffff000007',
            'Консоль администрирования': 'ffffff03-ffff-ffff-ffff-ffffff000008',
            'DNS': 'ffffff03-ffff-ffff-ffff-ffffff000009',
            'HTTP(S)-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000010',
            'Агент аутентификации': 'ffffff03-ffff-ffff-ffff-ffffff000011',
            'SMTP(S)-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000012',
            'POP(S)-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000013',
            'CLI по SSH': 'ffffff03-ffff-ffff-ffff-ffffff000014',
            'VPN': 'ffffff03-ffff-ffff-ffff-ffffff000015',
#           'SCADA': 'ffffff03-ffff-ffff-ffff-ffffff000017',
            'Reverse-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000018',
            'Веб-портал': 'ffffff03-ffff-ffff-ffff-ffffff000019',
            'SAML сервер': 'ffffff03-ffff-ffff-ffff-ffffff000022',
            'Log analyzer': 'ffffff03-ffff-ffff-ffff-ffffff000023',
            'OSPF': 'ffffff03-ffff-ffff-ffff-ffffff000024',
            'BGP': 'ffffff03-ffff-ffff-ffff-ffffff000025',
            'RIP': 'ffffff03-ffff-ffff-ffff-ffffff000030',
            'SNMP-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000026',
            'SSH-прокси': 'ffffff03-ffff-ffff-ffff-ffffff000027',
            'Multicast': 'ffffff03-ffff-ffff-ffff-ffffff000028',
            'NTP сервис': 'ffffff03-ffff-ffff-ffff-ffffff000029',
            'UserID syslog collector': 'ffffff03-ffff-ffff-ffff-ffffff000031',
            'BFD': 'ffffff03-ffff-ffff-ffff-ffffff000032',
            'Endpoints connect': 'ffffff03-ffff-ffff-ffff-ffffff000033',
            'API XML RPC поверх HTTPS': 'ffffff03-ffff-ffff-ffff-ffffff000034'
        }
        self.error = 0
        self.check_services_access()
        self.check_networks()
        self.check_sessions_limit()


    def check_services_access(self):
        """Обрабатываем сервисы из контроля доступа"""
        new_services_access = []
        for service in self.services_access:
            if service['enabled']:
                # Проверяем что такой сервис существует в этой версии МС и получаем его ID.
                service_name = service['service_id']
                if service_name == 'API XML RPC поверх HTTPS' and self.parent.utm.float_version < 7.4:
                    continue
                try:
                    service['service_id'] = self.service_ids[service_name]
                except KeyError as err:
                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. Не корректный сервис "{service_name}" в контроле доступа. Сервис не импортирован.')
                    self.description = f'{self.description}\nError: Не импортирован сервис "{service_name}" в контроль доступа.'
                    self.error = 1
                    continue
                # Приводим список разрешённых адресов сервиса к спискам IP-листов.
                if service['allowed_ips']:
                    if isinstance(service['allowed_ips'][0], list):
                        allowed_ips = []
                        for item in service['allowed_ips']:
                            if item[0] == 'list_id':
                                _, list_name = self.parent.get_transformed_name(item[1], err=0, descr='Имя списка', mode=0)
                                try:
                                    item[1] = self.parent.mc_data['ip_lists'][list_name].id
                                except KeyError as err:
                                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В контроле доступа "{service_name}" не найден список IP-адресов {err}.')
                                    self.description = f'{self.description}\nError: В контроле доступа "{service_name}" не найден список IP-адресов {err}.'
                                    self.error = 1
                                    continue
                            allowed_ips.append(item)
                        service['allowed_ips'] = allowed_ips
                    else:
                        nlist_name = f'Zone {self.name} (service access: {service_name})'
                        if nlist_name in self.parent.mc_data['ip_lists']:
                            service['allowed_ips'] = [['list_id', self.parent.mc_data['ip_lists'][nlist_name].id]]
                        else:
                            content = [{'value': ip} for ip in service['allowed_ips']]
                            err, list_id = self.parent.add_new_nlist(nlist_name, 'network', content)
                            if err == 1:
                                message = f'Error: [Зона "{self.name}"] Не создан список IP-адресов в контроле доступа "{service_name}".'
                                self.parent.stepChanged.emit(f'RED|    {list_id}\n       {message}')
                                self.description = f'{self.description}\nError: В контроле доступа "{service_name}" не создан список IP-адресов.'
                                self.error = 1
                                continue
                            elif err == 3:
                                message = f'Warning: Список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}" уже существует.'
                                self.parent.stepChanged.emit('ORANGE|    {message}\n       Перезапустите конвертер и повторите попытку.')
                                continue
                            else:
                                self.parent.stepChanged.emit(f'BLACK|       Создан список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" для зоны "{self.name}".')
                                service['allowed_ips'] = [['list_id', list_id]]
                                self.parent.mc_data['ip_lists'][nlist_name] = BaseObject(id=list_id, template_id=self.parent.template_id, template_name=self.parent.templates[self.parent.template_id])

                new_services_access.append(service)
        self.services_access = new_services_access


    def check_networks(self):
        """Обрабатываем защиту от IP-спуфинга"""
        if self.networks:
            if isinstance(self.networks[0], list):
                new_networks = []
                for item in self.networks:
                    if item[0] == 'list_id':
                        _, list_name = self.parent.get_transformed_name(item[1], err=0, descr='Имя списка', mode=0)
                        try:
                            item[1] = self.parent.mc_data['ip_lists'][list_name].id
                        except KeyError as err:
                            self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.')
                            self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.'
                            self.error = 1
                            continue
                    new_networks.append(item)
                self.networks = new_networks
            else:
                nlist_name = f'Zone {self.name} (IP-spufing)'
                if nlist_name in self.parent.mc_data['ip_lists']:
                    self.networks = [['list_id', self.parent.mc_data['ip_lists'][nlist_name].id]]
                else:
                    content = [{'value': ip} for ip in self.networks]
                    err, list_id = self.parent.add_new_nlist(nlist_name, 'network', content)
                    if err == 1:
                        message = f'Error: [Зона "{self.name}"] Не создан список IP-адресов в защите от IP-спуфинга.'
                        self.parent.stepChanged.emit(f'RED|    {list_id}\n       {message}')
                        self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не создан список IP-адресов.'
                        self.networks = []
                        self.error = 1
                    elif err == 3:
                        message = f'Warning: Список IP-адресов "{nlist_name}" в защите от IP-спуфинга зоны "{self.name}" уже существует.'
                        self.parent.stepChanged.emit('ORANGE|    {message}\n       Перезапустите конвертер и повторите попытку.')
                    else:
                        self.parent.stepChanged.emit(f'BLACK|       Создан список IP-адресов "{nlist_name}" в защите от IP-спуфинга для зоны "{self.name}".')
                        self.networks = [['list_id', list_id]]
                        self.parent.mc_data['ip_lists'][nlist_name] = BaseObject(id=list_id, template_id=self.parent.template_id, template_name=self.parent.templates[self.parent.template_id])
        if not self.networks:
            self.enable_antispoof = False
            self.antispoof_invert = False


    def check_sessions_limit(self):
        """Обрабатываем ограничение сессий"""
        new_sessions_limit_exclusions = []
        for item in self.sessions_limit_exclusions:
            try:
                item[1] = self.parent.mc_data['ip_lists'][item[1]].id
                new_sessions_limit_exclusions.append(item)
            except KeyError as err:
                self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Ограничение сессий" не найден список IP-адресов {err}.')
                self.description = f'{self.description}\nError: В разделе "Ограничение сессий" не найден список IP-адресов {err}.'
                self.error = 1
        self.sessions_limit_exclusions = new_sessions_limit_exclusions
        if not self.sessions_limit_exclusions:
            self.sessions_limit_enabled = False


