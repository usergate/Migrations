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
# Классы экспорта конфигурации из шаблона UserGate Management Center.
# Версия 0.1 09.10.2024
#

import os, sys, json
import common_func as func
from datetime import datetime as dt
from xmlrpc.client import DateTime as class_DateTime
from PyQt6.QtCore import QThread, pyqtSignal
from services import trans_filename, default_urlcategorygroup


class ExportAll(QThread):
    """Экспортируем всю конфигурацию с NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points):
        super().__init__()
        self.utm = utm
        self.config_path = config_path      # Путь к каталогу с конфигурацией данного узла
        self.all_points = all_points
#        self.scenarios_rules = {}           # Устанавливаются через функцию set_scenarios_rules()
#        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.error = 0

    def run(self):
        """Экспортируем всё в пакетном режиме"""
        err, self.ngfw_data = func.read_bin_file(self)
        if err:
            self.stepChanged.emit('iRED|Экспорт конфигурации с UserGate NGFW прерван!')
            return

        for item in self.all_points:
            top_level_path = os.path.join(self.config_path, item['path'])
            for point in item['points']:
                current_path = os.path.join(top_level_path, point)
                if point in export_funcs:
                    export_funcs[point](self, current_path)
                else:
                    self.error = 1
                    self.stepChanged.emit(f'RED|Не найдена функция для экспорта {point}!')

        self.stepChanged.emit('iORANGE|Экспорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Экспорт всей конфигурации прошёл успешно.\n')


class ExportSelectedPoints(QThread):
    """Экспортируем выделенный раздел конфигурации с NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, selected_path, selected_points, template_id):
        super().__init__()
        self.utm = utm
        self.config_path = config_path
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.template_id = template_id

#        self.scenarios_rules = {}           # Устанавливаются через функцию set_scenarios_rules()
        self.error = 0

    def run(self):
        """Экспортируем определённый раздел конфигурации"""
        # Читаем бинарный файл библиотечных данных.
        err, self.mc_data = func.read_bin_file(self)
        if err:
            self.stepChanged.emit('iRED|Экспорт конфигурации из шаблона UserGate Management Center прерван! Не удалось прочитать служебные данные.')
            return

#        try:
        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            if point in export_funcs:
                export_funcs[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для экспорта {point}!')
#        except Exception as err:
#            self.error = 1
#            self.stepChanged.emit('RED|Ошибка функции "{export_funcs[point].__name__}": {err}')

        if self.error:
            self.stepChanged.emit('iORANGE|Экспорт конфигурации прошёл с ошибками!\n')
        else:
            self.stepChanged.emit('iGREEN|Экспорт конфигурации завершён.\n')


def export_general_settings(parent, path):
    """Экспортируем раздел 'UserGate/Настройки'."""
    err, data = parent.utm.get_template_general_settings(parent.template_id)
    if err:
        parent.error = 1
        parent.stepChanged.emit('RED|    Error: Произошла ошибка получения настроек раздела "UserGate/Настройки".')
        parent.stepChanged.emit(f'RED|       {data}')
    else:
        err, msg = func.create_dir(path)
        if err:
            parent.error = 1
            parent.stepChanged.emit('RED|    Error: Произошла ошибка экспорта настроек раздела "UserGate/Настройки".')
            parent.stepChanged.emit(f'RED|       {msg}')
        else:
            export_ui(parent, path, data)
            export_ntp_settings(parent, path, data)
            export_modules(parent, path, data)
            export_cache_settings(parent, path, data)
            export_web_portal_settings(parent, path, data)
            export_upstream_proxy_settings(parent, path, data)


def export_ui(parent, path, data):
    """Экспортируем раздел 'UserGate/Настройки/Настройки интерфейса'"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Настройки интерфейса".')

    error = 0
    params = {}

    params['ui_timezone'] = data['ui_timezone']['value']
    params['ui_language'] = data['ui_language']['value']
    if data['web_console_ssl_profile_id']['value']:
        try:
            params['web_console_ssl_profile_id'] = parent.mc_data['ssl_profiles'][data['web_console_ssl_profile_id']['value']]
        except KeyError:
            parent.stepChanged.emit('RED|    Error: Не найден профиль SSL для веб-консоли. Данный параметр не экспортирован.')
            error = 1
    if data['response_pages_ssl_profile_id']['value']:
        try:
            params['response_pages_ssl_profile_id'] = parent.mc_data['ssl_profiles'][data['response_pages_ssl_profile_id']['value']]
        except KeyError:
            parent.stepChanged.emit('RED|    Error: Не найден профиль SSL для страниц блокировки/аутентификации. Данный параметр не экспортирован.')
            error = 1
    if data['endpoint_ssl_profile_id']['value']:
        try:
            params['endpoint_ssl_profile_id'] = parent.mc_data['ssl_profiles'][data['endpoint_ssl_profile_id']['value']]
        except KeyError:
            parent.stepChanged.emit('RED|    Error: Не найден профиль SSL конечного устройства. Данный параметр не экспортирован.')
            error = 1
    if data['endpoint_certificate_id']['value']:
        try:
            params['endpoint_certificate_id'] = parent.mc_data['certs'][data['endpoint_certificate_id']['value']]
        except KeyError:
            parent.stepChanged.emit('RED|    Error: Не найден сертификат конечного устройства. Данный параметр не экспортирован.')
            error = 1
    params['webui_auth_mode'] = data['webui_auth_mode']['value']

    json_file = os.path.join(path, 'config_settings_ui.json')
    with open(json_file, 'w') as fh:
        json.dump(params, fh, indent=4, ensure_ascii=False)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек интерфейса.')
    else:
        parent.stepChanged.emit(f'GREEN|    Настройки интерфейса выгружены в файл "{json_file}".')


def export_ntp_settings(parent, path, data):
    """Экспортируем настройки NTP"""
    parent.stepChanged.emit('BLUE|Экспорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')

    ntp_settings = {
        'ntp_servers': [],
        'ntp_enabled': data['ntp_enabled']['value']
    }
    if data['ntp_server1']['value']:
        ntp_settings['ntp_servers'].append(data['ntp_server1']['value'])
    if data['ntp_server2']['value']:
        ntp_settings['ntp_servers'].append(data['ntp_server2']['value'])

    if ntp_settings['ntp_servers']:
        json_file = os.path.join(path, 'config_ntp.json')
        with open(json_file, 'w') as fh:
            json.dump(ntp_settings, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки NTP выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет настроек NTP для экспорта.')


def export_modules(parent, path, data):
    """Экспортируем раздел 'UserGate/Настройки/Модули'"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Модули".')
    error = 0

    proxy_port = data['proxy_server_port']['value']
    json_file = os.path.join(path, 'config_proxy_port.json')
    with open(json_file, 'w') as fh:
        json.dump(proxy_port, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт выгружен в файл "{json_file}".')

    saml_port = data['saml_server_port']['value']
    json_file = os.path.join(path, 'config_saml_port.json')
    with open(json_file, 'w') as fh:
        json.dump(saml_port, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    Порт SAML-сервера выгружен в файл "{json_file}".')

    params = {
        'auth_captive': data['auth_captive']['value'],
        'logout_captive': data['logout_captive']['value'],
        'block_page_domain': data['block_page_domain']['value'],
        'ftpclient_captive': data['ftpclient_captive']['value'],
        'ftp_proxy_enabled': data['ftp_proxy_enabled']['value'],
        'lldp_config': data['lldp_config']['value']
    }
    if data['tunnel_inspection_zone_config']['value']['target_zone']:
        try:
            params['tunnel_inspection_zone_config'] = {
                'target_zone': parent.mc_data['zones'][data['tunnel_inspection_zone_config']['value']['target_zone']],
                'enabled': data['tunnel_inspection_zone_config']['value']['enabled']
            }
        except KeyError:
            parent.stepChanged.emit('RED|    Error: Не найдена зона. Параметр "Зона для инспектируемых туннелей" не экспортирован.')
            error = 1
    
    json_file = os.path.join(path, 'config_settings_modules.json')
    with open(json_file, 'w') as fh:
        json.dump(params, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    Настройки модулей выгружены в файл "{json_file}".')

    if error:
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорта настроек модулей.')
    else:
        parent.stepChanged.emit(f'GREEN|    Раздел "UserGate/Настройки/Модули" экспортирован успешно.')


def export_cache_settings(parent, path, data):
    """Экспортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "UserGate/Настройки/Настройки кэширования HTTP".')
    error = 0

    params = data['http_cache']['value']
    params['add_via_enabled'] = data['advanced']['value']['add_via_enabled']
    params['add_forwarded_enabled'] = data['advanced']['value']['add_forwarded_enabled']
    params['smode_enabled'] = data['advanced']['value']['smode_enabled']
    params['module_l7_enabled'] = data['advanced']['value']['module_l7_enabled']
    params['http_connection_timeout'] = data['advanced']['value']['http_connection_timeout']
    params['http_loading_timeout'] = data['advanced']['value']['http_loading_timeout']

    json_file = os.path.join(path, 'config_proxy_settings.json')
    with open(json_file, 'w') as fh:
        json.dump(params, fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    Настройки кэширования HTTP и доп.параметры выгружены в файл "{json_file}".')


    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'httpcwl')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        if result:
            err, data = parent.utm.get_template_nlist_items(parent.template_id, result[0]['id'])
            if err:
                parent.stepChanged.emit(f'RED|    {data}')
                error = 1
            else:
                if data:
                    for item in data:
                        item.pop('id')
                    json_file = os.path.join(path, 'config_proxy_exceptions.json')
                    with open(json_file, 'w') as fh:
                        json.dump(data, fh, indent=4, ensure_ascii=False)
                    parent.stepChanged.emit(f'BLACK|    Исключения из кэширования HTTP выгружены в файл "{json_file}".')
                else:
                    parent.stepChanged.emit(f'GRAY|    Нет исключений кэширования HTTP.')
        else:
            parent.stepChanged.emit(f'GRAY|    Нет исключений кэширования HTTP.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек кэширования HTTP.')
    else:
        parent.stepChanged.emit(f'GREEN|    Раздел "UserGate/Настройки/Настройки кэширования HTTP" экспортирован успешно.')


def export_web_portal_settings(parent, path, data):
    """Экспортируем настройки веб-портала"""
    parent.stepChanged.emit('BLUE|Выгружаются настройки Веб-портала раздела "UserGate/Настройки/Веб-портал":')
    error = 0

    err, result = parent.utm.get_realm_responsepages_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        list_templates = {x['id']: x['name'] for x in result}

        err, result = parent.utm.get_realm_client_certificate_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            client_certificate_profiles = {x['id']: x['name'] for x in result}

            params = data['proxy_portal']['value']
            params['user_auth_profile_id'] = parent.mc_data['auth_profiles'].get(params['user_auth_profile_id'], -1)
            params['proxy_portal_template_id'] = list_templates.get(params['proxy_portal_template_id'], -1)
            params['proxy_portal_login_template_id'] = list_templates.get(params['proxy_portal_login_template_id'], -1)
            params['certificate_id'] = parent.mc_data['certs'].get(params['certificate_id'], -1)
            params['ssl_profile_id'] = parent.mc_data['ssl_profiles'].get(params['ssl_profile_id'], -1)
            if params['client_certificate_profile_id']:
                try:
                    params['client_certificate_profile_id'] = client_certificate_profiles[params['client_certificate_profile_id']]
                except KeyError:
                    parent.stepChanged.emit('bRED|    Warning: Не найден профиль клиентского сертификата.')
                    params['client_certificate_profile_id'] = 0
                    params['cert_auth_enabled'] = False
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек Веб-портала!')
    else:
        json_file = os.path.join(path, 'config_web_portal.json')
        with open(json_file, 'w') as fh:
            json.dump(params, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки Веб-портала выгружены в файл "{json_file}".')


def export_upstream_proxy_settings(parent, path, data):
    """Экспортируем настройки вышестоящего прокси"""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

    json_file = os.path.join(path, 'upstream_proxy_settings.json')
    with open(json_file, 'w') as fh:
        json.dump(data['upstream_proxy']['value'], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    Настройки вышестоящего прокси выгружены в файл "{json_file}".')

    json_file = os.path.join(path, 'upstream_proxy_check_update.json')
    with open(json_file, 'w') as fh:
        json.dump(data['upstream_update_proxy']['value'], fh, indent=4, ensure_ascii=False)
    parent.stepChanged.emit(f'BLACK|    Настройки вышестоящего прокси для проверки лицензии и обновлений выгружены в файл "{json_file}".')

    parent.stepChanged.emit('GREEN|    Настройки вышестоящего прокси экспортированы.')


def export_certificates(parent, path):
    """Экспортируем сертификаты."""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Сертификаты".')
    error = 0

    err, result = parent.utm.get_template_certificates_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        for item in result:
            parent.stepChanged.emit(f'BLACK|    Экспорт сертификата {item["name"]}.')
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
            err, msg = func.create_dir(path_cert)
            if err:
                parent.stepChanged.emit(f'RED|       {msg}')
                error = 1
            else:
                # Выгружаем сертификат в формат DER.
                err, base64_cert = parent.utm.get_template_certificate_data(parent.template_id, item['id'])
                if err:
                    parent.stepChanged.emit(f'RED|       {base64_cert}')
                    error = 1
                else:
                    with open(os.path.join(path_cert, 'cert.der'), 'wb') as fh:
                        fh.write(base64_cert.data)

                # Выгружаем сертификат с цепочками в формат PEM.
                err, base64_cert = parent.utm.get_template_certificate_chain_data(parent.template_id, item['id'])
                if err:
                    parent.stepChanged.emit(f'ORANGE|       Не удалось выгрузить сертификат в формате PEM [{base64_cert}]')
                    error = 1
                else:
                    with open(os.path.join(path_cert, 'cert.pem'), 'wb') as fh:
                        fh.write(base64_cert.data)

                # Выгружаем детальную информацию сертификата в файл certificate_details.json.
                err, details_info = parent.utm.get_template_certificate_details(parent.template_id, item['id'])
                if err:
                    parent.stepChanged.emit(f'RED|       {details_info}')
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
            parent.stepChanged.emit(f'BLACK|       Сертификат {item["name"]} экспортирован в каталог {path_cert}.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте сертификатов.')
    else:
        parent.stepChanged.emit(f'GREEN|    Сертификаты выгружены в каталог "{path}".')


def export_users_certificate_profiles(parent, path):
    """Экспортируем профили пользовательских сертификатов."""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "UserGate/Профили пользовательских сертификатов".')

    err, result = parent.utm.get_template_client_certificate_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла оОшибка при экспорте профилей пользовательских сертификатов.')
        parent.error = 1
        return

    if result:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей пользовательских сертификатов.')
            parent.error = 1
            return

        for item in result:
            item.pop('id', None)
            item.pop('template_id', None)

            item['ca_certificates'] = [parent.mc_data['certs'][x] for x in item['ca_certificates']]

        json_file = os.path.join(path, 'users_certificate_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Профили пользовательских сертификатов выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет профилей пользовательских сертификатов для экспорта.')


def export_zones(parent, path):
    """Экспортируем список зон."""
    parent.stepChanged.emit('BLUE|Экспорт настроек раздела "Сеть/Зоны".')

    err, data = parent.utm.get_template_zones_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте зон.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте зон.')
            parent.error = 1
            return

        service_ids = {
            'ffffff03-ffff-ffff-ffff-ffffff000001': 'Ping',
            'ffffff03-ffff-ffff-ffff-ffffff000002': 'SNMP',
            'ffffff03-ffff-ffff-ffff-ffffff000004': 'Captive-портал и страница блокировки',
            'ffffff03-ffff-ffff-ffff-ffffff000005': 'XML-RPC для управления',
            'ffffff03-ffff-ffff-ffff-ffffff000006': 'Кластер',
            'ffffff03-ffff-ffff-ffff-ffffff000007': 'VRRP',
            'ffffff03-ffff-ffff-ffff-ffffff000008': 'Консоль администрирования',
            'ffffff03-ffff-ffff-ffff-ffffff000009': 'DNS',
            'ffffff03-ffff-ffff-ffff-ffffff000010': 'HTTP(S)-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000011': 'Агент аутентификации',
            'ffffff03-ffff-ffff-ffff-ffffff000012': 'SMTP(S)-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000013': 'POP(S)-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000014': 'CLI по SSH',
            'ffffff03-ffff-ffff-ffff-ffffff000015': 'VPN',
            'ffffff03-ffff-ffff-ffff-ffffff000017': 'SCADA',
            'ffffff03-ffff-ffff-ffff-ffffff000018': 'Reverse-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000019': 'Веб-портал',
            'ffffff03-ffff-ffff-ffff-ffffff000022': 'SAML сервер',
            'ffffff03-ffff-ffff-ffff-ffffff000023': 'Log analyzer',
            'ffffff03-ffff-ffff-ffff-ffffff000024': 'OSPF',
            'ffffff03-ffff-ffff-ffff-ffffff000025': 'BGP',
            'ffffff03-ffff-ffff-ffff-ffffff000030': 'RIP',
            'ffffff03-ffff-ffff-ffff-ffffff000026': 'SNMP-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000027': 'SSH-прокси',
            'ffffff03-ffff-ffff-ffff-ffffff000028': 'Multicast',
            'ffffff03-ffff-ffff-ffff-ffffff000029': 'NTP сервис',
            'ffffff03-ffff-ffff-ffff-ffffff000031': 'UserID syslog collector',
            'ffffff03-ffff-ffff-ffff-ffffff000032': 'BFD',
            'ffffff03-ffff-ffff-ffff-ffffff000033': 'Endpoints connect'
        }
        error = 0

        for zone in data:
            zone['name'] = zone['name']
            zone.pop('id', None)
            zone.pop('template_id', None)
            for net in zone['networks']:
                if net[0] == 'list_id':
                    net[1] = parent.mc_data['ip_lists'][net[1]]
            for item in zone['sessions_limit_exclusions']:
                item[1] = parent.mc_data['ip_lists'][item[1]]

            new_services_access = []
            for service in zone['services_access']:
                for item in service['allowed_ips']:
                    if item[0] == 'list_id':
                        item[1] = parent.mc_data['ip_lists'][item[1]]
                try:
                    service['service_id'] = service_ids[service['service_id']]
                    new_services_access.append(service)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|       Error [Зона "{zone["name"]}"]. Не экспортирован сервис с ID "{err}" в контроль доступа.')
                    zone['description'] = f'{zone["description"]}\nError: Не экспортирован сервис с ID "{err}" в контроль доступа.'
                    error = 1
            zone['services_access'] = new_services_access

        json_file = os.path.join(path, 'config_zones.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

        if error:
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте зон.')
            parent.error = 1
        parent.stepChanged.emit(f'GREEN|    Настройки зон выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет зон для экспорта.')


def export_interfaces_list(parent, path):
    """Экспортируем список интерфейсов"""
    parent.stepChanged.emit('BLUE|Экспорт интерфейсов из раздела "Сеть/Интерфейсы".')

    err, result = parent.utm.get_template_netflow_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте интерфейсов.')
        parent.error = 1
        return
    list_netflow = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_template_lldp_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте интерфейсов.')
        parent.error = 1
        return
    list_lldp = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_template_interfaces_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте интерфейсов.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте интерфейсов.')
            parent.error = 1
            return
        error = 0

        for item in data:
            item['id'], _ = item['id'].split(':')
            item.pop('link_info', None)
            item.pop('speed', None)
            item.pop('errors', None)
            item.pop('running', None)
            item.pop('template_id', None)
            item.pop('_cc_node_name', None)
            if item['zone_id']:
                item['zone_id'] = parent.mc_data['zones'].get(item['zone_id'], 0)
            item['netflow_profile'] = list_netflow.get(item['netflow_profile'], 'undefined')
            item['lldp_profile'] = list_lldp.get(item['lldp_profile'], 'undefined')

            new_ipv4 = []
            for ips in item['ipv4']:
                err, result = func.pack_ip_addr(ips['ip'], ips['mask'])
                if err:
                    parent.stepChanged.emit(f'RED|    Не удалось преобразовать IP: "{ips}" для интерфейса "{item["name"]}".')
                    item['description'] = f'{item["description"]}\nError: Не удалось преобразовать IP: "{ips}".'
                    error = 1
                else:
                    new_ipv4.append(result)
            item['ipv4'] = new_ipv4

        data.sort(key=lambda x: x['name'])

        json_file = os.path.join(path, 'config_interfaces.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        if error:
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте интерфейсов.')
        parent.stepChanged.emit(f'GREEN|    Настройки интерфейсов выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет интерфейсов для экспорта.')


def export_gateways_list(parent, path):
    """Экспортируем список шлюзов"""
    parent.stepChanged.emit('BLUE|Экспорт раздела "Сеть/Шлюзы".')

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте шлюзов.')
        parent.error = 1
        return

    if result:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте шлюзов.')
            parent.error = 1
            return

        for item in result:
            item.pop('id', None)
            item.pop('_cc_node_name', None)
            item.pop('template_id', None)
            if not item.get('name', False):
                item['name'] = item['ipv4']
 
        json_file = os.path.join(path, 'config_gateways.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки шлюзов выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет шлюзов для экспорта.')

    """Экспортируем настройки проверки сети шлюзов"""
    err, result = parent.utm.get_template_gateway_failover(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек проверки сети.')
        parent.error = 1
    else:
        result.pop('cc_enabled', None)
        json_file = os.path.join(path, 'config_gateway_failover.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки "Проверка сети" выгружены в файл "{json_file}".')

    parent.stepChanged.emit('GREEN|    Экспорт раздела "Сеть/Шлюзы" завершён.')


def export_dhcp_subnets(parent, path):
    """Экспортируем настройки DHCP"""
    parent.stepChanged.emit('BLUE|Экспорт настроек DHCP раздела "Сеть/DHCP".')

    err, result = parent.utm.get_template_dhcp_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DHCP.')
        parent.error = 1
        return

    if result:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DHCP.')
            parent.error = 1
            return

        for item in result:
            item.pop('id', None)
            item.pop('template_id', None)
            item.pop('_cc_node_name', None)

        json_file = os.path.join(path, 'config_dhcp_subnets.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки DHCP выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет настроек DHCP для экспорта.')


def export_dns_config(parent, path):
    """Экспортируем настройки DNS"""
    parent.stepChanged.emit('BLUE|Экспорт настройек DNS раздела "Сеть/DNS".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    error = 0
    err, result = parent.utm.get_template_dns_settings(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DNS-прокси шаблона. Данные настройки не экспортированы.')
        error = 1
    else:
        params = {}
        for item in result:
            params[item['code']] = item['value']

        json_file = os.path.join(path, 'config_dns_proxy.json')
        with open(json_file, 'w') as fh:
            json.dump(params, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки DNS-прокси выгружены в файл "{json_file}".')

    err, result = parent.utm.get_template_dns_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте системных DNS-серверов шаблона. Данные настройки не экспортированы.')
        error = 1
    else:
        json_file = os.path.join(path, 'config_dns_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список системных DNS серверов выгружен в файл "{json_file}".')
    
    err, result = parent.utm.get_template_dns_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил DNS прокси шаблона. Данные настройки не экспортированы.')
        error = 1
    else:
        for item in result:
            item.pop('id', None)
            item.pop('template_id', None)
            item.pop('grid_position', None)
        json_file = os.path.join(path, 'config_dns_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список правил DNS прокси выгружен в файл "{json_file}".')
    
    err, result = parent.utm.get_template_dns_static_records(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте статических записей DNS шаблона. Данные настройки не экспортированы.')
        error = 1
    else:
        for item in result:
            item.pop('id', None)
            item.pop('template_id', None)
        json_file = os.path.join(path, 'config_dns_static.json')
        with open(json_file, 'w') as fh:
            json.dump(result, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Статические записи DNS прокси выгружены в файл "{json_file}".')

    if error:
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек DNS.')
    else:
        parent.stepChanged.emit(f'GREEN|    Настройки DNS экспортированы в каталог "{path}".')


def export_vrf_list(parent, path):
    """Экспортируем настройки VRF"""
    parent.stepChanged.emit('BLUE|Экспорт настроек VRF раздела "Сеть/Виртуальные маршрутизаторы".')

    err, result = parent.utm.get_template_bfd_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек VRF.')
        parent.error = 1
        return
    bfd_profiles = {x['id']: x['name'] for x in result}
    bfd_profiles[-1] = -1

    err, data = parent.utm.get_template_vrf_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек VRF.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек VRF.')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            item.pop('_cc_node_name', None)

            for x in item['routes']:
                x.pop('id', None)
            route_maps = {}
            filters = {}
            item['bgp'].pop('id', None)
            if item['bgp']['as_number'] == "null":
                item['bgp']['as_number'] = 0
            for x in item['bgp']['routemaps']:
                route_maps[x['id']] = x['name']
                x.pop('id', None)
            for x in item['bgp']['filters']:
                filters[x['id']] = x['name']
                x.pop('id', None)
            for x in item['bgp']['neighbors']:
                x.pop('id', None)
                x['remote_asn'] = int(x['remote_asn'])
                for i, rmap in enumerate(x['filter_in']):
                    x['filter_in'][i] = filters[rmap]
                for i, rmap in enumerate(x['filter_out']):
                    x['filter_out'][i] = filters[rmap]
                for i, rmap in enumerate(x['routemap_in']):
                    x['routemap_in'][i] = route_maps[rmap]
                for i, rmap in enumerate(x['routemap_out']):
                    x['routemap_out'][i] = route_maps[rmap]
                x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
            item['ospf'].pop('id', None)
            for x in item['ospf']['interfaces']:
                x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
            for x in item['ospf']['areas']:
                x.pop('id', None)
            item['rip'].pop('id', None)
            if not isinstance(item['rip']['default_originate'], bool):
                item['rip']['default_originate'] = True
            item['pimsm'].pop('id', None)

        json_file = os.path.join(path, 'config_vrf.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Настройки VRF выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет VRF для экспорта.')


def export_wccp(parent, path):
    """Экспортируем список правил WCCP"""
    parent.stepChanged.emit('BLUE|Экспорт списка правил WCCP из раздела "Сеть/WCCP".')

    err, data = parent.utm.get_template_wccp_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка правил WCCP.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка правил WCCP.')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            for x in item['routers']:
                x[1] = parent.mc_data['ip_lists'][x[1]] if x[0] == 'list_id' else x[1]

        json_file = os.path.join(path, 'config_wccp.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список правил WCCP выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет правил WCCP для экспорта.')


def export_local_groups(parent, path):
    """Экспортируем список локальных групп пользователей"""
    parent.stepChanged.emit('BLUE|Экспорт списка локальных групп из раздела "Пользователи и устройства/Группы".')

    err, data = parent.utm.get_template_groups_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных групп.')
        parent.error = 1
        return

    if data:
        for item in data:
            item['users'] = []
            err, users = parent.utm.get_template_group_users(parent.template_id, item['id'])
            if err:
                parent.stepChanged.emit(f'RED|    {users}')
                parent.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте членов группы "{item["name"]}".')
                parent.error = 1
            else:
                for x in users:
                    user = x[1].split(f' {chr(8212)} ')[0]  # Убираем длинное тире.
                    if not '\\' in user:
                        user = user.split()[0]  # Убираем логин, оставляем имя.
                    item['users'].append(user)
            item.pop('id', None)
            item.pop('template_id', None)
            item.pop('group_type', None)
            item.pop('all_users', None)

        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных групп.')
            parent.error = 1
            return

        json_file = os.path.join(path, 'config_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список локальных групп выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет локальных групп для экспорта.')


def export_local_users(parent, path):
    """Экспортируем список локальных пользователей"""
    parent.stepChanged.emit('BLUE|Экспорт списка локальных пользователей из раздела "Пользователи и устройства/Пользователи".')

    err, data = parent.utm.get_template_users_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных пользователей.')
        parent.error = 1
        return

    if data:
        for item in data:
            item.pop('creation_date', None)
            item.pop('expiration_date', None)
            item.pop('template_id', None)
            item.pop('user_type', None)
            err, groups = parent.utm.get_template_user_groups(parent.template_id, item['id'])
            if err:
                parent.stepChanged.emit(f'RED|    {groups}')
                parent.stepChanged.emit(f'ORANGE|    Произошла ошибка при экспорте групп пользователя "{item["name"]}".')
                parent.error = 1
                item['groups'] = []
            else:
                item['groups'] = [x['name'].split(f' {chr(8212)} ')[0] for x in groups]
            item.pop('id', None)

        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка локальных пользователей.')
            parent.error = 1
            return

        json_file = os.path.join(path, 'config_users.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список локальных пользователей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет локальных пользователей для экспорта.')


def export_auth_servers(parent, path):
    """Экспортируем список серверов аутентификации"""
    parent.stepChanged.emit('BLUE|Экспорт списка серверов аутентификации из раздела "Пользователи и устройства/Серверы аутентификации".')

    err, result = parent.utm.get_template_auth_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка серверов аутентификации.')
        parent.error = 1
        return

    if result:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка серверов аутентификации.')
            parent.error = 1
            return

        ldap = []
        radius = []
        tacacs = []
        ntlm = []
        saml = []
        for item in result:
            item.pop('id', None)
            item.pop('template_id', None)
            if item['type'] == 'ldap':
                ldap.append(item)
            if item['type'] == 'radius':
                radius.append(item)
            if item['type'] == 'tacacs_plus':
                tacacs.append(item)
            if item['type'] == 'ntlm':
                ntlm.append(item)
            if item['type'] == 'saml_idp':
                saml.append(item)
            item.pop('type', None)

        if ldap:
            json_file = os.path.join(path, 'config_ldap_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ldap, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список серверов LDAP выгружен в файл "{json_file}".')
        if radius:
            json_file = os.path.join(path, 'config_radius_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(radius, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список серверов RADIUS выгружен в файл "{json_file}".')
        if tacacs:
            json_file = os.path.join(path, 'config_tacacs_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(tacacs, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список серверов TACACS выгружен в файл "{json_file}".')
        if ntlm:
            json_file = os.path.join(path, 'config_ntlm_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(ntlm, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список серверов NTLM выгружен в файл "{json_file}".')
        if saml:
            for item in saml:
                item['certificate_id'] = parent.mc_data['certs'].get(item['certificate_id'], 0)
            json_file = os.path.join(path, 'config_saml_servers.json')
            with open(json_file, 'w') as fh:
                json.dump(saml, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список серверов SAML выгружен в файл "{json_file}".')

        parent.stepChanged.emit(f'GREEN|    Список серверов аутентификации экспортирован.')
    else:
        parent.stepChanged.emit('GRAY|    Нет серверов аутентификации для экспорта.')


def export_2fa_profiles(parent, path):
    """Экспортируем список MFA профилей"""
    parent.stepChanged.emit('BLUE|Экспорт списка MFA профилей из раздела "Пользователи и устройства/Профили MFA".')

    err, result = parent.utm.get_realm_notification_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка MFA профилей!')
        parent.error = 1
        return
    list_notifications = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_template_2fa_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка MFA профилей!')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка MFA профилей!')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            if item['type'] == 'totp':
                item['init_notification_profile_id'] = list_notifications.get(item['init_notification_profile_id'], item['init_notification_profile_id'])
                item.pop('auth_notification_profile_id', None)
            else:
                item['auth_notification_profile_id'] = list_notifications.get(item['auth_notification_profile_id'], item['auth_notification_profile_id'])
                item.pop('totp_show_qr_code', None)
                item.pop('init_notification_profile_id', None)

        json_file = os.path.join(path, 'config_2fa_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список MFA профилей выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет MFA профилей для экспорта.')


def export_auth_profiles(parent, path):
    """Экспортируем список профилей аутентификации"""
    parent.stepChanged.emit('BLUE|Экспорт списка профилей авторизации из раздела "Пользователи и устройства/Профили аутентификации".')

    err, result = parent.utm.get_realm_auth_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей аутентификации.')
        parent.error = 1
        return
    auth_servers = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_realm_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей аутентификации.')
        parent.error = 1
        return
    profiles_2fa = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_template_auth_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей аутентификации.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей аутентификации.')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            if item['2fa_profile_id']:
                try:
                    item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']]
                except KeyError:
                    parent.stepChanged.emit(f'RED|    Error [Профиль "{item["name"]}"]. Не найден профиль MFA.')
                    item['2fa_profile_id'] = False

            for auth_method in item['allowed_auth_methods']:
                if 'saml_idp_server' in auth_method:
                    auth_method['saml_idp_server_id'] = auth_method.pop('saml_idp_server', False)
                for key, value in auth_method.items():
                    if key in {'ldap_server_id', 'radius_server_id', 'tacacs_plus_server_id', 'ntlm_server_id', 'saml_idp_server_id'}:
                        if auth_method[key]:
                            auth_method[key] = auth_servers[value]

        json_file = os.path.join(path, 'config_auth_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список профилей аутентификации выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет профилей аутентификации для экспорта.')


def export_captive_profiles(parent, path):
    """Экспортируем список Captive-профилей"""
    parent.stepChanged.emit('BLUE|Экспорт списка Captive-профилей из раздела "Пользователи и устройства/Captive-профили".')

    err, result = parent.utm.get_realm_responsepages_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
        parent.error = 1
        return
    list_templates = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_realm_client_certificate_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
        parent.error = 1
        return
    client_cert_profiles = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_realm_notification_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
        parent.error = 1
        return
    list_notifications = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_template_captive_profiles(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте Captive-профилей.')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            try:
                item['captive_template_id'] = list_templates[item['captive_template_id']]
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-профиль "{item["name"]}"]. Не найден шаблон страницы аутентификации.')
                item['captive_template_id'] = -1
            try:
                item['notification_profile_id'] = list_notifications[item['notification_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-профиль "{item["name"]}"]. Не найден профиль оповещения гостевых пользователей.')
                item['notification_profile_id'] = -1
            try:
                item['user_auth_profile_id'] = parent.mc_data['auth_profiles'][item['user_auth_profile_id']]
            except KeyError:
                parent.stepChanged.emit('RED|    Error [Captive-профиль "{item["name"]}"]. Не найден профиль аутентификации. Профиль установлен в дефолтное значение.')
                item['user_auth_profile_id'] = 'Example user auth profile'

            item['ta_groups'] = [parent.mc_data['local_groups'][guid] for guid in item['ta_groups']]
            if item['ta_expiration_date']:
                item['ta_expiration_date'] = dt.strptime(item['ta_expiration_date'], "%Y-%m-%dT%H:%M:%S").strftime("%Y-%m-%d %H:%M:%S")
            try:
                item['client_certificate_profile_id'] = client_cert_profiles.get(item['client_certificate_profile_id'], 0)
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-профиль "{item["name"]}"]. Не найден профиль клиентского сертификата.')
                item['client_certificate_profile_id'] = 0

        json_file = os.path.join(path, 'config_captive_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список Captive-профилей выгружен в файл "{json_file}".')

    else:
        parent.stepChanged.emit('GRAY|    Нет профилей аутентификации для экспорта.')


def export_captive_portal_rules(parent, path):
    """Экспортируем список правил Captive-портала"""
    parent.stepChanged.emit('BLUE|Экспорт списка правил Captive-портала из раздела "Пользователи и устройства/Captive-портал".')

    err, result = parent.utm.get_realm_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил Captive-портала.')
        parent.error = 1
        return
    captive_profiles = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_template_captive_portal_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил Captive-портала.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил Captive-портала.')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            item.pop('grid_position', None)
            item['profile_id'] = captive_profiles.get(item['profile_id'], 0)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['urls'] = get_urls_name(parent, item['urls'], item['name'])
            item['url_categories'] = get_url_categories_name(parent, item['url_categories'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['time_created'] = item['time_created'].replace('T', ' ').replace('Z', '')
            item['time_updated'] = item['time_updated'].replace('T', ' ').replace('Z', '')

        json_file = os.path.join(path, 'config_captive_portal_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список правил Captive-портала выгружен в файл "{json_file}".')

    else:
        parent.stepChanged.emit('GRAY|    Нет правил Captive-портала для экспорта.')


def export_terminal_servers(parent, path):
    """Экспортируем список терминальных серверов"""
    parent.stepChanged.emit('BLUE|Экспорт списка терминальных серверов из раздела "Пользователи и устройства/Терминальные серверы".')

    err, data = parent.utm.get_template_terminal_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка терминальных серверов.')
        parent.error = 1
        return

    if data:
        err, msg = func.create_dir(path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка терминальных серверов.')
            parent.error = 1
            return

        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)

        json_file = os.path.join(path, 'config_terminal_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'GREEN|    Список терминальных серверов выгружен в файл "{json_file}".')

    else:
        parent.stepChanged.emit('GRAY|    Нет терминальных серверов для экспорта.')


def export_userid_agent(parent, path):
    """Экспортируем настройки UserID агент"""
    parent.stepChanged.emit('BLUE|Экспорт настроек UserID агент из раздела "Пользователи и устройства/UserID агент".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

# В версии 7.1 это не работает!!!!
#    err, result = parent.utm.get_template_useridagent_filters_list(parent.template_id)
#    if err:
#        parent.stepChanged.emit(f'RED|    {result}')
#        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте настроек UserID агент.')
#        parent.error = 1
#        return
#    useridagent_filters = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_template_useridagent_servers(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте агентов UserID.')
        parent.error = 1
        return

    if data:
        for item in data:
            item.pop('id', None)
            item.pop('template_id', None)
            item['auth_profile_id'] = parent.mc_data['auth_profiles'][item['auth_profile_id']]
            if 'filters' in item:
                parent.stepChanged.emit(f'ORANGE|    Error [Агент UserID "{item["name"]}"]. Не экспортированы фильтры. В вашей версии МС экспорт фильтров не работает.')
#                item['filters'] = [useridagent_filters[x] for x in item['filters']]

        json_file = os.path.join(path, 'userid_agent_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список агентов UserID выгружен в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет агентов UserID для экспорта.')

    err, data = parent.utm.get_template_useridagent_config(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте свойств агента UserID.')
        parent.error = 1
        return

    if data:
        item.pop('template_id', None)
        if data['tcp_ca_certificate_id']:
            data['tcp_ca_certificate_id'] = parent.mc_data['certs'][data['tcp_ca_certificate_id']]
        if data['tcp_server_certificate_id']:
            data['tcp_server_certificate_id'] = parent.mc_data['certs'][data['tcp_server_certificate_id']]
        data['ignore_networks'] = [['list_id', parent.mc_data['ip_lists'][x[1]]] for x in data['ignore_networks']]

        json_file = os.path.join(path, 'userid_agent_config.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Свойства агента UserID выгружены в файл "{json_file}".')
    else:
        parent.stepChanged.emit('GRAY|    Нет свойств агента UserID для экспорта.')

    parent.stepChanged.emit(f'GREEN|    Настройки UserID агент выгружены в каталог "{path}".')


def export_firewall_rules(parent, path):
    """Экспортируем список правил межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Экспорт правил межсетевого экрана из раздела "Политики сети/Межсетевой экран".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    if parent.version >= 7.1:
        err, result = parent.utm.get_idps_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        idps_profiles = {x['id']: x['name'] for x in result}

        err, result = parent.utm.get_l7_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        l7_profiles = {x['id']: x['name'] for x in result}

        err, result = parent.utm.get_hip_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        hip_profiles = {x['id']: x['name'] for x in result}

    duplicate = {}
    err, data = parent.utm.get_firewall_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in duplicate.keys():
                num = duplicate[item['name']]
                num = num + 1
                duplicate[item['name']] = num
                item['name'] = f"{item['name']} {num}"
            else:
                duplicate[item['name']] = 0
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('rownumber', None)
            item.pop('active', None)
            item.pop('deleted_users', None)

            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['services'] = get_services(parent, item['services'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            if 'apps' in item:
                item['apps'] = get_apps(parent, item['apps'], item['name'])
            if 'ips_profile' in item and item['ips_profile']:
                item['ips_profile'] = idps_profiles[item['ips_profile']]
            if 'l7_profile' in item and item['l7_profile']:
                item['l7_profile'] = l7_profiles[item['l7_profile']]
            if 'hip_profiles' in item:
                item['hip_profiles'] = [hip_profiles[x] for x in item['hip_profiles']]

        json_file = os.path.join(path, 'config_firewall_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила межсетевого экрана выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил межсетевого экрана.' if error else out_message)


def export_nat_rules(parent, path):
    """Экспортируем список правил NAT"""
    parent.stepChanged.emit('BLUE|Экспорт правил NAT из раздела "Политики сети/NAT и маршрутизация".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1
    ngfw_gateways = {f'{x["id"]}:{x["node_name"]}': x['name'] for x in result if 'name' in x}

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, data = parent.utm.get_traffic_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item.pop('guid', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            item['zone_in'] = get_zones_name(parent, item['zone_in'], item['name'])
            item['zone_out'] = get_zones_name(parent, item['zone_out'], item['name'])
            item['source_ip'] = get_ips_name(parent, item['source_ip'], item['name'])
            item['dest_ip'] = get_ips_name(parent, item['dest_ip'], item['name'])
            item['service'] = get_services(parent, item['service'], item['name'])
            item['gateway'] = ngfw_gateways.get(item['gateway'], item['gateway'])
            if parent.version >= 6:
                item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            else:
                item['users'] = []
                item['position_layer'] = 'local'
                item['time_created'] = ''
                item['time_updated'] = ''

        json_file = os.path.join(path, 'config_nat_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила NAT выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил NAT.' if error else out_message)


def export_loadbalancing_rules(parent, path):
    """Экспортируем список правил балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Экспорт правил балансировки нагрузки из раздела "Политики сети/Балансировка нагрузки".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_servers = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_reverseproxy_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    reverse_servers = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, tcpudp, icap, reverse = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {tcpudp}')
        parent.error = 1
        error = 1
    else:
        for item in tcpudp:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 7.1:
                item['src_zones'] = []
                item['src_zones_negate'] = False
                item['src_ips'] = []
                item['src_ips_negate'] = False
            else:
                item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
                item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
        json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
        with open(json_file, 'w') as fh:
            json.dump(tcpudp, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список балансировщиков TCP/UDP выгружен в файл "{json_file}".')

        for item in icap:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['profiles'] = [icap_servers[x] for x in item['profiles']]
        json_file = os.path.join(path, 'config_loadbalancing_icap.json')
        with open(json_file, 'w') as fh:
            json.dump(icap, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список балансировщиков ICAP выгружен в файл "{json_file}".')

        for item in reverse:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['profiles'] = [reverse_servers[x] for x in item['profiles']]
        json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
        with open(json_file, 'w') as fh:
            json.dump(reverse, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список балансировщиков reverse-прокси выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Правила балансировки нагрузки выгружены в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил балансировки нагрузки.' if error else out_message)


def export_shaper_rules(parent, path):
    """Экспортируем список правил пропускной способности"""
    parent.stepChanged.emit('BLUE|Экспорт правил пропускной способности из раздела "Политики сети/Пропускная способность".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_shaper_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_shaper_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('deleted_users', None)
            item.pop('active', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['services'] = get_services(parent, item['services'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['apps'] = get_apps(parent, item['apps'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['pool'] = shaper_list[item['pool']]
            if parent.version < 6:
                item['position_layer'] = 'local'
                item['limit'] = True
                item['limit_value'] = '3/h'
                item['limit_burst'] = 5
                item['log'] = False
                item['log_session_start'] = True

        json_file = os.path.join(path, 'config_shaper_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила пропускной способности выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил пропускной способности.' if error else out_message)


def export_content_rules(parent, path):
    """Экспортируем список правил фильтрации контента"""
    parent.stepChanged.emit('BLUE|Экспорт список правил фильтрации контента из раздела "Политики безопасности/Фильтрация контента".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_nlists_list('morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    morphology_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useragent_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    templates_list = {x['id']: x['name'] for x in result}

#    err, result = parent.utm.get_nlists_list('mime')
#    if err:
#        parent.stepChanged.emit(f'RED|    {result}')
#        parent.error = 1
#        return
#    mime_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    duplicate = {}
    err, data = parent.utm.get_content_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        data.pop()    # удаляем последнее правило (защищённое).
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if item['name'] in duplicate.keys():
                num = duplicate[item['name']]
                num = num + 1
                duplicate[item['name']] = num
                item['name'] = f"{item['name']} {num}"
            else:
                duplicate[item['name']] = 0
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('deleted_users', None)
            item.pop('active', None)
            item['blockpage_template_id'] = templates_list.get(item['blockpage_template_id'], -1)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['url_categories'] = get_url_categories_name(parent, item['url_categories'], item['name'])
            item['morph_categories'] = [morphology_list[x] for x in item['morph_categories']]
            item['urls'] = get_urls_name(parent, item['urls'], item['name'])
            item['referers'] = get_urls_name(parent, item['referers'], item['name'])
            if 'referer_categories' in item:
                item['referer_categories'] = get_url_categories_name(parent, item['referer_categories'], item['name'])
            else:
                item['referer_categories'] = []     # В версии 5 этого поля нет.
                item['users_negate'] = False        # В версии 5 этого поля нет.
                item['position_layer'] = 'local'    # В версии 5 этого поля нет.
            for x in item['user_agents']:
                x[1] = useragent_list[x[1]] if x[0] == 'list_id' else x[1]
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['content_types'] = [parent.ngfw_data['mime'][x] for x in item['content_types']]
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            if parent.version < 7:
                item['time_created'] = ''
                item['time_updated'] = ''
            elif parent.version < 7.1:
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

        json_file = os.path.join(path, 'config_content_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила фильтрации контента выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил фильтрации контента.' if error else out_message)


def export_safebrowsing_rules(parent, path):
    """Экспортируем список правил веб-безопасности"""
    parent.stepChanged.emit('BLUE|Экспорт правил веб-безопасности из раздела "Политики безопасности/Веб-безопасность".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_safebrowsing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('deleted_users', None)
            item.pop('active', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['url_list_exclusions'] = get_urls_name(parent, item['url_list_exclusions'], item['name'])
            if parent.version < 6:
                item.pop('dst_zones', None)
                item.pop('dst_ips', None)
                item.pop('dst_zones_negate', None)
                item.pop('dst_ips_negate', None)
                item['position_layer'] = 'local'
            if parent.version < 7:
                item['time_created'] = ''
                item['time_updated'] = ''
            elif parent.version < 7.1:
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

        json_file = os.path.join(path, 'config_safebrowsing_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила веб-безопасности выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил веб-безопасности.' if error else out_message)


def export_tunnel_inspection_rules(parent, path):
    """Экспортируем правила инспектирования туннелей"""
    parent.stepChanged.emit('BLUE|Экспорт правил инспектирования туннелей из раздела "Политики безопасности/Инспектирование туннелей".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_tunnel_inspection_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item['name'] = item['name'].strip().translate(trans_name)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])

        json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила инспектирования туннелей выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил инспектирования туннелей.' if error else out_message)


def export_ssldecrypt_rules(parent, path):
    """Экспортируем список правил инспектирования SSL"""
    parent.stepChanged.emit('BLUE|Экспорт правил инспектирования SSL из раздела "Политики безопасности/Инспектирование SSL".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    ssl_forward_profiles = {}
    if parent.version >= 7:
        err, result = parent.utm.get_ssl_forward_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        ssl_forward_profiles = {x['id']: x['name'] for x in result}
        ssl_forward_profiles[-1] = -1

    err, data = parent.utm.get_ssldecrypt_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('deleted_users', None)
            item.pop('active', None)
            item.pop('content_types_negate', None)
            item.pop('url_list_exclusions', None)
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['url_categories'] = get_url_categories_name(parent, item['url_categories'], item['name'])
            item['urls'] = get_urls_name(parent, item['urls'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][item['ssl_profile_id']] if 'ssl_profile_id' in item else 'Default SSL profile'
            item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']] if 'ssl_forward_profile_id' in item else -1
            if parent.version < 6:
                item['position_layer'] = 'local'
            if parent.version < 7:
                item['time_created'] = ''
                item['time_updated'] = ''
            elif parent.version < 7.1:
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

        json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила инспектирования SSL выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил инспектирования SSL.' if error else out_message)


def export_sshdecrypt_rules(parent, path):
    """Экспортируем список правил инспектирования SSH"""
    parent.stepChanged.emit('BLUE|Экспорт правил инспектирования SSH из раздела "Политики безопасности/Инспектирование SSH".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_sshdecrypt_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('rownumber', None)
            item.pop('guid', None)
            item.pop('active', None)
            item.pop('urls_negate', None)
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            item['protocols'] = get_services(parent, item['protocols'], item['name'])
            if parent.version < 7:
                item['time_created'] = ''
                item['time_updated'] = ''
                item['layer'] = 'Content Rules'
            elif parent.version < 7.1:
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

        json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила инспектирования SSH выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил инспектирования SSH.' if error else out_message)


def export_idps_rules(parent, path):
    """Экспортируем список правил СОВ"""
    parent.stepChanged.emit('BLUE|Экспорт правил СОВ из раздела "Политики безопасности/СОВ".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_nlists_list('ipspolicy')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    idps_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_idps_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('apps', None)
            item.pop('apps_negate', None)
            item.pop('cc', None)
            if item['action'] == 'drop':   # Для версий < 7
                item['action'] = 'reset'
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['services'] = get_services(parent, item['services'], item['name'])
            try:
                item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
            except KeyError as err:
                parent.stepChanged.emit('bRED|    Error [Правило "{item["name"]}"]: Не найден профиль СОВ "{err}". Проверьте профиль СОВ этого правила.')
                item['idps_profiles'] = []
            if parent.version < 6:
                item['position_layer'] = 'local'
                item['idps_profiles_exclusions'] = []
            else:
                try:
                    item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
                except KeyError as err:
                    parent.stepChanged.emit('bRED|    Error [Правило "{item["name"]}"]: Не найден профиль исключения СОВ "{err}". Проверьте профили СОВ этого правила.')
                    item['idps_profiles_exclusions'] = []

        json_file = os.path.join(path, 'config_idps_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила СОВ выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил СОВ.' if error else out_message)


def export_scada_rules(parent, path):
    """Экспортируем список правил АСУ ТП"""
    parent.stepChanged.emit('BLUE|Экспорт правил АСУ ТП из раздела "Политики безопасности/Правила АСУ ТП".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_scada_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    scada_profiles = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_scada_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)
            if parent.version < 6:
                item['position_layer'] = 'local'
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['services'] = [parent.ngfw_data['services'][x] for x in item['services']]
            item['scada_profiles'] = [scada_profiles[x] for x in item['scada_profiles']]

        json_file = os.path.join(path, 'config_scada_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила АСУ ТП выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил АСУ ТП.' if error else out_message)


def export_scenarios(parent, path):
    """Экспортируем список сценариев"""
    parent.stepChanged.emit('BLUE|Экспорт списка сценариев из раздела "Политики безопасности/Сценарии".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_scenarios_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('cc', None)
            for condition in item['conditions']:
                if condition['kind'] == 'application':
                    condition['apps'] = get_apps(parent, condition['apps'], item['name'])
                elif condition['kind'] == 'mime_types':
                    condition['content_types'] = [parent.ngfw_data['mime'][x] for x in condition['content_types']]
                elif condition['kind'] == 'url_category':
                    condition['url_categories'] = get_url_categories_name(parent, condition['url_categories'], item['name'])

        json_file = os.path.join(path, 'config_scenarios.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список сценариев выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка сценариев.' if error else out_message)


def export_mailsecurity_rules(parent, path):
    """Экспортируем список правил защиты почтового трафика"""
    parent.stepChanged.emit('BLUE|Экспорт правил защиты почтового трафика из раздела "Политики безопасности/Защита почтового трафика".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    email = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_mailsecurity_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('deleted_users', None)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            if parent.version < 6:
                item['services'] = [['service', "POP3" if x == 'pop' else x.upper()] for x in item.pop('protocol')]
                if not item['services']:
                    item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
                item['envelope_to_negate'] = False
                item['envelope_from_negate'] = False
                item['position_layer'] = 'local'
            else:
                item['services'] = get_services(parent, item['services'], item['name'])
            if 'dst_zones_negate' not in item:      # Этого поля нет в версиях 5 и 6.
                item['dst_zones_negate'] = False
            item['envelope_from'] = [[x[0], email[x[1]]] for x in item['envelope_from']]
            item['envelope_to'] = [[x[0], email[x[1]]] for x in item['envelope_to']]
            if parent.version < 7.1:
                item['rule_log'] = False

        json_file = os.path.join(path, 'config_mailsecurity_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Список правил защиты почтового трафика выгружен в файл "{json_file}".')

    err, dnsbl, batv = parent.utm.get_mailsecurity_dnsbl()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        dnsbl['white_list'] = get_ips_name(parent, dnsbl['white_list'], item['name'])
        dnsbl['black_list'] = get_ips_name(parent, dnsbl['black_list'], item['name'])

        json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
        with open(json_file, 'w') as fh:
            json.dump(dnsbl, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки DNSBL выгружен в файл "{json_file}".')

        json_file = os.path.join(path, 'config_mailsecurity_batv.json')
        with open(json_file, 'w') as fh:
            json.dump(batv, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Настройки BATV выгружен в файл "{json_file}".')


def export_icap_rules(parent, path):
    """Экспортируем список правил ICAP"""
    parent.stepChanged.emit('BLUE|Экспорт правил ICAP из раздела "Политики безопасности/ICAP-правила".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

#    err, result = parent.utm.get_nlists_list('mime')
#    if err:
#        parent.stepChanged.emit(f'RED|    {result}')
#        parent.error = 1
#        return
#    mime_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    icap_servers = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, err_msg, result, _ = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {err_msg}')
        parent.error = 1
        return
    icap_loadbalancing = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_icap_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            for server in item['servers']:
                if server[0] == 'lbrule':
                    try:
                        server[1] = icap_loadbalancing[server[1]]
                    except KeyError as err:
                        parent.stepChanged.emit(f'bRED|    Error [Rule: "{item["name"]}"]. Не найден балансировщик серверов ICAP "{err}". Импортируйте балансировщики ICAP и повторите попытку.')
                        item['servers'] = []
                elif server[0] == 'profile':
                    try:
                        server[1] = icap_servers[server[1]]
                    except KeyError as err:
                        parent.stepChanged.emit(f'bRED|    Error [Rule: "{item["name"]}"]. Не найден сервер ICAP "{err}". Импортируйте сервера ICAP и повторите попытку.')
                        item['servers'] = []
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['url_categories'] = get_url_categories_name(parent, item['url_categories'], item['name'])
            item['urls'] = get_urls_name(parent, item['urls'], item['name'])
            item['content_types'] = [parent.ngfw_data['mime'][x] for x in item['content_types']]
            if parent.version < 6:
                item['position_layer'] = 'local'
            if parent.version < 7:
                item['time_created'] = ''
                item['time_updated'] = ''
            else:
                item['time_created'] = item['time_created'].rstrip('Z').replace('T', ' ', 1)
                item['time_updated'] = item['time_updated'].rstrip('Z').replace('T', ' ', 1)

        json_file = os.path.join(path, 'config_icap_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила ICAP выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил ICAP.' if error else out_message)


def export_icap_servers(parent, path):
    """Экспортируем список серверов ICAP"""
    parent.stepChanged.emit('BLUE|Экспорт серверов ICAP из раздела "Политики безопасности/ICAP-серверы".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('cc', None)
            item.pop('active', None)
            item.pop('error', None)

        json_file = os.path.join(path, 'config_icap_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список серверов ICAP выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка серверов ICAP.' if error else out_message)


def export_dos_profiles(parent, path):
    """Экспортируем список профилей DoS"""
    parent.stepChanged.emit('BLUE|Экспорт профилей DoS из раздела "Политики безопасности/Профили DoS".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_dos_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_dos_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили DoS выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей DoS.' if error else out_message)


def export_dos_rules(parent, path):
    """Экспортируем список правил защиты DoS"""
    parent.stepChanged.emit('BLUE|Экспорт правил защиты DoS из раздела "Политики безопасности/Правила защиты DoS".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if not parent.scenarios_rules:
        err = set_scenarios_rules(parent)
        if err:
            parent.error = 1
            return

    err, result = parent.utm.get_dos_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    dos_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_dos_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('active', None)
            item.pop('rownumber', None)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['dst_zones'] = get_zones_name(parent, item['dst_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            item['services'] = get_services(parent, item['services'], item['name'])
            item['time_restrictions'] = get_time_restrictions_name(parent, item['time_restrictions'], item['name'])
            if item['dos_profile']:
                item['dos_profile'] = dos_profiles[item['dos_profile']]
            if item['scenario_rule_id']:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            if parent.version < 6:
                item['position_layer'] = 'local'

        json_file = os.path.join(path, 'config_dos_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила защиты DoS выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил защиты DoS.' if error else out_message)


#------------------------------------------------ Глобальный портал  ----------------------------------------------------
def export_proxyportal_rules(parent, path):
    """Экспортируем список URL-ресурсов веб-портала"""
    parent.stepChanged.emit('BLUE|Экспорт списка ресурсов веб-портала из раздела "Глобальный портал/Веб-портал".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_proxyportal_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('rownumber', None)
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            if parent.version < 7:
                item['transparent_auth'] = False
            if parent.version < 6:
                item['mapping_url_ssl_profile_id'] = 0
                item['mapping_url_certificate_id'] = 0
                item['position_layer'] = 'local'
            else:
                if item['mapping_url_ssl_profile_id']:
                    item['mapping_url_ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][item['mapping_url_ssl_profile_id']]
                if item['mapping_url_certificate_id']:
                    item['mapping_url_certificate_id'] = parent.ngfw_data['certs'][item['mapping_url_certificate_id']]

        json_file = os.path.join(path, 'config_web_portal.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список ресурсов веб-портала выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка ресурсов веб-портала.' if error else out_message)


def export_reverseproxy_servers(parent, path):
    """Экспортируем список серверов reverse-прокси"""
    parent.stepChanged.emit('BLUE|Экспорт списка серверов reverse-прокси из раздела "Глобальный портал/Серверы reverse-прокси".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_reverseproxy_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_reverseproxy_servers.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список серверов reverse-прокси выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка серверов reverse-прокси.' if error else out_message)


def export_reverseproxy_rules(parent, path):
    """Экспортируем список правил reverse-прокси"""
    parent.stepChanged.emit('BLUE|Экспорт правил reverse-прокси из раздела "Глобальный портал/Правила reverse-прокси".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    useragent_list = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, err_msg, _, result = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {err_msg}')
        parent.error = 1
        return
    reverse_loadbalancing = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_reverseproxy_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    reverse_servers = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    if parent.version >= 7.1:
        err, result = parent.utm.get_client_certificate_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        client_certificate_profiles = {x['id']: x['name'] for x in result}

        waf_profiles = {}
        if parent.utm.waf_license:  # Проверяем что есть лицензия на WAF
            # Получаем список профилей WAF. Если err=2, значит лицензия истекла или нет прав на API.
            err, data = parent.utm.get_waf_profiles_list()
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.error = 1
                return
            elif not err:
                waf_profiles = {x['id']: x['name'] for x in result}


    err, data = parent.utm.get_reverseproxy_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['src_ips'] = get_ips_name(parent, item['src_ips'], item['name'])
            item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])
            if parent.version < 6:
                item.pop('from', None)
                item.pop('to', None)
                item['ssl_profile_id'] = 0
                item['position_layer'] = 'local'
            else:
                try:
                    if item['ssl_profile_id']:
                        item['ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Указан несуществующий профиль SSL.')
                    item['ssl_profile_id'] = 0
                    item['is_https'] = False

            if item['certificate_id']:
                try:
                    item['certificate_id'] = parent.ngfw_data['certs'][item['certificate_id']]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Указан несуществующий сертификат "{item["certificate_id"]}".')
                    item['certificate_id'] = 0
                    item['is_https'] = False
            else:
                item['certificate_id'] = 0

            try:
                item['user_agents'] = [['list_id', useragent_list[x[1]]] for x in item['user_agents']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Указан несуществующий Useragent.')
                item['user_agents'] = []

            for x in item['servers']:
                try:
                    x[1] = reverse_servers[x[1]] if x[0] == 'profile' else reverse_loadbalancing[x[1]]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{item["name"]}"]. Указан несуществующий сервер reverse-прокси или балансировщик.')
                    x = ['profile', 'Example reverse proxy server']
            if parent.version < 7.1:
                item['user_agents_negate'] = False
                item['waf_profile_id'] = 0
                item['client_certificate_profile_id'] = 0
            else:
                item['client_certificate_profile_id'] = client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
                item['waf_profile_id'] = waf_profiles.get(item['waf_profile_id'], 0)

        json_file = os.path.join(path, 'config_reverseproxy_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Правила reverse-прокси выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил reverse-прокси.' if error else out_message)

#------------------------------------------------------- WAF ------------------------------------------------------------
def export_waf_custom_layers(parent, path):
    """Экспортируем персональные WAF-слои. Для версии 7.1 и выше"""
    if not parent.utm.waf_license:
        return
    parent.stepChanged.emit('BLUE|Экспорт персональных слоёв WAF из раздела "WAF/Персональные WAF-слои".')
    error = 0

    err, data = parent.utm.get_waf_custom_layers_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте персональных слоёв WAF.')
    else:
        if data:
            err, msg = func.create_dir(path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}')
                parent.error = 1
                return

            json_file = os.path.join(path, 'config_waf_custom_layers.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Персональные WAF-слои выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет персональных WAF-слоёв для экспорта.')


def export_waf_profiles_list(parent, path):
    """Экспортируем профили WAF. Для версии 7.1 и выше"""
    if not parent.utm.waf_license:
        return
    parent.stepChanged.emit('BLUE|Экспорт профилей WAF из раздела "WAF/WAF-профили".')
    error = 0

    err, result = parent.utm.get_waf_technology_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    waf_technology = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_waf_custom_layers_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    waf_custom_layers = {x['id']: x['name'] for x in result}

    err, result = parent.utm.get_waf_system_layers_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    waf_system_layers = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_waf_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей WAF.')
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            for layer in item['layers']:
                if layer['type'] == 'custom_layer':
                    layer['id'] = waf_custom_layers[layer['id']]
                else:
                    layer['id'] = waf_system_layers[layer['id']]
                    layer['protection_technologies'] = [waf_technology[x] for x in layer['protection_technologies']]
        if data:
            err, msg = func.create_dir(path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}')
                parent.error = 1
                return

            json_file = os.path.join(path, 'config_waf_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Профили WAF выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет профилей WAF для экспорта.')

#------------------------------------------------------- VPN ------------------------------------------------------------
def export_vpn_security_profiles(parent, path):
    """Экспортируем список профилей безопасности VPN. Для версий 5, 6, 7.0"""
    parent.stepChanged.emit('BLUE|Экспорт профилей безопасности VPN из раздела "VPN/Профили безопасности VPN".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_vpn_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('cc', None)
            if parent.version < 6:
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

        json_file = os.path.join(path, 'config_vpn_security_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили безопасности VPN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей безопасности VPN.' if error else out_message)


def export_vpnclient_security_profiles(parent, path):
    """Экспортируем клиентские профили безопасности VPN. Для версии 7.1 и выше"""
    parent.stepChanged.emit('BLUE|Экспорт клиентских профилей безопасности VPN из раздела "VPN/Клиентские профили безопасности".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_vpn_client_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['certificate_id'] = parent.ngfw_data['certs'].get(item['certificate_id'], 0)

        json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Клиентские профили безопасности VPN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте клиентских профилей безопасности VPN.' if error else out_message)


def export_vpnserver_security_profiles(parent, path):
    """Экспортируем серверные профили безопасности VPN. Для версии 7.1 и выше"""
    parent.stepChanged.emit('BLUE|Экспорт серверных профилей безопасности VPN из раздела "VPN/Серверные профили безопасности".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_client_certificate_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    client_certificate_profiles = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_vpn_server_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['certificate_id'] = parent.ngfw_data['certs'].get(item['certificate_id'], 0)
            item['client_certificate_profile_id'] = client_certificate_profiles.get(item['client_certificate_profile_id'], 0)

        json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Серверные профили безопасности VPN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте серверных профилей безопасности VPN.' if error else out_message)


def export_vpn_networks(parent, path):
    """Экспортируем список сетей VPN"""
    parent.stepChanged.emit('BLUE|Экспорт списка сетей VPN из раздела "VPN/Сети VPN".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_vpn_networks()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('cc', None)
            for x in item['networks']:
                if x[0] == 'list_id':
                    x[1] = parent.ngfw_data['ip_lists'][x[1]]
            if parent.version < 7.1:
                item['ep_tunnel_all_routes'] = False
                item['ep_disable_lan_access'] = False
                item['ep_routes_include'] = []
                item['ep_routes_exclude'] = []
            else:
                for x in item['ep_routes_include']:
                    if x[0] == 'list_id':
                        x[1] = parent.ngfw_data['ip_lists'][x[1]]
                for x in item['ep_routes_exclude']:
                    if x[0] == 'list_id':
                        x[1] = parent.ngfw_data['ip_lists'][x[1]]

        json_file = os.path.join(path, 'config_vpn_networks.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список сетей VPN выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка сетей VPN.' if error else out_message)


def export_vpn_client_rules(parent, path):
    """Экспортируем список клиентских правил VPN"""
    parent.stepChanged.emit('BLUE|Экспорт клиентских правил VPN из раздела "VPN/Клиентские правила".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if parent.version < 7.1:
        err, result = parent.utm.get_vpn_security_profiles()
    else:
        err, result = parent.utm.get_vpn_client_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    vpn_security_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_vpn_client_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('connection_time', None)
            item.pop('last_error', None)
            item.pop('status', None)
            item.pop('cc', None)
            item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
            if parent.version < 6:
                item['protocol'] = 'l2tp'
                item['subnet1'] = ''
                item['subnet2'] = ''

        json_file = os.path.join(path, 'config_vpn_client_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Клиентские правила VPN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте клиентских правил VPN.' if error else out_message)


def export_vpn_server_rules(parent, path):
    """Экспортируем список серверных правил VPN"""
    parent.stepChanged.emit('BLUE|Экспорт серверных правил VPN из раздела "VPN/Серверные правила".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    if parent.version < 7.1:
        err, result = parent.utm.get_vpn_security_profiles()
    else:
        err, result = parent.utm.get_vpn_server_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    vpn_security_profiles = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_vpn_networks()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    vpn_networks = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_vpn_server_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('rownumber', None)
            item.pop('cc', None)
            item['src_zones'] = get_zones_name(parent, item['src_zones'], item['name'])
            item['source_ips'] = get_ips_name(parent, item['source_ips'], item['name'])
            if parent.version < 6:
                item['dst_ips'] = []
                item['position_layer'] = 'local'
            else:
                item['dst_ips'] = get_ips_name(parent, item['dst_ips'], item['name'])
            item['users'] = get_names_users_and_groups(parent, item['users'], item['name'])

            item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
            item['tunnel_id'] = vpn_networks[item['tunnel_id']]
            item['auth_profile_id'] = parent.ngfw_data['auth_profiles'][item['auth_profile_id']]
            if parent.version >= 7.1:
                item.pop('allowed_auth_methods', None)

        json_file = os.path.join(path, 'config_vpn_server_rules.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Серверные правила VPN выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте серверных правил VPN.' if error else out_message)


#---------------------------------------------------- Библиотека --------------------------------------------------------
def export_morphology_lists(parent, path):
    """Экспортируем списки морфологии"""
    parent.stepChanged.emit('BLUE|Экспорт списков морфологии из раздела "Библиотеки/Морфология".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 6:
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

        json_file = os.path.join(path, 'config_morphology_lists.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Списки морфологии выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списков морфологии.' if error else out_message)


def export_services_list(parent, path):
    """Экспортируем список сервисов раздела библиотеки"""
    parent.stepChanged.emit('BLUE|Экспорт списка сервисов из раздела "Библиотеки/Сервисы".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_services_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id')
            item.pop('guid')
            item.pop('cc', None)
            item.pop('readonly', None)
            for value in item['protocols']:
                if 'alg' not in value:
                    value['alg'] = ''
                if parent.version < 6:
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

        json_file = os.path.join(path, 'config_services_list.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список сервисов выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка сервисов.' if error else out_message)


def export_services_groups(parent, path):
    """Экспортируем группы сервисов раздела библиотеки. Только для версии 7 и выше"""
    parent.stepChanged.emit('BLUE|Экспорт списка групп сервисов сервисов из раздела "Библиотеки/Группы сервисов".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0
    
    err, data = parent.utm.get_nlist_list('servicegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id')
            item.pop('guid')
            item.pop('editable')
            item.pop('enabled')
            item.pop('version')
            item['name'] = item['name'].strip().translate(trans_name)
            item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
            for content in item['content']:
                content.pop('id')
                content.pop('guid')

        json_file = os.path.join(path, 'config_services_groups_list.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Группы сервисов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте групп сервисов.' if error else out_message)


def export_IP_lists(parent, path):
    """Экспортируем списки IP-адресов и преобразует формат атрибутов списков к версии 7"""
    parent.stepChanged.emit('BLUE|Экспорт списка IP-адресов из раздела "Библиотеки/IP-адреса".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('network')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            file_name = item['name'].strip().translate(trans_filename)
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 6:
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

            json_file = os.path.join(path, f'{file_name}.json')
            with open(json_file, 'w') as fh:
                json.dump(item, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{item["name"]}" выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Списки IP-адресов выгружены в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списков IP-адресов.' if error else out_message)


def export_useragent_lists(parent, path):
    """Экспортируем списки useragent и преобразует формат атрибутов списков к версии 7"""
    parent.stepChanged.emit('BLUE|Экспорт списка "Useragent браузеров" из раздела "Библиотеки/Useragent браузеров".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 6:
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

        json_file = os.path.join(path, 'config_useragents_list.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список "Useragent браузеров" выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка "Useragent браузеров".' if error else out_message)


def export_mime_lists(parent, path):
    """Экспортируем списки Типов контента и преобразует формат атрибутов списков к версии 7"""
    parent.stepChanged.emit('BLUE|Экспорт списка "Типы контента" из раздела "Библиотеки/Типы контента".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('mime')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            if parent.version < 6:
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

        json_file = os.path.join(path, 'config_mime_types.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список "Типы контента" выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка "Типы контента".' if error else out_message)


def export_url_lists(parent, path):
    """Экспортируем списки URL и преобразует формат атрибутов списков к версии 6"""
    parent.stepChanged.emit('BLUE|Экспорт списков URL из раздела "Библиотеки/Списки URL".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('url')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            file_name = item['name'].strip().translate(trans_filename)
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            if parent.version < 6:
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

            json_file = os.path.join(path, f'{file_name}.json')
            with open(json_file, 'w') as fh:
                json.dump(item, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'BLACK|    Список URL "{item["name"]}" выгружен в файл "{json_file}".')

    out_message = f'GREEN|    Списки URL выгружены в каталог "{path}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списков URL.' if error else out_message)


def export_time_restricted_lists(parent, path):
    """Экспортируем содержимое календарей и преобразует формат атрибутов списков к версии 7"""
    parent.stepChanged.emit('BLUE|Экспорт списка "Календари" из раздела "Библиотеки/Календари".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('timerestrictiongroup')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            if parent.version < 6:
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
                if parent.version < 6:
                    content.pop('fixed_date_from', None)
                    content.pop('fixed_date_to', None)
                    content.pop('fixed_date', None)

        json_file = os.path.join(path, 'config_calendars.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список "Календари" выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка "Календари".' if error else out_message)


def export_shaper_list(parent, path):
    """Экспортируем список Полосы пропускания"""
    parent.stepChanged.emit('BLUE|Экспорт списка "Полосы пропускания" из раздела "Библиотеки/Полосы пропускания".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_shaper_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_shaper_list.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список "Полосы пропускания" выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка "Полосы пропускания".' if error else out_message)


def export_scada_profiles(parent, path):
    """Экспортируем список профилей АСУ ТП"""
    parent.stepChanged.emit('BLUE|Экспорт списка профилей АСУ ТП из раздела "Библиотеки/Профили АСУ ТП".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_scada_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_scada_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список "Профили АСУ ТП" выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка "Профили АСУ ТП".' if error else out_message)


def export_templates_list(parent, path):
    """
    Экспортируем список шаблонов страниц.
    Выгружает файл HTML только для изменённых страниц шаблонов.
    """
    parent.stepChanged.emit('BLUE|Экспорт шаблонов страниц из раздела "Библиотеки/Шаблоны страниц".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            err, html_data = parent.utm.get_template_data(item['type'], item['id'])
            if html_data:
                with open(os.path.join(path, f'{item["name"]}.html'), "w") as fh:
                    fh.write(html_data)
                parent.stepChanged.emit(f'BLACK|    Страница HTML для шаблона "{item["name"]}" выгружена в файл "{item["name"]}.html".')

            item.pop('id', None)
            item.pop('last_update', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_templates_list.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Шаблоны страниц выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте шаблонов страниц.' if error else out_message)


def export_url_categories(parent, path):
    """Экспортируем категории URL"""
    parent.stepChanged.emit('BLUE|Экспорт категорий URL из раздела "Библиотеки/Категории URL".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    revert_urlcategorygroup = {v: k for k, v in default_urlcategorygroup.items()}

    err, data = parent.utm.get_nlist_list('urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = default_urlcategorygroup.get(item['name'], item['name'].strip().translate(trans_name))
            item.pop('id', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            if parent.version < 6:
                item['guid'] = revert_urlcategorygroup.get(item['name'], item['guid'])
                item['last_update'] = dt.strptime(item['last_update'].value, "%Y-%m-%dT%H:%M:%SZ").strftime("%Y-%m-%d %H:%M:%S")
                item['attributes'] = {}
                item['list_type_update'] = 'static'
                item['schedule'] = 'disabled'
            else:
                item['last_update'] = item['last_update'].rstrip('Z').replace('T', ' ', 1)
            for content in item['content']:
                if parent.version < 6:
                    content['category_id'] = content.pop('value')
                    content['name'] = parent.ngfw_data['url_categories'][int(content['category_id'])]
                content.pop('id', None)

        json_file = os.path.join(path, 'config_url_categories.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Категории URL выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте категорий URL.' if error else out_message)


def export_custom_url_category(parent, path):
    """Экспортируем изменённые категории URL"""
    parent.stepChanged.emit('BLUE|Экспорт изменённых категорий URL из раздела "Библиотеки/Изменённые категории URL".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_custom_url_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('user', None)
            item.pop('default_categories', None)
            item.pop('change_date', None)
            item.pop('cc', None)
            item['categories'] = [parent.ngfw_data['url_categories'][x] for x in item['categories']]

        json_file = os.path.join(path, 'custom_url_categories.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Изменённые категории URL выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте изменённых категорий URL.' if error else out_message)


def export_applications(parent, path):
    """Экспортируем список пользовательских приложений для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Экспорт пользовательских приложений из раздела "Библиотеки/Приложения".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_version71_apps(query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('attributes', None)
            item.pop('cc', None)
            item['l7categories'] = [parent.ngfw_data['l7_categories'][x[1]] for x in item['l7categories']]

        json_file = os.path.join(path, 'config_applications.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Пользовательские приложения выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте пользовательских приложений.' if error else out_message)


def export_app_profiles(parent, path):
    """Экспортируем профили приложений. Только для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Экспорт профилей приложений из раздела "Библиотеки/Профили приложений".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_l7_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            for app in item['overrides']:
                app['id'] = parent.ngfw_data['l7_apps'][app['id']]

        json_file = os.path.join(path, 'config_app_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили приложений выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей приложений.' if error else out_message)


def export_application_groups(parent, path):
    """Экспортируем группы приложений."""
    parent.stepChanged.emit('BLUE|Экспорт групп приложений из раздела "Библиотеки/Группы приложений".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('applicationgroup')
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('version', None)
            item.pop('global', None)
            item['name'] = item['name'].strip().translate(trans_name)
            if parent.version < 6:
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
                if parent.version < 6:
                    content['name'] = parent.ngfw_data['l7_apps'][content['value']]
                elif parent.version < 7.1:
                    content['category'] = [parent.ngfw_data['l7_categories'][x] for x in content['category']]
                else:
                    try:
                        content['l7categories'] = [parent.ngfw_data['l7_categories'][x[1]] for x in content['l7categories']]
                    except KeyError:
                        pass    # Ошибка бывает если ранее было не корректно добавлено приложение через API в версии 7.1.

        json_file = os.path.join(path, 'config_application_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Группы приложений выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте групп приложений.' if error else out_message)


def export_email_groups(parent, path):
    """Экспортируем группы почтовых адресов."""
    parent.stepChanged.emit('BLUE|Экспорт групп почтовых адресов из раздела "Библиотеки/Почтовые адреса".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            if parent.version < 6:
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

        json_file = os.path.join(path, 'config_email_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Группы почтовых адресов выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте групп почтовых адресов.' if error else out_message)


def export_phone_groups(parent, path):
    """Экспортируем группы телефонных номеров."""
    parent.stepChanged.emit('BLUE|Экспорт групп телефонных номеров из раздела "Библиотеки/Номера телефонов".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_nlist_list('phonegroup')
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('guid', None)
            item.pop('editable', None)
            item.pop('enabled', None)
            item.pop('global', None)
            item.pop('version', None)
            if parent.version < 6:
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

        json_file = os.path.join(path, 'config_phone_groups.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Группы телефонных номеров выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте групп телефонных номеров.' if error else out_message)


def export_custom_idps_signatures(parent, path):
    """Экспортируем пользовательские сигнатуры СОВ для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Экспорт пользовательских сигнатур СОВ из раздела "Библиотеки/Сигнатуры СОВ".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_idps_signatures_list(query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('attributes', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'custom_idps_signatures.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Пользовательские сигнатуры СОВ выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте пользовательских сигнатур СОВ.' if error else out_message)


def export_idps_profiles(parent, path):
    """Экспортируем список профилей СОВ"""
    parent.stepChanged.emit('BLUE|Экспорт профилей СОВ из раздела "Библиотеки/Профили СОВ".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return

    error = 0
    data = []

    if parent.version < 7.1:
        err, data = parent.utm.get_nlist_list('ipspolicy')
        if err:
            parent.stepChanged.emit(f'iRED|{data}')
            parent.error = 1
            error = 1
        else:
            for item in data:
                item.pop('id', None)
                item.pop('guid', None)
                item.pop('editable', None)
                item.pop('enabled', None)
                item.pop('global', None)
                item.pop('version', None)
                item['name'] = item['name'].strip().translate(trans_name)
                if parent.version < 6:
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
        err, data = parent.utm.get_idps_profiles_list()
        if err:
            parent.stepChanged.emit(f'iRED|{data}')
            parent.error = 1
            error = 1
        else:
            for item in data:
                item.pop('id', None)
                item.pop('cc', None)
                for app in item['overrides']:
                    err, result = parent.utm.get_idps_signature_fetch(app['id'])
                    if err:
                        parent.stepChanged.emit(f'iRED|{result}')
                        parent.error = 1
                        error = 1
                    else:
                        app['signature_id'] = result['signature_id']
                        app['msg'] = result['msg']

    json_file = os.path.join(path, 'config_idps_profiles.json')
    with open(json_file, 'w') as fh:
        json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Список профилей СОВ выгружен в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей СОВ.' if error else out_message)


def export_notification_profiles(parent, path):
    """Экспортируем список профилей оповещения"""
    parent.stepChanged.emit('BLUE|Экспорт профилей оповещений из раздела "Библиотеки/Профили оповещений".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)

        json_file = os.path.join(path, 'config_notification_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили оповещений выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей оповещений.' if error else out_message)


def export_netflow_profiles(parent, path):
    """Экспортируем список профилей netflow"""
    parent.stepChanged.emit('BLUE|Экспорт профилей netflow из раздела "Библиотеки/Профили netflow".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_netflow_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)

        json_file = os.path.join(path, 'config_netflow_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили netflow выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей netflow.' if error else out_message)


def export_ssl_profiles(parent, path):
    """Экспортируем список профилей SSL"""
    parent.stepChanged.emit('BLUE|Экспорт профилей SSL из раздела "Библиотеки/Профили SSL".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_ssl_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)

        json_file = os.path.join(path, 'config_ssl_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили SSL выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей SSL.' if error else out_message)


def export_lldp_profiles(parent, path):
    """Экспортируем список профилей LLDP"""
    parent.stepChanged.emit('BLUE|Экспорт профилей LLDP из раздела "Библиотеки/Профили LLDP".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_lldp_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)

        json_file = os.path.join(path, 'config_lldp_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили LLDP выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей LLDP.' if error else out_message)


def export_ssl_forward_profiles(parent, path):
    """Экспортируем профили пересылки SSL"""
    parent.stepChanged.emit('BLUE|Экспорт профилей пересылки SSL из раздела "Библиотеки/Профили пересылки SSL".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_ssl_forward_profiles()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['name'] = item['name'].strip().translate(trans_name)

        json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили пересылки SSL выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей пересылки SSL.' if error else out_message)


def export_hip_objects(parent, path):
    """Экспортируем HIP объекты"""
    parent.stepChanged.emit('BLUE|Экспорт HIP объектов из раздела "Библиотеки/HIP объекты".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_hip_objects_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_hip_objects.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    HIP объекты выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте HIP объектов.' if error else out_message)


def export_hip_profiles(parent, path):
    """Экспортируем HIP профили"""
    parent.stepChanged.emit('BLUE|Экспорт HIP профилей из раздела "Библиотеки/HIP профили".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_hip_objects_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    hip_objects = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_hip_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            for obj in item['hip_objects']:
                obj['id'] = hip_objects[obj['id']]

        json_file = os.path.join(path, 'config_hip_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    HIP профили выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте HIP профилей.' if error else out_message)


def export_bfd_profiles(parent, path):
    """Экспортируем профили BFD"""
    parent.stepChanged.emit('BLUE|Экспорт профилей BFD из раздела "Библиотеки/Профили BFD".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_bfd_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_bfd_profiles.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Профили BFD выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей BFD.' if error else out_message)


def export_useridagent_syslog_filters(parent, path):
    """Экспортируем syslog фильтры UserID агента"""
    parent.stepChanged.emit('BLUE|Экспорт syslog фильтров UserID агента из раздела "Библиотеки/Syslog фильтры UserID агента".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
        return
    error = 0

    err, data = parent.utm.get_useridagent_filters_list()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        error = 1
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)

        json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)

    out_message = f'GREEN|    Syslog фильтры UserID агента выгружены в файл "{json_file}".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте syslog фильтров UserID агента.' if error else out_message)

#--------------------------------------------------- Оповещения ---------------------------------------------------------
def export_snmp_rules(parent, path):
    """Экспортируем список правил SNMP"""
    parent.stepChanged.emit('BLUE|Экспорт списка правил SNMP из раздела "Диагностика и мониторинг/Оповещения/SNMP".')

    if parent.version >= 7.1:
        err, result = parent.utm.get_snmp_security_profiles()
        if err:
            parent.stepChanged.emit(f'iRED|{result}')
            parent.error = 1
            return
        snmp_security_profiles = {x['id']: x['name'] for x in result}

    err, data = parent.utm.get_snmp_rules()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте списка правил SNMP.')
    else:
        for item in data:
            item['name'] = item['name'].strip().translate(trans_name)
            item.pop('id', None)
            item.pop('cc', None)
            if parent.version >= 7.1:
                item['snmp_security_profile'] = snmp_security_profiles.get(item['snmp_security_profile'], 0)

        if data:
            err, msg = func.create_dir(path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}')
                parent.error = 1
                return

            json_file = os.path.join(path, 'config_snmp_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Список правил SNMP выгружен в файл "{json_file}".')
        else:
            parent.stepChanged.emit(f'GRAY|    Нет правил SNMP для экспорта.')


def export_notification_alert_rules(parent, path):
    """Экспортируем список правил оповещений"""
    parent.stepChanged.emit('BLUE|Экспорт правил оповещений из раздела "Диагностика и мониторинг/Оповещения/Правила оповещений".')

    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        parent.error = 1
        return
    list_notifications = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        parent.error = 1
        return
    email_group = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, result = parent.utm.get_nlist_list('phonegroup')
    if err:
        parent.stepChanged.emit(f'iRED|{result}')
        parent.error = 1
        return
    phone_group = {x['id']: x['name'].strip().translate(trans_name) for x in result}

    err, data = parent.utm.get_notification_alert_rules()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте правил оповещений.')
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item['notification_profile_id'] = list_notifications[item['notification_profile_id']]
            item['emails'] = [[x[0], email_group[x[1]]] for x in item['emails']]
            item['phones'] = [[x[0], phone_group[x[1]]] for x in item['phones']]

        if data:
            err, msg = func.create_dir(path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}')
                parent.error = 1
                return

            json_file = os.path.join(path, 'config_alert_rules.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Правила оповещений выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет правил оповещений для экспорта.')


def export_snmp_security_profiles(parent, path):
    """Экспортируем профили безопасности SNMP. Для версии 7.1 и выше"""
    parent.stepChanged.emit('BLUE|Экспорт профилей безопасности SNMP из раздела "Диагностика и мониторинг/Оповещения/Профили безопасности SNMP".')

    err, data = parent.utm.get_snmp_security_profiles()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте профилей безопасности SNMP.')
    else:
        for item in data:
            item.pop('id', None)
            item.pop('cc', None)
            item.pop('readonly', None)

        if data:
            err, msg = func.create_dir(path)
            if err:
                parent.stepChanged.emit(f'RED|    {msg}')
                parent.error = 1
                return

            json_file = os.path.join(path, 'config_snmp_profiles.json')
            with open(json_file, 'w') as fh:
                json.dump(data, fh, indent=4, ensure_ascii=False)
            parent.stepChanged.emit(f'GREEN|    Профили безопасности SNMP выгружены в файл "{json_file}".')
        else:
            parent.stepChanged.emit('GRAY|    Нет профилей безопасности SNMP для экспорта.')


def export_snmp_settings(parent, path):
    """Экспортируем параметры SNMP. Для версии 7.1 и выше"""
    parent.stepChanged.emit('BLUE|Экспорт параметров SNMP из раздела "Диагностика и мониторинг/Оповещения/Параметры SNMP".')
    err, msg = func.create_dir(path)
    if err:
        parent.stepChanged.emit(f'RED|    {msg}')
        parent.error = 1
    else:
        export_snmp_engine(parent, path)
        export_snmp_sys_name(parent, path)
        export_snmp_sys_location(parent, path)
        export_snmp_sys_description(parent, path)

    parent.stepChanged.emit(f'GREEN|    Параметры SNMP выгружены в каталог "{path}".')

def export_snmp_engine(parent, path):
    """Экспортируем SNMP Engine ID. Для версий 6 и 7.0"""
    if 5 < parent.version < 7.1:
        parent.stepChanged.emit('BLUE|Экспорт SNMP Engine ID из раздела "UserGate/Настройки/Модули/SNMP Engine ID".')
        engine_path = os.path.join(parent.config_path, 'Notifications/SNMPParameters')
        err, msg = func.create_dir(engine_path)
        if err:
            parent.stepChanged.emit(f'RED|    {msg}')
            parent.error = 1
        else:
            export_snmp_engine(parent, engine_path)


    err, data = parent.utm.get_snmp_engine()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте SNMP Engine ID.')
    else:
        json_file = os.path.join(path, 'config_snmp_engine.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    SNMP Engine ID выгружено в файл "{json_file}".')

def export_snmp_sys_name(parent, path):
    err, data = parent.utm.get_snmp_sysname()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте значения SNMP SysName.')
    else:
        json_file = os.path.join(path, 'config_snmp_sysname.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Значение SNMP SysName выгружено в файл "{json_file}".')

def export_snmp_sys_location(parent, path):
    err, data = parent.utm.get_snmp_syslocation()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте значения SNMP SysLocation.')
    else:
        json_file = os.path.join(path, 'config_snmp_syslocation.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Значение SNMP SysLocation выгружено в файл "{json_file}".')

def export_snmp_sys_description(parent, path):
    err, data = parent.utm.get_snmp_sysdescription()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при экспорте значения SNMP SysDescription.')
    else:
        json_file = os.path.join(path, 'config_snmp_sysdescription.json')
        with open(json_file, 'w') as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        parent.stepChanged.emit(f'BLACK|    Значение SNMP SysDescription выгружено в файл "{json_file}".')

#------------------------------------------------------------------------------------------------------------------------
def pass_function(parent, path):
    """Функция заглушка"""
    parent.stepChanged.emit(f'GRAY|Экспорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')


export_funcs = {
    'GeneralSettings':  export_general_settings,
    'DeviceManagement': pass_function,
    'Administrators': pass_function,
    'Certificates': export_certificates,
    'UserCertificateProfiles': export_users_certificate_profiles,
    'Zones': export_zones,
    'Interfaces': export_interfaces_list,
    'Gateways': export_gateways_list,
    'DHCP': export_dhcp_subnets,
    'DNS': export_dns_config,
    'VRF': export_vrf_list,
    'WCCP': export_wccp,
    'Groups': export_local_groups,
    'Users': export_local_users,
    'AuthServers': export_auth_servers,
    'AuthProfiles': export_auth_profiles,
    'CaptivePortal': export_captive_portal_rules,
    'CaptiveProfiles': export_captive_profiles,
    'TerminalServers': export_terminal_servers,
    'MFAProfiles': export_2fa_profiles,
    'UserIDagent': export_userid_agent,
#    'BYODPolicies': export_byod_policy,
#    'BYODDevices': pass_function,
    'Firewall': export_firewall_rules,
    'NATandRouting': export_nat_rules,
    'LoadBalancing': export_loadbalancing_rules,
    'TrafficShaping': export_shaper_rules,
    "ContentFiltering": export_content_rules,
    "SafeBrowsing": export_safebrowsing_rules,
    "TunnelInspection": export_tunnel_inspection_rules,
    "SSLInspection": export_ssldecrypt_rules,
    "SSHInspection": export_sshdecrypt_rules,
    "IntrusionPrevention": export_idps_rules,
    "Scenarios": export_scenarios,
    "MailSecurity": export_mailsecurity_rules,
    "ICAPRules": export_icap_rules,
    "ICAPServers": export_icap_servers,
    "DoSRules": export_dos_rules,
    "DoSProfiles": export_dos_profiles,
    "SCADARules": export_scada_rules,
    "WebPortal": export_proxyportal_rules,
    "ReverseProxyRules": export_reverseproxy_rules,
    "ReverseProxyServers": export_reverseproxy_servers,
    "WAFprofiles": export_waf_profiles_list,
    "CustomWafLayers": export_waf_custom_layers,
    "SystemWafRules": pass_function,
    "ServerRules": export_vpn_server_rules,
    "ClientRules": export_vpn_client_rules,
    "VPNNetworks": export_vpn_networks,
    "SecurityProfiles": export_vpn_security_profiles,
    "ServerSecurityProfiles": export_vpnserver_security_profiles,
    "ClientSecurityProfiles": export_vpnclient_security_profiles,
    "Morphology": export_morphology_lists,
    "Services": export_services_list,
    "ServicesGroups": export_services_groups,
    "IPAddresses": export_IP_lists,
    "Useragents": export_useragent_lists,
    "ContentTypes": export_mime_lists,
    "URLLists": export_url_lists,
    "TimeSets": export_time_restricted_lists,
    "BandwidthPools": export_shaper_list,
    "SCADAProfiles": export_scada_profiles,
    "ResponcePages": export_templates_list,
    "URLCategories": export_url_categories,
    "OverURLCategories": export_custom_url_category,
    "Applications": export_applications,
    "ApplicationProfiles": export_app_profiles,
    "ApplicationGroups": export_application_groups,
    "Emails": export_email_groups,
    "Phones": export_phone_groups,
    "IPDSSignatures": export_custom_idps_signatures,
    "IDPSProfiles": export_idps_profiles,
    "NotificationProfiles": export_notification_profiles,
    "NetflowProfiles": export_netflow_profiles,
    "SSLProfiles": export_ssl_profiles,
    "LLDPProfiles": export_lldp_profiles,
    "SSLForwardingProfiles": export_ssl_forward_profiles,
    "HIDObjects": export_hip_objects,
    "HIDProfiles": export_hip_profiles,
    "BfdProfiles": export_bfd_profiles,
    "UserIdAgentSyslogFilters": export_useridagent_syslog_filters,
    "AlertRules": export_notification_alert_rules,
    "SNMP": export_snmp_rules,
    "SNMPParameters": export_snmp_settings,
    "SNMPSecurityProfiles": export_snmp_security_profiles,
}

###################################### Служебные функции ##########################################
def get_ips_name(parent, rule_ips, rule_name):
    """Получаем имена списков IP-адресов, URL-листов и GeoIP. Если списки не существует на MC, то они пропускаются."""
    new_rule_ips = []
    for ips in rule_ips:
        if ips[0] == 'geoip_code':
            new_rule_ips.append(ips)
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', parent.mc_data['ip_lists'][ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', parent.mc_data['url_lists'][ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]. Не найден список {ips[0]}.')
    return new_rule_ips

def get_zones_name(parent, zones, rule_name):
    """Получаем имена зон. Если зона не существует на MC, то она пропускается."""
    new_zones = []
    for zone_id in zones:
        try:
            new_zones.append(parent.mc_data['zones'][zone_id])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]. Не найдена зона c ID: {zone_id}.')
    return new_zones

def get_urls_name(parent, urls, rule_name):
    """Получаем имена списков URL. Если список не существует на MC, то он пропускается."""
    new_urls = []
    for url_id in urls:
        try:
            new_urls.append(parent.mc_data['url_lists'][url_id])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]. Не найден список URL c ID: {url_id}.')
    return new_urls

def get_url_categories_name(parent, url_categories, rule_name):
    """Получаем имена категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
    new_urls = []
    for arr in url_categories:
        try:
            if arr[0] == 'list_id':
                new_urls.append(['list_id', parent.mc_data['url_categorygroups'][arr[1]]])
            elif arr[0] == 'category_id':
                new_urls.append(['category_id', parent.mc_data['url_categories'][arr[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]. Не найдена категория URL {err}.')
    return new_urls

def get_time_restrictions_name(parent, times, rule_name):
    """Получаем имена календарей. Если не существуют на MC, то пропускаются."""
    new_times = []
    for cal_id in times:
        try:
            new_times.append(parent.mc_data['calendars'][cal_id])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]. Не найден календарь c ID: {cal_id}.')
    return new_times

def get_names_users_and_groups(parent, users, rule_name):
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
                    user_name = parent.ngfw_data['local_users'][item[1]]
                except KeyError:
                    err, user_name = parent.utm.get_ldap_user_name(item[1])
                    if err:
                        parent.stepChanged.emit(f'bRED|    {user_name}  [Rule: "{rule_name}"]')
                    elif not user_name:
                        parent.stepChanged.emit(f'NOTE|    Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['user', user_name])
                else:
                    new_users.append(['user', user_name])
            case 'group':
                try:
                    group_name = parent.ngfw_data['local_groups'][item[1]]
                except KeyError:
                    err, group_name = parent.utm.get_ldap_group_name(item[1])
                    if err:
                        parent.stepChanged.emit(f'bRED|    {group_name}  [Rule: "{rule_name}"]')
                    elif not group_name:
                        parent.stepChanged.emit(f'NOTE|    Error [Rule: "{rule_name}"]. Нет LDAP-коннектора для домена "{item[1].split(":")[0]}"! Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                    else:
                        new_users.append(['group', group_name])
                else:
                    new_users.append(['group', group_name])
    return new_users

def get_services(parent, service_list, rule_name):
    """Получаем имена сервисов по их ID. Если сервис не найден, то он пропускается."""
    new_service_list = []
    if parent.version < 7:
        for item in service_list:
            try:
                new_service_list.append(['service', parent.ngfw_data['services'][item]])
            except TypeError as err:
                parent.stepChanged.emit(f'bRED|    Error [Rule: "{rule_name}"]. Не корректное значение в поле "services" - {err}.')
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error [Rule: "{rule_name}"]. Не найден сервис "{item}".')
    else:
        for item in service_list:
            try:
                new_service_list.append(['service', parent.ngfw_data['services'][item[1]]] if item[0] == 'service' else ['list_id', parent.ngfw_data['service_groups'][item[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error [Rule: "{rule_name}"]. Не найдена группа сервисов "{item}".')
    return new_service_list

def get_apps(parent, array_apps, rule_name):
    """Определяем имя приложения или группы приложений по ID."""
    new_app_list = []
    for app in array_apps:
        if app[0] == 'ro_group':
            if app[1] == 0:
                new_app_list.append(['ro_group', 'All'])
            else:
                try:
                    new_app_list.append(['ro_group', parent.ngfw_data['l7_categories'][app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Не найдена категория l7 "{app}" для правила "{rule_name}".')
                    parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.')
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.ngfw_data['application_groups'][app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Не найдена группа приложений l7 №{err} для правила "{rule_name}".')
        elif app[0] == 'app':
            try:
                new_app_list.append(['app', parent.ngfw_data['l7_apps'][app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Не найдено приложение №{err} для правила "{rule_name}".')
                parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.')
    return new_app_list

def set_scenarios_rules(parent):
    """Устанавливаем в parent значение атрибута: scenarios_rules"""
    err, result = parent.utm.get_scenarios_rules()
    if err:
        parent.stepChanged.emit(f'iRED|{data}')
        return 1
    parent.scenarios_rules = {x['id']: x['name'].strip().translate(trans_name) for x in result}
    return 0

def translate_iface_name(ngfw_version, path, data):
    """Преобразуем имена интерфейсов для версии 5 (eth меняется на port, так же меняются имена vlan)"""
    if ngfw_version < 6:
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

