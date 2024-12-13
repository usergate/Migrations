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
# import_functions.py
# Классы импорта разделов конфигурации на NGFW UserGate.
# Версия 2.9 13.12.2024   (идентично с ug_ngfw_converter и universal_converter)
#

import os, sys, time, copy, json
import common_func as func
from datetime import datetime as dt
from PyQt6.QtCore import QThread, pyqtSignal
from services import zone_services


class ImportAll(QThread):
    """Импортируем всю конфигурацию на NGFW"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points, arguments):
        super().__init__()
        self.utm = utm
        self.config_path = config_path
        self.all_points = all_points
        self.iface_settings = arguments['iface_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
        self.client_certificate_profiles = {}
        self.notification_profiles = {}
        self.list_templates = {}
        self.icap_servers = {}
        self.reverseproxy_servers = {}
        self.error = 0

    def run(self):
        """Импортируем всё в пакетном режиме"""
        err, self.ngfw_data = func.read_bin_file(self)
        if err:
            self.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван! Не удалось прочитать служебные данные.')
            return

        path_dict = {}
        for item in self.all_points:
            top_level_path = os.path.join(self.config_path, item['path'])
            for point in item['points']:
                path_dict[point] = os.path.join(top_level_path, point)
        for key, value in import_funcs.items():
            if key in path_dict:
                value(self, path_dict[key])

        if func.write_bin_file(self, self.ngfw_data):
            self.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван! Не удалось записать служебные данные.')
            return

        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт всей конфигурации прошёл успешно.\n')


class ImportSelectedPoints(QThread):
    """Импортируем выделенный раздел конфигурации на NGFW"""
    stepChanged = pyqtSignal(str)
    def __init__(self, utm, config_path, selected_path, selected_points, arguments):
        super().__init__()
        self.utm = utm
        self.config_path = config_path
        self.selected_path = selected_path
        self.selected_points = selected_points
        self.iface_settings = arguments['iface_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
        self.client_certificate_profiles = {}
        self.notification_profiles = {}
        self.list_templates = {}
        self.icap_servers = {}
        self.reverseproxy_servers = {}
        self.error = 0

    def run(self):
        """Импортируем определённый раздел конфигурации"""
        err, self.ngfw_data = func.read_bin_file(self)
        if err:
            parent.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван!')
            return

        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            if point in import_funcs:
                import_funcs[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')

        if func.write_bin_file(self, self.ngfw_data):
            self.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван! Не удалось записать служебные данные.')
            return

        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт конфигурации завершён.\n')


#------------------------------------------ UserGate -------------------------------------------------------
def import_certificates(parent, path):
    """Импортируем сертификаты"""
    parent.stepChanged.emit('BLUE|Импорт сертификатов в раздел "UserGate/Сертификаты".')

    if not os.path.isdir(path):
        return
    certificates = {entry.name: entry.path for entry in os.scandir(path) if entry.is_dir()}
    if not certificates:
        parent.stepChanged.emit('GRAY|    Нет сертификатов для импорта.')
        return
    error = 0
    
    for cert_name, cert_path in certificates.items():
        files = [entry.name for entry in os.scandir(cert_path) if entry.is_file()]

        json_file = os.path.join(cert_path, 'certificate_list.json')
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            continue

        if 'cert.pem' in files:
            with open(os.path.join(cert_path, 'cert.pem'), mode='rb') as fh:
                cert_data = fh.read()
        elif 'cert.der' in files:
            with open(os.path.join(cert_path, 'cert.der'), mode='rb') as fh:
                cert_data = fh.read()
        else:
            parent.stepChanged.emit(f'NOTE|    Не найден файл сертификата "{cert_name}" для импорта. Будет сгенерирован новый сертификат "{cert_name}".')
            data.update(data['issuer'])
            err, result = parent.utm.new_certificate(data)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|       {result}')
                continue
            else:
                parent.mc_data['certs'][cert_name] = result
                parent.stepChanged.emit(f'BLACK|    Создан новый сертификат "{cert_name}".')
                parent.stepChanged.emit(f'LBLUE|       Необходимо назначить роль новому сертификату "{cert_name}".')
                continue

        if 'key.der' in files:
            with open(os.path.join(cert_path, 'key.der'), mode='rb') as fh:
                key_data = fh.read()
        elif 'key.pem' in files:
            with open(os.path.join(cert_path, 'key.pem'), mode='rb') as fh:
                key_data = fh.read()
        else:
            key_data = None

        if data['name'] in parent.mc_data['certs']:
            parent.stepChanged.emit(f'GRAY|    Сертификат "{cert_name}" уже существует.')
            err, result = parent.utm.update_certificate(parent.mc_data['certs'][data['name']], data, cert_data, private_key=key_data)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Cертификат "{cert_name}" updated.')
        else:
            err, result = parent.utm.add_certificate(data, cert_data, private_key=key_data)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.mc_data['certs'][cert_name] = result
                parent.stepChanged.emit(f'BLACK|    Импортирован сертификат "{cert_name}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте сертификатов.')
    else:
        parent.stepChanged.emit('GREEN|    Сертификаты импортированы в раздел "UserGate/Сертификаты".')


def import_general_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки'"""
    import_ui(parent, path)
    import_ntp_settings(parent, path)
    import_proxy_port(parent, path)
    import_modules(parent, path)
    if 5 < parent.version < 7.1:
        parent.stepChanged.emit('BLUE|Импорт SNMP Engine ID в раздел "UserGate/Настройки/Модули/SNMP Engine ID".')
        engine_path = os.path.join(parent.config_path, 'Notifications/SNMPParameters')
        import_snmp_engine(parent, engine_path)
    import_cache_settings(parent, path)
    import_proxy_exceptions(parent, path)
    import_web_portal_settings(parent, path)
    import_upstream_proxy_settings(parent, path)


def import_ui(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Настройки интерфейса'"""
    json_file = os.path.join(path, 'config_settings_ui.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки интерфейса".')

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
    if parent.version < 7.1:
        data.pop('api_session_lifetime', None)
        data.pop('endpoint_ssl_profile_id', None)
        data.pop('endpoint_certificate_id', None)
    if parent.version == 5.0:
        data.pop('web_console_ssl_profile_id', None)
        data.pop('response_pages_ssl_profile_id', None)
    for key, value in data.items():
        if key in params:
            if key == 'web_console_ssl_profile_id':
                try:
                    value = parent.ngfw_data['ssl_profiles'][value]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'response_pages_ssl_profile_id':
                try:
                    value = parent.ngfw_data['ssl_profiles'][value]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'endpoint_ssl_profile_id':
                try:
                    value = parent.ngfw_data['ssl_profiles'][value]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден профиль SSL "{err}" для "{params[key]}". Загрузите профили SSL и повторите попытку.')
                    error = 1
                    continue
            if key == 'endpoint_certificate_id':
                try:
                    value = parent.ngfw_data['certs'][value]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Не найден сертификат "{err}" для "{params[key]}". Загрузите сертификаты и повторите попытку.')
                    error = 1
                    continue

        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{data[key]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек интерфейса.')
    else:
        parent.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Настройки интерфейса".')

def import_ntp_settings(parent, path):
    """Импортируем настройки NTP"""
    json_file = os.path.join(path, 'config_ntp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек NTP раздела "UserGate/Настройки/Настройка времени сервера".')

    data.pop('utc_time', None)
    data.pop('ntp_synced', None)
    err, result = parent.utm.add_ntp_config(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек NTP.')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы настройки NTP в раздел "UserGate/Настройки/Настройка времени сервера".')


def import_proxy_port(parent, path):
    """Импортируем раздел UserGate/Настройки/Модули/HTTP(S)-прокси порт"""
    json_file = os.path.join(path, 'config_proxy_port.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули/HTTP(S)-прокси порт".')

    err, result = parent.utm.set_proxy_port(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта HTTP(S)-прокси порта.')
    else:
        parent.stepChanged.emit(f'BLACK|    HTTP(S)-прокси порт установлен в значение "{data}"')


def import_modules(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Модули'"""
    json_file = os.path.join(path, 'config_settings_modules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Модули".')
    error = 0

    params = {
        'auth_captive': 'Домен Auth captive-портала',
        'logout_captive': 'Домен Logout captive-портала',
        'block_page_domain': 'Домен страницы блокировки',
        'ftpclient_captive': 'FTP поверх HTTP домен',
        'ftp_proxy_enabled': 'FTP поверх HTTP',
        'tunnel_inspection_zone_config': 'Зона для инспектируемых туннелей',
        'lldp_config': 'Настройка LLDP'
    }
    if parent.version < 7.1:
        data.pop('tunnel_inspection_zone_config', None)
        data.pop('lldp_config', None)
    else:
        if 'tunnel_inspection_zone_config' in data:
            zone_name = data['tunnel_inspection_zone_config']['target_zone']
            data['tunnel_inspection_zone_config']['target_zone'] = parent.ngfw_data['zones'].get(zone_name, 8)

    for key, value in data.items():
        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Параметр "{params[key]}" установлен в значение "{value}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек модулей.')
    else:
        parent.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Модули".')


def import_cache_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Настройки кэширования HTTP'"""
    json_file = os.path.join(path, 'config_proxy_settings.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP".')
    error = 0

    if parent.version < 7:
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
    if parent.version == 7.0:
        data.pop('module_tftp_enabled', None)
    for key, value in data.items():
        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Параметр "{key}" установлен в значение "{value}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек кэширования HTTP.')
    else:
        parent.stepChanged.emit('GREEN|    Импортирован раздел "UserGate/Настройки/Настройки кэширования HTTP".')


def import_proxy_exceptions(parent, path):
    """Импортируем раздел UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования"""
    json_file = os.path.join(path, 'config_proxy_exceptions.json')
    err, exceptions = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Настройки кэширования HTTP/Исключения кэширования".')
    error = 0

    err, nlist = parent.utm.get_nlist_list('httpcwl')
    for item in exceptions:
        err, result = parent.utm.add_nlist_item(nlist['id'], item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        elif err == 2:
            parent.stepChanged.emit(f'GRAY|    URL "{item["value"]}" уже существует в исключениях кэширования.')
        else:
            parent.stepChanged.emit(f'BLACK|    В исключения кэширования добавлен URL "{item["value"]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта исключений кэширования HTTP.')
    else:
        parent.stepChanged.emit('GREEN|    Исключения кэширования HTTP импортированы".')


def import_web_portal_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки/Веб-портал'"""
    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт раздела "UserGate/Настройки/Веб-портал".')
    error = 0
    error_message = 'ORANGE|    Произошла ошибка при импорте настроек Веб-портала!'
    out_message = 'GREEN|    Импортирован раздел "UserGate/Настройки/Веб-портал".'

    if not parent.list_templates:
        if get_templates_list(parent):    # Устанавливаем атрибут parent.list_templates
            parent.stepChanged.emit(error_message)
            return

    if parent.version >= 7.1:
        if not parent.client_certificate_profiles:
            if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
                parent.stepChanged.emit(error_message)
                return

    if parent.version >= 6:
        try:
            data['ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][data['ssl_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Не найден профиль SSL {err}". Загрузите профили SSL и повторите попытку.')
            parent.stepChanged.emit(error_message)
            parent.error = 1
            return
    else:
        data.pop('ssl_profile_id', None)

    if parent.version >= 7.1:
        data['client_certificate_profile_id'] = parent.client_certificate_profiles.get(data['client_certificate_profile_id'], 0)
        if not data['client_certificate_profile_id']:
            data['cert_auth_enabled'] = False
    else:
        data.pop('client_certificate_profile_id', None)

    try:
        data['user_auth_profile_id'] = parent.ngfw_data['auth_profiles'][data['user_auth_profile_id']]
    except KeyError as err:
        parent.stepChanged.emit(f'RED|    Не найден профиль аутентификации {err}". Загрузите профили аутентификации и повторите попытку.')
        parent.stepChanged.emit(error_message)
        parent.error = 1
        return
    if data['certificate_id']:
        try:
            data['certificate_id'] = parent.ngfw_data['certs'][data['certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Не найден сертификат {err}". Укажите сертификат вручную или загрузите сертификаты и повторите попытку.')
            parent.error = 1
    else:
        data['certificate_id'] = -1

    data['proxy_portal_template_id'] = parent.list_templates.get(data['proxy_portal_template_id'], -1)
    data['proxy_portal_login_template_id'] = parent.list_templates.get(data['proxy_portal_login_template_id'], -1)

    err, result = parent.utm.set_proxyportal_config(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        error = 1

    parent.stepChanged.emit(error_message if error else out_message)


def import_upstream_proxy_settings(parent, path):
    """Импортируем настройки вышестоящего прокси. Только для версии 7.1 и выше."""
    if parent.version >= 7.1:
        json_file = os.path.join(path, 'upstream_proxy_settings.json')
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            return

        parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Настройки/Вышестоящий прокси".')

        err, result = parent.utm.set_upstream_proxy_settings(data)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            parent.stepChanged.emit('ORANGE|    Ошибка импорта настроек вышестоящего прокси!')
        else:
            parent.stepChanged.emit('GREEN|    Импортированы настройки вышестоящего прокси в раздел "UserGate/Настройки/Вышестоящий прокси".')


def import_users_certificate_profiles(parent, path):
    """Импортируем профили пользовательских сертификатов. Только для версии 7.1 и выше."""
    json_file = os.path.join(path, 'users_certificate_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
            parent.stepChanged.emit('ORANGE|    Ошибка импорта профилей пользовательских сертификатов!')
            return

    parent.stepChanged.emit('BLUE|Импорт настроек раздела "UserGate/Профили пользовательских сертификатов".')
    error = 0

    for item in data:
        item['ca_certificates'] = [parent.ngfw_data['certs'][x] for x in item['ca_certificates']]

        err, result = parent.utm.add_client_certificate_profile(item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        elif err == 2:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    Импортирован профиль "{item["name"]}".')
            parent.client_certificate_profiles[item['name']] = result

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта профилей пользовательских сертификатов!')
    else:
        parent.stepChanged.emit('GREEN|    Импортированы профили пользовательских сертификатов в раздел "UserGate/Профили пользовательских сертификатов".')


#----------------------------------------------- Сеть --------------------------------------------------------
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
            service_name = service['service_id']
            # Проверяем что такой сервис существует в этой версии NGFW и получаем его ID.
            try:
                service['service_id'] = self.ngfw_zone_services[service['service_id']]
            except KeyError as err:
                self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. Не корректный сервис "{service_name}" в контроле доступа.')
                self.description = f'{self.description}\nError: Не импортирован сервис "{service_name}" в контроль доступа.'
                self.error = 1
                continue
            # Приводим список разрешённых адресов сервиса в соответствие с версией NGFW.
            if service['allowed_ips']:
                if self.ngfw_version < 7.1:
                    if isinstance(service['allowed_ips'][0], list):
                        service['allowed_ips'] = []
                        self.parent.stepChanged.emit(f'ORANGE|    Для зоны "{self.name}" в контроле доступа сервиса "{service_name}" удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.')
                        self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.'
                else:
                    if isinstance(service['allowed_ips'][0], list):
                        allowed_ips = []
                        for item in service['allowed_ips']:
                            if item[0] == 'list_id':
                                try:
                                    item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                                except KeyError as err:
                                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В контроле доступа сервиса "{service_name}" не найден список IP-адресов {err}.')
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
                            err, list_id = add_new_nlist(self.parent.utm, nlist_name, 'network', content)
                            if err == 1:
                                self.parent.stepChanged.emit(f'RED|    {list_id}')
                                self.parent.stepChanged.emit(f'RED|       Error [Зона "{self.name}"]. Не создан список IP-адресов в контроле доступа сервиса "{service_name}".')
                                self.description = f'{self.description}\nError: В контроле доступа сервиса "{service_name}" не создан список IP-адресов.'
                                self.error = 1
                                continue
                            elif err == 2:
                                self.parent.stepChanged.emit(f'ORANGE|    Warning: Список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}" уже существует.')
                                self.parent.stepChanged.emit('bRED|       Перезапустите конвертер и повторите попытку.')
                                continue
                            else:
                                self.parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" контроля доступа сервиса "{service_name}" зоны "{self.name}".')
                                service['allowed_ips'] = [['list_id', list_id]]
                                self.parent.ngfw_data['ip_lists'][nlist_name] = list_id
            # Удаляем сервисы зон версии 7.1 которых нет в более старых версиях.
            if self.ngfw_version < 7.1:
                for service in zone['services_access']:
                    if service['service_id'] in (31, 32, 33):
                        continue

            new_service_access.append(service)
        self.services_access = new_service_access


    def check_networks(self):
        """Обрабатываем защиту от IP-спуфинга"""
        if self.networks:
            if self.ngfw_version < 7.1:
                if isinstance(self.networks[0], list):
                    self.networks = []
                    self.enable_antispoof = False
                    self.antispoof_invert = False
                    self.parent.stepChanged.emit(f'ORANGE|    Для зоны "{zone["name"]}" удалены списки IP-адресов в защите от IP-спуфинга. Списки поддерживаются только в версии 7.1 и выше.')
                    self.description = f'{self.description}\nError: В защите от IP-спуфинга удалены списки IP-адресов. Списки поддерживаются только в версии 7.1 и выше.'
            else:
                if isinstance(self.networks[0], list):
                    new_networks = []
                    for item in self.networks:
                        if item[0] == 'list_id':
                            try:
                                item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                            except KeyError as err:
                                self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Защита от IP-спуфинга" не найден список IP-адресов {err}.')
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
                        err, list_id = add_new_nlist(self.parent.utm, nlist_name, 'network', content)
                        if err == 1:
                            self.parent.stepChanged.emit(f'RED|    {list_id}')
                            self.parent.stepChanged.emit(f'RED|       Error [Зона "{self.name}"]. Не создан список IP-адресов в защите от IP-спуфинга.')
                            self.description = f'{self.description}\nError: В разделе "Защита от IP-спуфинга" не создан список IP-адресов.'
                            self.networks = []
                            self.error = 1
                        elif err == 2:
                            self.parent.stepChanged.emit(f'ORANGE|    Warning: Список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{self.name}" уже существует.')
                            self.parent.stepChanged.emit('bRED|       Перезапустите конвертер и повторите попытку.')
                            self.networks = []
                        else:
                            self.parent.stepChanged.emit(f'BLACK|    Cоздан список IP-адресов "{nlist_name}" защиты от IP-спуфинга для зоны "{self.name}".')
                            self.networks = [['list_id', list_id]]
                            self.parent.ngfw_data['ip_lists'][nlist_name] = list_id


    def check_sessions_limit(self):
        """Обрабатываем ограничение сессий"""
        new_sessions_limit_exclusions = []
        if self.ngfw_version >= 7.1:
            for item in self.sessions_limit_exclusions:
                try:
                    item[1] = self.parent.ngfw_data['ip_lists'][item[1]]
                    new_sessions_limit_exclusions.append(item)
                except KeyError as err:
                    self.parent.stepChanged.emit(f'RED|    Error [Зона "{self.name}"]. В разделе "Ограничение сессий" не найден список IP-адресов {err}.')
                    self.description = f'{self.description}\nError: В разделе "Ограничение сессий" не найден список IP-адресов {err}.'
                    self.error = 1
            self.sessions_limit_exclusions = new_sessions_limit_exclusions
            if not self.sessions_limit_exclusions:
                self.sessions_limit_enabled = False


def import_zones(parent, path):
    """Импортируем зоны на NGFW, если они есть."""
    json_file = os.path.join(path, 'config_zones.json')
    err, zones = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')
    error = 0

    for zone in zones:
        zone['name'] = func.get_restricted_name(zone['name'])

        current_zone = Zone(parent, zone)
        zone['services_access'] = current_zone.services_access
        zone['enable_antispoof'] = current_zone.enable_antispoof
        zone['antispoof_invert'] = current_zone.antispoof_invert
        zone['networks'] = current_zone.networks

        if parent.utm.float_version < 7.1:
            zone.pop('sessions_limit_enabled', None)
            zone.pop('sessions_limit_threshold', None)
            zone.pop('sessions_limit_exclusions', None)
        else:
            zone['sessions_limit_enabled'] = current_zone.sessions_limit_enabled
            zone['sessions_limit_exclusions'] = current_zone.sessions_limit_exclusions

        zone['description'] = current_zone.description
        error = current_zone.error

        err, result = parent.utm.add_zone(zone)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}. Зона "{zone["name"]}" не импортирована.')
        elif err == 2:
            parent.stepChanged.emit(f'uGRAY|    {result}')
            err, result2 = parent.utm.update_zone(parent.ngfw_data['zones'][zone['name']], zone)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}')
            elif err == 2:
                parent.stepChanged.emit(f'uGRAY|       {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|       Зона "{zone["name"]}" обновлена.')
        else:
            parent.ngfw_data['zones'][zone["name"]] = result
            parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
    else:
        parent.stepChanged.emit('GREEN|    Зоны импортированы в раздел "Сеть/Зоны".')


def import_interfaces(parent, path):
    err, result = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при создании интерфейсов GRE/IPIP/VXLAN.')
        parent.error = 1
        return
    ngfw_ifaces = {x['name']: x['kind'] for x in result}

    err, result = parent.utm.get_netflow_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка создания интерфейса VLAN.')
        parent.error = 1
        return
    list_netflow = {x['name']: x['id'] for x in result}
    list_netflow['undefined'] = 'undefined'

    list_lldp = {}
    if parent.version >= 7:
        err, result = parent.utm.get_lldp_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка создания интерфейса VLAN.')
            parent.error = 1
            return
        list_lldp = {x['name']: x['id'] for x in result}
        list_lldp['undefined'] = 'undefined'

    json_file = os.path.join(path, 'config_interfaces.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    kinds = {item['kind'] for item in data}

    if 'tunnel' in kinds:
        import_ipip_interfaces(parent, path, data, ngfw_ifaces)
    if 'vlan' in kinds:
        import_vlans(parent, path, list_netflow, list_lldp)
    if 'vpn' in kinds:
        import_vpn_interfaces(parent, path, data, list_netflow, list_lldp, ngfw_ifaces)


def import_ipip_interfaces(parent, path, data, ngfw_ifaces):
    """Импортируем интерфесы IP-IP."""
    # Проверяем что есть интерфейсы IP-IP для импорта.
    is_gre = False
    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'][:3] == 'gre':
            is_gre = True
    if not is_gre:
        return

    parent.stepChanged.emit('BLUE|Импорт интерфейсов GRE/IPIP/VXLAN в раздел "Сеть/Интерфейсы".')
    mc_gre = [int(name[3:]) for name, kind in ngfw_ifaces.items() if kind == 'tunnel' and name.startswith('gre')]
    gre_num = max(mc_gre) if mc_gre else 0
    if gre_num:
        parent.stepChanged.emit(f'rNOTE|    Для интерфейсов GRE будут использованы номера начиная с {gre_num + 1} так как младшие номера уже существуют на NGFW.')
    error = 0

    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'].startswith('gre'):
            gre_num += 1
            item['name'] = f"gre{gre_num}"
            item.pop('id', None)
            item.pop('master', None)
            item.pop('mac', None)
            item.pop('node_name', None)              # удаляем если конфиг получен из МС
            if item.get('config_on_device', False):  # не импортируем если конфиг получен из МС и параметр True.
                continue

            if item['zone_id']:
                try:
                    item['zone_id'] = parent.ngfw_data['zones'][item['zone_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Для интерфейса "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0

            err, result = parent.utm.add_interface_tunnel(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Интерфейс {item["tunnel"]["mode"]} - {item["name"]} не импортирован]')
                error = 1
            elif err == 2:
                parent.stepChanged.emit(f'rNOTE|    {result} [Интерфейс {item["tunnel"]["mode"]} - {item["name"]} не импортирован]')
            else:
                parent.stepChanged.emit(f'BLACK|    Добавлен интерфейс {item["tunnel"]["mode"]} - {item["name"]}.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейсов GRE/IPIP/VXLAN.')
    else:
        parent.stepChanged.emit('GREEN|    Интерфейсы GRE/IPIP/VXLAN импортированы в раздел "Сеть/Интерфейсы".')


def import_vlans(parent, path, list_netflow, list_lldp):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    parent.stepChanged.emit('BLUE|Импорт VLAN в раздел "Сеть/Интерфейсы".')
    error = 0
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        if parent.ngfw_vlans == 1:
            parent.error = 1
        return

    for item in parent.iface_settings:
        if 'kind' in item and item['kind'] == 'vlan':
            current_port = parent.new_vlans[item['vlan_id']]['port']
            current_zone = parent.new_vlans[item['vlan_id']]['zone']
            if item["vlan_id"] in parent.ngfw_vlans:
                parent.stepChanged.emit(f'GRAY|    VLAN {item["vlan_id"]} уже существует на порту {parent.ngfw_vlans[item["vlan_id"]]}')
                continue
            if current_port == "Undefined":
                parent.stepChanged.emit(f"rNOTE|    VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                continue
            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'
            item['enabled'] = False      # Отключаем интерфейс. После импорта надо включить руками.
            if item['mode'] == 'keep':   # Если конфиг получен из МС
                item['mode'] = 'manual'

            item.pop('id', None)          # удаляем readonly поле
            item.pop('master', None)      # удаляем readonly поле
            item.pop('kind', None)        # удаляем readonly поле
            item.pop('mac', None)

            if item.get('config_on_device', False):  # не импортируем если конфиг получен из МС и настраивается на устройстве.
                continue
            item.pop('node_name', None)         # удаляем если конфиг получен из МС

            if current_zone != "Undefined":
                try:
                    item['zone_id'] = parent.ngfw_data['zones'][current_zone]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: Не найдена зона "{err}" для VLAN "{item["name"]}". Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0
                    error = 1
            else:
                item['zone_id'] = 0

            if parent.version < 7.1:
                item.pop('ifalias', None)
                item.pop('flow_control', None)
            if parent.version < 7.0:
                item.pop('dhcp_default_gateway', None)
                item.pop('lldp_profile', None)
            else:
                try:
                    item['lldp_profile'] = list_lldp[item['lldp_profile']]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Для VLAN "{item["name"]}" не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили lldp.')
                    item['lldp_profile'] = 'undefined'
            try:
                item['netflow_profile'] = list_netflow[item['netflow_profile']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Для VLAN "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow.')
                item['netflow_profile'] = 'undefined'

            err, result = parent.utm.add_interface_vlan(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Интерфейс {item["name"]} не импортирован]')
                error = 1
            else:
                parent.ngfw_vlans[item['vlan_id']] = item['name']
                parent.stepChanged.emit(f'BLACK|    Интерфейс VLAN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейса VLAN.')
    else:
        parent.stepChanged.emit('GREEN|    Интерфейсы VLAN импортированы в раздел "Сеть/Интерфейсы".')


def import_vpn_interfaces(parent, path, data, list_netflow, list_lldp, ngfw_ifaces):
    """Импортируем интерфейсы VPN"""
    parent.stepChanged.emit('BLUE|Импорт интерфейсов VPN в раздел "Сеть/Интерфейсы".')
    error = 0
    
    for item in data:
        if 'kind' in item and item['kind'] == 'vpn':
            if item['name'] in ngfw_ifaces:
                parent.stepChanged.emit(f'GRAY|    Интерфейс VPN {item["name"]} уже существует на NGFW.')
                continue

            item['node_name'] = 'cluster'
            item.pop('id', None)
            item.pop('mac', None)
            item.pop('master', None)
            item.pop('running', None)

            if item['zone_id']:
                try:
                    item['zone_id'] = parent.ngfw_data['zones'][item['zone_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: Для интерфейса "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0
                    error = 1

            if parent.version < 7.1:
                item.pop('ifalias', None)
                item.pop('flow_control', None)
            if parent.version < 7.0:
                item.pop('lldp_profile', None)
            else:
                try:
                    item['lldp_profile'] = list_lldp[item['lldp_profile']]
                except KeyError:
                    parent.stepChanged.emit(f'RED|    Error: Для интерфейса "{item["name"]}" не найден lldp profile "{item["lldp_profile"]}". Импортируйте профили lldp.')
                    item['lldp_profile'] = 'undefined'
                    error = 1
            try:
                item['netflow_profile'] = list_netflow[item['netflow_profile']]
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error: Для интерфейса "{item["name"]}" не найден netflow profile "{item["netflow_profile"]}". Импортируйте профили netflow.')
                item['netflow_profile'] = 'undefined'
                error = 1

            err, result = parent.utm.add_interface_vpn(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Интерфейс "{item["name"]}" не импортирован]')
                error = 1
            elif err == 2:
                parent.stepChanged.emit(f'rNOTE|    {result} [Интерфейс "{item["name"]}" не импортирован]')
            else:
                ngfw_ifaces[item['name']] = item['kind']
                parent.stepChanged.emit(f'BLACK|    Интерфейс VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте интерфейса VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Интерфейсы VPN импортированы в раздел "Сеть/Интерфейсы".')


def import_gateways(parent, path):
    import_gateways_list(parent, path)
    import_gateway_failover(parent, path)


def import_gateways_list(parent, path):
    """Импортируем список шлюзов"""
    json_file = os.path.join(path, 'config_gateways.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    parent.stepChanged.emit('LBLUE|    После импорта шлюзы будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
        parent.error = 1
        return
    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}
    gateways_read_only = {x.get('name', x['ipv4']): x.get('is_automatic', False) for x in result}

    if parent.version >= 6:
        err, result = parent.utm.get_routes_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
            parent.error = 1
            return
        vrf_list = [x['name'] for x in result]

    for item in data:
        if parent.version >= 6:
            if item['vrf'] not in vrf_list:
                err, result = add_empty_vrf(parent.utm, item['vrf'])
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    parent.stepChanged.emit(f'RED|    Error: Для шлюза "{item["name"]}" не удалось добавить VRF "{item["vrf"]}". Установлен VRF по умолчанию.')
                    item['vrf'] = 'default'
                    item['default'] = False
                else:
                    parent.stepChanged.emit(f'NOTE|    Для шлюза "{item["name"]}" создан VRF "{item["vrf"]}".')
                    time.sleep(3)   # Задержка, т.к. vrf долго применяет конфигурацию.
        else:
            item['iface'] = 'undefined'
            item.pop('is_automatic', None)
            item.pop('vrf', None)
        item.pop('node_name', None)         # удаляем если конфиг получен из МС
            
        if item['name'] in gateways_list:
            if not gateways_read_only[item['name']]:
                err, result = parent.utm.update_gateway(gateways_list[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [Шлюз "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" уже существует - Updated!')
            else:
                parent.stepChanged.emit(f'NOTE|    Шлюз "{item["name"]}" - объект только для чтения. Not updated!')
        else:
            item['enabled'] = False
            err, result = parent.utm.add_gateway(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Шлюз "{item["name"]}" не импортирован]')
                error = 1
            else:
                gateways_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
    else:
        parent.stepChanged.emit('GREEN|    Шлюзы импортированы в раздел "Сеть/Шлюзы".')


def import_gateway_failover(parent, path):
    """Импортируем настройки проверки сети"""
    json_file = os.path.join(path, 'config_gateway_failover.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек проверки сети раздела "Сеть/Шлюзы/Проверка сети".')

    err, result = parent.utm.set_gateway_failover(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при обновлении настроек проверки сети!')
    else:
        parent.stepChanged.emit('GREEN|    Настройки проверки сети обновлены.')


def import_dhcp_subnets(parent, path):
    """Импортируем настойки DHCP"""
    parent.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
    if isinstance(parent.ngfw_ports, int):
        parent.stepChanged.emit(parent.dhcp_settings)
        if parent.ngfw_ports == 1:
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_dhcp_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP!')
        parent.error = 1
        return
    ngfw_dhcp_subnets = [x['name'] for x in result]

    for item in parent.dhcp_settings:
        item.pop('node_name', None)         # удаляем если конфиг получен из МС
        if item['iface_id'] == 'Undefined':
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
            continue
        if item['name'] in ngfw_dhcp_subnets:
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как уже существует.')
            continue
        if item['iface_id'] not in parent.ngfw_ports:
            parent.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт: {item["iface_id"]} не существует.')
            continue

        err, result = parent.utm.add_dhcp_subnet(item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}   [subnet "{item["name"]}" не импортирован]')
            error = 1
        elif err == 2:
            parent.stepChanged.emit(f'NOTE|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован.')
            ngfw_dhcp_subnets.append(item['name'])
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP!')
    else:
        parent.stepChanged.emit('GREEN|    Настройки DHCP импортированы.')


def import_dns_config(parent, path):
    """Импортируем настройки DNS"""
    import_dns_proxy(parent, path)
    import_dns_servers(parent, path)
    import_dns_rules(parent, path)
    import_dns_static(parent, path)


def import_dns_proxy(parent, path):
    """Импортируем настройки DNS прокси"""
    json_file = os.path.join(path, 'config_dns_proxy.json')
    err, result = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек DNS-прокси раздела "Сеть/DNS/Настройки DNS-прокси".')
    error = 0
    if parent.version < 6.0:
        result.pop('dns_receive_timeout', None)
        result.pop('dns_max_attempts', None)
    for key, value in result.items():
        err, result = parent.utm.set_settings_param(key, value)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DNS-прокси!')
    else:
        parent.stepChanged.emit('GREEN|    Настройки DNS-прокси импортированы.')


def import_dns_servers(parent, path):
    """Импортируем список системных DNS серверов"""
    json_file = os.path.join(path, 'config_dns_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт системных DNS серверов раздела "Сеть/DNS/Системные DNS-серверы".')
    error = 0
    for item in data:
        item.pop('id', None)
        item.pop('is_bad', None)
        err, result = parent.utm.add_dns_server(item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result} [DNS сервер "{item["dns"]}" не импортирован]')
            error = 1
        elif err == 2:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте системных DNS-серверов!')
    else:
        parent.stepChanged.emit('GREEN|    Системные DNS-сервера импортированы.')


def import_dns_rules(parent, path):
    """Импортируем список правил DNS прокси"""
    json_file = os.path.join(path, 'config_dns_rules.json')
    err, rules = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил DNS-прокси раздела "Сеть/DNS/Правила DNS".')
    error = 0
    dns_rules = [x['name'] for x in parent.utm._server.v1.dns.rules.list(parent.utm._auth_token, 0, 1000, {})['items']]

    for item in rules:
        item.pop('position_layer', None)    # Удаляем если экспорт был из шаблона МС.
        if parent.version >= 6.0:
            item['position'] = 'last'
        if item['name'] in dns_rules:
            parent.stepChanged.emit(f'GRAY|    Правило DNS прокси "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_dns_rule(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Правило DNS прокси "{item["name"]}" не импортировано]')
                error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Правило DNS прокси "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил DNS-прокси!')
    else:
        parent.stepChanged.emit('GREEN|    Правила DNS-прокси импортированы.')


def import_dns_static(parent, path):
    """Импортируем статические записи DNS прокси"""
    json_file = os.path.join(path, 'config_dns_static.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт статических записей DNS-прокси раздела "Сеть/DNS/Статические записи".')
    error = 0

    for item in data:
        err, result = parent.utm.add_dns_static_record(item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result} [Статическая запись DNS "{item["name"]}" не импортирована]')
            error = 1
        elif err == 2:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS-прокси!')
    else:
        parent.stepChanged.emit('GREEN|    Статические записи DNS-прокси импортированы.')

    
def import_vrf(parent, path):
    """Импортируем список виртуальных маршрутизаторов"""
    json_file = os.path.join(path, 'config_vrf.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт виртуальных маршрутизаторов в раздел "Сеть/Виртуальные маршрутизаторы".')
    parent.stepChanged.emit('LBLUE|    Добавляемые маршруты будут в не активном состоянии. Необходимо будет проверить маршрутизацию и включить их.')
    parent.stepChanged.emit('LBLUE|    Если вы используете BGP, по окончании импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.')
    error = 0

    err, result = parent.utm.get_interfaces_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
        parent.error = 1
        return
    ngfw_ifaces = {func.get_restricted_name(x['name']) for x in result}

    err, result = parent.utm.get_routes_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
        parent.error = 1
        return
    virt_routes = {func.get_restricted_name(x['name']): x['id'] for x in result}

    if parent.version >= 7.1:
        err, result = parent.utm.get_bfd_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
            parent.error = 1
            return
        bfd_profiles = {x['name']: x['id'] for x in result}
        bfd_profiles[-1] = -1

    vrfnames = []
    for item in data:
        if item['name'] in vrfnames:
            parent.stepChanged.emit(f'rNOTE|    VRF "{item["name"]}" не импортирован так как VRF с таким именем уже был импортирован выше.')
            continue
        else:
            vrfnames.append(item['name'])
        
        for x in item['routes']:
            x['enabled'] = False
            x['name'] = func.get_restricted_name(x['name'])
            if x['ifname'] != 'undefined':
                if x['ifname'] not in ngfw_ifaces:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Интерфейс "{x["ifname"]}" удалён из статического маршрута "{x["name"]}" так как отсутствует на NGFW.')
                    x['ifname'] = 'undefined'
                    error = 1

        if item['ospf']:
            item['ospf']['enabled'] = False
            ids = set()
            new_interfaces = []
            for x in item['ospf']['interfaces']:
                if x['iface_id'] not in ngfw_ifaces:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Интерфейс OSPF "{x["iface_id"]}" удалён из настроек OSPF так как отсутствует на NGFW.')
                    ids.add(x['id'])
                    error = 1
                    continue
                if item['name'] != 'default' and x['iface_id'] not in item['interfaces']:
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Интерфейс OSPF "{x["iface_id"]}" удалён из настроек OSPF так как отсутствует в этом VRF.')
                    ids.add(x['id'])
                    error = 1
                else:
                    if parent.version < 7.1:
                        x.pop('bfd_profile', None)
                        x.pop('network_type', None)
                        x.pop('is_passive', None)
                    else:
                        x['network_type'] = x.get('network_type', '')
                        x['is_passive'] = x.get('is_passive', False)
                        try:
                            x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                        except KeyError as err:
                            parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Для OSPF не найден профиль BFD {err}. Установлено значение по умолчанию.')
                            x['bfd_profile'] = -1
                            error = 1
                    new_interfaces.append(x)
            item['ospf']['interfaces'] = new_interfaces

            new_areas = []
            for area in item['ospf']['areas']:
                err, result = func.unpack_ip_address(area['area_id'])
                if err:
                    try:
                        area['area_id'] = int(area['area_id'])
                    except ValueError:
                        parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё не валидный идентификатор области.')
                        error = 1
                        continue
                tmp = set(area['interfaces'])
                if not (tmp - ids):
                    parent.stepChanged.emit(f'RED|    Error [VRF "{item["name"]}"]. Область OSPF "{area["name"]}" удалёна из настроек OSPF так как у неё отсутствуют интерфейсы.')
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
            if parent.version < 7:
                item['bgp']['as_number'] = str(item['bgp']['as_number'])
            for x in item['bgp']['neighbors']:
                x['filter_in'] = []
                x['filter_out'] = []
                x['routemap_in'] = []
                x['routemap_out'] = []
                if parent.version < 7:
                    x['remote_asn'] = str(x['remote_asn'])
                if parent.version < 7.1:
                    x.pop('bfd_profile', None) 
                else:
                    try:
                        x['bfd_profile'] = bfd_profiles[x['bfd_profile']]
                    except KeyError:
                        x['bfd_profile'] = -1
                        parent.stepChanged.emit(f'rNOTE|    Не найден профиль BFD для VRF "{item["name"]}". Установлено значение по умолчанию.')

        if item['name'] in virt_routes:
            parent.stepChanged.emit(f'GRAY|    Виртуальный маршрутизатор "{item["name"]}" уже существует.')
            err, result = parent.utm.update_vrf(virt_routes[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [vrf: "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Виртуальный маршрутизатор "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_vrf(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [vrf: "{item["name"]}" не импортирован]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуальных маршрутизаторов.')
    else:
        parent.stepChanged.emit('GREEN|    Виртуальные маршрутизаторы импортированы в раздел "Сеть/Виртуальные маршрутизаторы".')


def import_wccp_rules(parent, path):
    """Импортируем список правил WCCP"""
    json_file = os.path.join(path, 'config_wccp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    error = 0

    parent.stepChanged.emit('BLUE|Импорт правил WCCP в раздел "Сеть/WCCP".')
    err, result = parent.utm.get_wccp_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
        parent.error = 1
        return
    wccp_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('cc_network_devices', None)    # Если конфиг экспортирован с МС.
        item.pop('cc_network_devices_negate', None)
        if parent.version < 7:
            item['ports'] = [str(x) for x in item['ports']]
        if parent.version == 7.0:
            item['mask_value'] = ""
        if item['routers']:
            routers = []
            for x in item['routers']:
                if x[0] == 'list_id':
                    try:
                        x[1] = parent.ngfw_data['ip_lists'][x[1]]
                    except KeyError as err:
                        parent.stepChanged.emit(f'ORANGE|    Не найден список {err} для правила "{item["name"]}". Загрузите списки IP-адресов и повторите попытку.')
                        continue
                routers.append(x)
            item['routers'] = routers

        if item['name'] in wccp_rules:
            parent.stepChanged.emit(f'NOTE|    Правило WCCP "{item["name"]}" уже существует.')
            if parent.version >= 6:
                err, result = parent.utm.update_wccp_rule(wccp_rules[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|       {result}')
                    error = 1
                else:
                    parent.stepChanged.emit(f'NOTE|       Правило WCCP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_wccp_rule(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result} [Правило WCCP "{item["name"]}" не импортировано]')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Правило WCCP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил WCCP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила WCCP импортированы в раздел "Сеть/WCCP".')


#-------------------------------------- Пользователи и устройства ---------------------------------------------------
def import_local_groups(parent, path):
    """Импортируем список локальных групп пользователей"""
    json_file = os.path.join(path, 'config_groups.json')
    err, groups = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
    error = 0

    for item in groups:
        users = item.pop('users')
        # В версии 5 API добавления группы не проверяет что группа уже существует.
        if item['name'] in parent.ngfw_data['local_groups']:
            parent.stepChanged.emit(f'GRAY|    Группа "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_group(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Локальная группа "{item["name"]}" не импортирована]')
                error = 1
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что группа уже существует.
            else:
                parent.ngfw_data['local_groups'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Локальная группа "{item["name"]}" импортирована.')

        # В версии 5 в группах нет доменных пользователей.
        if parent.version <= 6:
            continue
        # Добавляем доменных пользователей в группу.
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1 and ('\\' in user_array[1]):
                domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                err1, result1 = parent.utm.get_ldap_user_guid(domain, name)
                if err1:
                    parent.stepChanged.emit(f'RED|       {result1} [Не удалось получить GUID пользователя {user_name} из домена {domain}]')
                    error = 1
                    break
                elif not result1:
                    parent.stepChanged.emit(f'bRED|    Нет LDAP-коннектора для домена "{domain}"! Доменные пользователи не импортированы в группу "{item["name"]}".')
                    parent.stepChanged.emit(f'bRED|    Импортируйте и настройте LDAP-коннектор. Затем повторите импорт групп.')
                    break
                err2, result2 = parent.utm.add_user_in_group(parent.ngfw_data['local_groups'][item['name']], result1)
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [Пользователь "{user_name}" не добавлен в группу "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Ошибка импорта локальных групп пользователей!')
    else:
        parent.stepChanged.emit('GREEN|    Локальные группы пользователей импортирован в раздел "Пользователи и устройства/Группы".')


def import_local_users(parent, path):
    """Импортируем список локальных пользователей"""
    json_file = os.path.join(path, 'config_users.json')
    err, users = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
    error = 0

    for item in users:
        user_groups = item.pop('groups', None)
        # В версии 5 API добавления пользователя не проверяет что он уже существует.
        if item['name'] in parent.ngfw_data['local_users']:
            parent.stepChanged.emit(f'GRAY|    Пользователь "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_user(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result} [Пользователь "{item["name"]}" не импортирован]')
                error = 1
                break
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
            else:
                parent.ngfw_data['local_users'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

        # Добавляем пользователя в группу.
        for group in user_groups:
            try:
                group_guid = parent.ngfw_data['local_groups'][group]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
            else:
                err2, result2 = parent.utm.add_user_in_group(group_guid, parent.ngfw_data['local_users'][item['name']])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [User "{item["name"]}" не добавлен в группу "{group}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей!')
    else:
        parent.stepChanged.emit('GREEN|    Локальные пользователи импортированы в раздел "Пользователи и устройства/Пользователи".')


def import_auth_servers(parent, path):
    """Импортируем список серверов аутентификации"""
    import_ldap_servers(parent, path)
    import_ntlm_server(parent, path)
    import_radius_server(parent, path)
    import_tacacs_server(parent, path)
    import_saml_server(parent, path)
    

def import_ldap_servers(parent, path):
    """Импортируем список серверов LDAP"""
    json_file = os.path.join(path, 'config_ldap_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0

    err, result = parent.utm.get_ldap_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        ldap_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in ldap_servers:
                parent.stepChanged.emit(f'GRAY|    LDAP-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['keytab_exists'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('ldap', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [Сервер аутентификации LDAP "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ldap_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации LDAP "{item["name"]}" импортирован.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}", ввести пароль и импортировать keytab файл.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP!')
    else:
        parent.stepChanged.emit('GREEN|    Сервера LDAP импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_ntlm_server(parent, path):
    """Импортируем список серверов NTLM"""
    json_file = os.path.join(path, 'config_ntlm_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0

    err, result = parent.utm.get_ntlm_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        ntlm_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in ntlm_servers:
                parent.stepChanged.emit(f'GRAY|    NTLM-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('ntlm', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [Сервер аутентификации NTLM "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    ntlm_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации NTLM "{item["name"]}" импортирован.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM!')
    else:
        parent.stepChanged.emit('GREEN|    Сервера NTLM импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_radius_server(parent, path):
    """Импортируем список серверов RADIUS"""
    json_file = os.path.join(path, 'config_radius_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0

    err, result = parent.utm.get_radius_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        radius_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in radius_servers:
                parent.stepChanged.emit(f'GRAY|    RADIUS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('radius', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [Сервер аутентификации RADIUS "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    radius_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и ввести пароль.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS!')
    else:
        parent.stepChanged.emit('GREEN|    Сервера RADIUS импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_tacacs_server(parent, path):
    """Импортируем список серверов TACACS+"""
    json_file = os.path.join(path, 'config_tacacs_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0

    err, result = parent.utm.get_tacacs_servers()
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        tacacs_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in tacacs_servers:
                parent.stepChanged.emit(f'GRAY|    TACACS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                err, result = parent.utm.add_auth_server('tacacs', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [Сервер аутентификации TACACS+ "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    tacacs_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и ввести секретный ключ.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+!')
    else:
        parent.stepChanged.emit('GREEN|    Сервера TACACS+ импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_saml_server(parent, path):
    """Импортируем список серверов SAML"""
    json_file = os.path.join(path, 'config_saml_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
    error = 0

    err, result = parent.utm.get_saml_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        saml_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in saml_servers:
                parent.stepChanged.emit(f'GRAY|    SAML-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item.pop("cc", None)
                try:
                    item['certificate_id'] = parent.ngfw_data['certs'][item['certificate_id']]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден сертификат "{item["certificate_id"]}".')
                    item['certificate_id'] = 0

                err, result = parent.utm.add_auth_server('saml', item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [Сервер аутентификации SAML "{item["name"]}" не импортирован]')
                    error = 1
                else:
                    saml_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации SAML "{item["name"]}" импортирован.')
                    parent.stepChanged.emit(f'NOTE|    Необходимо включить "{item["name"]}" и загрузить SAML metadata.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML!')
    else:
        parent.stepChanged.emit('GREEN|    Сервера SAML импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_2fa_profiles(parent, path):
    """Импортируем список 2FA профилей"""
    json_file = os.path.join(path, 'config_2fa_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей MFA в раздел "Пользователи и устройства/Профили MFA".')
    error = 0

    if not parent.notification_profiles:
        if get_notification_profiles_list(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
            return

    err, result = parent.utm.get_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
        parent.error = 1
        return
    else:
        profiles_2fa = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles_2fa:
            parent.stepChanged.emit(f'GRAY|    Профиль MFA "{item["name"]}" уже существует.')
        else:
            if item['type'] == 'totp':
                if item['init_notification_profile_id'] not in parent.notification_profiles:
                    parent.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["init_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    error = 1
                    continue
                item['init_notification_profile_id'] = parent.notification_profiles[item['init_notification_profile_id']]
            else:
                if item['auth_notification_profile_id'] not in parent.notification_profiles:
                    parent.stepChanged.emit(f'RED|    Error: Профиль MFA "{item["name"]}" не добавлен. Не найден профиль оповещения "{item["auth_notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                    error = 1
                    continue
                item['auth_notification_profile_id'] = parent.notification_profiles[item['auth_notification_profile_id']]

            err, result = parent.utm.add_2fa_profile(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль MFA "{item["name"]}" не импортирован]')
                error = 1
            else:
                profiles_2fa[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль MFA "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей MFA.')
    else:
        parent.stepChanged.emit('GREEN|    Профили MFA импортированы в раздел "Пользователи и устройства/Профили MFA".')


def import_auth_profiles(parent, path):
    """Импортируем список профилей аутентификации"""
    json_file = os.path.join(path, 'config_auth_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей аутентификации в раздел "Пользователи и устройства/Профили аутентификации".')
    error = 0

    err, ldap, radius, tacacs, ntlm, saml = parent.utm.get_auth_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {ldap}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
        parent.error = 1
        return
    auth_servers = {func.get_restricted_name(x['name']): x['id'] for x in [*ldap, *radius, *tacacs, *ntlm, *saml]}

    err, result = parent.utm.get_2fa_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
        parent.error = 1
        return
    profiles_2fa = {func.get_restricted_name(x['name']): x['id'] for x in result}

    auth_type = {
        'ldap': 'ldap_server_id',
        'radius': 'radius_server_id',
        'tacacs_plus': 'tacacs_plus_server_id',
        'ntlm': 'ntlm_server_id',
        'saml_idp': 'saml_idp_server_id'
    }

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['2fa_profile_id']:
            try:
                item['2fa_profile_id'] = profiles_2fa[item['2fa_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден профиль MFA "{item["2fa_profile_id"]}". Загрузите профили MFA и повторите попытку.')
                item['2fa_profile_id'] = False
                error = 1

        for auth_method in item['allowed_auth_methods']:
            if len(auth_method) == 2:
                method_server_id = auth_type[auth_method['type']]
                try:
                    auth_method[method_server_id] = auth_servers[auth_method[method_server_id]]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден сервер аутентификации "{auth_method[method_server_id]}". Загрузите серверы аутентификации и повторите попытку.')
                    auth_method.clear()
                    error = 1

                if 'saml_idp_server_id' in auth_method and parent.version < 6:
                    auth_method['saml_idp_server'] = auth_method.pop('saml_idp_server_id', False)

        item['allowed_auth_methods'] = [x for x in item['allowed_auth_methods'] if x]

        if item['name'] in parent.ngfw_data['auth_profiles']:
            parent.stepChanged.emit(f'uGRAY|    Профиль аутентификации "{item["name"]}" уже существует.')
            err, result = parent.utm.update_auth_profile(parent.ngfw_data['auth_profiles'][item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Profile: item["name"]]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль аутентификации "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_auth_profile(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Профиль аутентификации "{item["name"]}" не импортирован]')
                error = 1
            else:
                parent.ngfw_data['auth_profiles'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль аутентификации "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей аутентификации.')
    else:
        parent.stepChanged.emit('GREEN|    Профили аутентификации импортированы в раздел "Пользователи и устройства/Профили аутентификации".')


def import_captive_profiles(parent, path):
    """Импортируем список Captive-профилей"""
    json_file = os.path.join(path, 'config_captive_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Captive-профилей в раздел "Пользователи и устройства/Captive-профили".')
    error = 0

    if not parent.list_templates:
        if get_templates_list(parent):    # Устанавливаем атрибут parent.list_templates
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return

    if not parent.notification_profiles:
        if get_notification_profiles_list(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
            return

    err, result = parent.utm.get_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
        parent.error = 1
        return
    captive_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    if (6 <= parent.version < 7.1):
        result = parent.utm._server.v3.accounts.groups.list(parent.utm._auth_token, 0, 1000, {}, [])['items']
        list_groups = {func.get_restricted_name(x['name']): x['id'] for x in result}

    if parent.version >= 7.1:
        if not parent.client_certificate_profiles:
            if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
                parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
                return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['captive_template_id'] = parent.list_templates.get(item['captive_template_id'], -1)
        try:
            item['user_auth_profile_id'] = parent.ngfw_data['auth_profiles'][item['user_auth_profile_id']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль аутентификации "{item["user_auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['user_auth_profile_id'] = 1
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["user_auth_profile_id"]}".'
            error = 1

        if item['notification_profile_id'] != -1:
            try:
                item['notification_profile_id'] = parent.notification_profiles[item['notification_profile_id']]
            except KeyError:
                parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль оповещения "{item["notification_profile_id"]}". Загрузите профили оповещения и повторите попытку.')
                item['notification_profile_id'] = -1
                item['description'] = f'{item["description"]}\nError: Не найден профиль оповещения "{item["notification_profile_id"]}".'
                error = 1
        try:
            if (6 <= parent.version < 7.1):
                item['ta_groups'] = [list_groups[name] for name in item['ta_groups']]
            else:
                item['ta_groups'] = [parent.ngfw_data['local_groups'][name] for name in item['ta_groups']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Группа гостевых пользователей "{err}" не найдена. Загрузите локальные группы и повторите попытку.')
            item['ta_groups'] = []
            item['description'] = f'{item["description"]}\nError: Не найдена группа гостевых пользователей "{err}".'
            error = 1

        if item['ta_expiration_date']:
            item['ta_expiration_date'] = item['ta_expiration_date'].replace(' ', 'T')
        else:
            item.pop('ta_expiration_date', None)

        if parent.version >= 7.1:
            item.pop('use_https_auth', None)
            if item['captive_auth_mode'] != 'aaa':
                item['client_certificate_profile_id'] = parent.client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
                if not item['client_certificate_profile_id']:
                    parent.stepChanged.emit(f'RED|    Error [Captive-profile "{item["name"]}"]. Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Загрузите профили сертификата пользователя и повторите попытку.')
                    item['captive_auth_mode'] = 'aaa'
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                    error = 1
        else:
            item.pop('captive_auth_mode', None)
            item.pop('client_certificate_profile_id', None)

        if item['name'] in captive_profiles:
            parent.stepChanged.emit(f'uGRAY|    Captive-профиль "{item["name"]}" уже существует.')
            err, result = parent.utm.update_captive_profile(captive_profiles[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Captive-profile: {item["name"]}]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Captive-профиль "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_captive_profile(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-profile "{item["name"]}" не импортирован]')
                error = 1
            else:
                captive_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Captive-профиль "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте Captive-профилей.')
    else:
        parent.stepChanged.emit('GREEN|    Captive-профили импортированы в раздел "Пользователи и устройства/Captive-профили".')


def import_captive_portal_rules(parent, path):
    """Импортируем список правил Captive-портала"""
    json_file = os.path.join(path, 'config_captive_portal_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил Captive-портала в раздел "Пользователи и устройства/Captive-портал".')
    error = 0

    err, result = parent.utm.get_captive_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
        parent.error = 1
        return
    captive_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_captive_portal_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
        parent.error = 1
        return
    captive_portal_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['profile_id']:
            try:
                item['profile_id'] = captive_profiles[item['profile_id']]
            except KeyError:
                parent.stepChanged.emit('RED|    [Captive-portal "{item["name"]}"]. Не найден Captive-профиль "{item["profile_id"]}". Загрузите Captive-профили и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден Captive-профиль "{item["profile_id"]}".'
                item['profile_id'] = 0
                error = 1
        item['src_zones'] = get_zones_id(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones_id(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips_id(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips_id(parent, item['dst_ips'], item['name'])
        item['urls'] = get_urls_id(parent, item['urls'], item['name'])
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], item['name'])
        item['time_restrictions'] = get_time_restrictions_id(parent, item['time_restrictions'], item['name'])

        if item['name'] in captive_portal_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило Captive-портала "{item["name"]}" уже существует.')
            err, result = parent.utm.update_captive_portal_rule(captive_portal_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Captive-portal "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило Captive-портала "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_captive_portal_rules(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Captive-portal "{item["name"]}" не импортирован]')
                error = 1
            else:
                captive_portal_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило Captive-портала "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил Captive-портала.')
    else:
        parent.stepChanged.emit('GREEN|    Правила Captive-портала импортированы в раздел "Пользователи и устройства/Captive-портал".')


def import_terminal_servers(parent, path):
    """Импортируем список терминальных серверов"""
    json_file = os.path.join(path, 'config_terminal_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка терминальных серверов в раздел "Пользователи и устройства/Терминальные серверы".')
    error = 0

    err, result = parent.utm.get_terminal_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка терминальных серверов.')
        parent.error = 1
        return
    terminal_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in terminal_servers:
            parent.stepChanged.emit(f'uGRAY|    Терминальный сервер "{item["name"]}" уже существует.')
            err, result = parent.utm.update_terminal_server(terminal_servers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [Terminal Server "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       Терминальный сервер "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_terminal_server(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [Terminal Server "{item["name"]}" не импортирован]')
                error = 1
            else:
                terminal_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Терминальный сервер "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка терминальных серверов.')
    else:
        parent.stepChanged.emit('GREEN|    Список терминальных серверов импортирован в раздел "Пользователи и устройства/Терминальные серверы".')


def import_byod_policy(parent, path):
    """Импортируем список Политики BYOD"""
    json_file = os.path.join(path, 'config_byod_policy.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Политики BYOD" в раздел "Пользователи и устройства/Политики BYOD".')
    error = 0

    err, result = parent.utm.get_byod_policy()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Политики BYOD".')
        parent.error = 1
        return
    byod_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name'])
        if item['name'] in byod_rules:
            parent.stepChanged.emit(f'uGRAY|    Политика BYOD "{item["name"]}" уже существует.')
            err, result = parent.utm.update_byod_policy(byod_rules[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [BYOD policy "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       BYOD policy "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_byod_policy(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [BYOD policy "{item["name"]}" не импортирована]')
                error = 1
            else:
                byod_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Политика BYOD "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Политики BYOD".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Политики BYOD" импортирован в раздел "Пользователи и устройства/Политики BYOD".')


def import_userid_agent(parent, path):
    """Импортируем настройки UserID агент"""
    import_agent_config(parent, path)
    import_agent_servers(parent, path)


def import_agent_config(parent, path):
    """Импортируем настройки UserID агент"""
    json_file = os.path.join(path, 'userid_agent_config.json')
    err, result = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Импорт свойств агента UserID в раздел "Пользователи и устройства/UserID агент".')

    # В случае версий 7.2 и выше - берём только первую конфигурацию свойств, так как при экспорте с кластера могут быть
    # конфигурации со всех узлов кластера и не понятно свойства с какого узла импортировать.
    try:
        data = result[0]
    except Exception:       # Будет ошибка если экспортировали конвертером версии 3.1 и ниже.
        parent.stepChanged.emit(f'RED|    Error: Произошла ошибка при импорте свойства агента UserID. Ошибка файла конфигурации.')
        parent.error = 1
        return

    data.pop('name', None)
    if parent.utm.float_version != 7.2:
        data['expiration_time'] = 2700
        data.pop('radius_monitoring_interval', None)

    if data['tcp_ca_certificate_id']:
        try:
            data['tcp_ca_certificate_id'] = parent.ngfw_data['certs'][data['tcp_ca_certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit('RED|    Error: Не найден сертификат "{err}". Загрузите сертификаты и повторите попытку.')
            data.pop('tcp_ca_certificate_id', None)
            error = 1
    else:
        data.pop('tcp_ca_certificate_id', None)

    if data['tcp_server_certificate_id']:
        try:
            data['tcp_server_certificate_id'] = parent.ngfw_data['certs'][data['tcp_server_certificate_id']]
        except KeyError as err:
            parent.stepChanged.emit('RED|    Error: Не найден сертификат УЦ "{err}". Загрузите сертификаты и повторите попытку.')
            data.pop('tcp_server_certificate_id', None)
            error = 1
    else:
        data.pop('tcp_server_certificate_id', None)

    new_networks = []
    for x in data['ignore_networks']:
        try:
            new_networks.append(['list_id', parent.ngfw_data['ip_lists'][x[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Не найден список IP-адресов {err} для Ignore Networks. Загрузите списки IP-адресов и повторите попытку.')
            error = 1
    data['ignore_networks'] = new_networks

    err, result = parent.utm.set_useridagent_config(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result} [Свойства агента UserID не импортированы]')
        error = 1

    if error:
        parent.error = 1
        parent.stepChanged.emit(f'ORANGE|    Произошла ошибка при импорте свойства агента UserID.')
    else:
        parent.stepChanged.emit('BLACK|    Свойства агента UserID обновлены.')


def import_agent_servers(parent, path):
    """Импортируем настройки AD и свойств отправителя syslog UserID агент"""
    json_file = os.path.join(path, 'userid_agent_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт Агент UserID в раздел "Пользователи и устройства/Агент UserID".')
    error = 0

    err, result = parent.utm.get_useridagent_filters()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек UserID агент.')
        parent.error = 1
        return
    useridagent_filters = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_useridagent_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек UserID агент.')
        parent.error = 1
        return
    useridagent_servers = {x['name']: x['id'] for x in result}


    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if parent.utm.float_version != 7.2:
            if item['type'] == 'radius':
                parent.stepChanged.emit(f'NOTE|    Коннектор UserID агент "{item["name"]}" не импортирован так как ваша версия NGFW меньше 7.2.')
                continue
            item.pop('exporation_time', None)
        try:
            item['auth_profile_id'] = parent.ngfw_data['auth_profiles'][item['auth_profile_id']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден профиль аутентификации "{item["auth_profile_id"]}". Загрузите профили аутентификации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль аутентификации "{item["auth_profile_id"]}".'
            item['auth_profile_id'] = 1
            error = 1
        if 'filters' in item:
            new_filters = []
            for filter_name in item['filters']:
                try:
                    new_filters.append(useridagent_filters[filter_name])
                except KeyError:
                    parent.stepChanged.emit(f'RED|    Error [UserID агент "{item["name"]}"]. Не найден Syslog фильтр UserID агента "{filter_name}". Загрузите фильтры UserID агента и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден Syslog фильтр UserID агента "{filter_name}".'
                    error = 1
            item['filters'] = new_filters

        if item['name'] in useridagent_servers:
            parent.stepChanged.emit(f'uGRAY|    UserID агент "{item["name"]}" уже существует.')
            err, result = parent.utm.update_useridagent_server(useridagent_servers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'RED|       {result}  [UserID агент "{item["name"]}"]')
                error = 1
            else:
                parent.stepChanged.emit(f'uGRAY|       UserID агент "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_useridagent_server(item)
            if err:
                parent.stepChanged.emit(f'RED|    {result}  [UserID агент "{item["name"]}" не импортирован]')
                error = 1
            else:
                useridagent_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    UserID агент "{item["name"]}" импортирован.')
        if item['type'] == 'ad':
            parent.stepChanged.emit(f'LBLUE|       Необходимо указать пароль для этого коннетора Microsoft AD.')
        elif item['type'] == 'radius':
            parent.stepChanged.emit(f'LBLUE|       Необходимо указать секретный код для этого коннетора RADIUS.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек UserID агент.')
    else:
        parent.stepChanged.emit('GREEN|    Агенты UserID импортированы в раздел "Пользователи и устройства/Агент UserID".')


#---------------------------------------- Политики сети ---------------------------------------------------------
def import_firewall_rules(parent, path):
    """Импортируем список правил межсетевого экрана"""
    json_file = os.path.join(path, 'config_firewall_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')
#    parent.stepChanged.emit('LBLUE|    После импорта правила МЭ будут в не активном состоянии. Необходимо проверить и включить нужные.')

    if not parent.scenarios_rules:
        if get_scenarios_rules(parent):     # Устанавливаем атрибут parent.scenarios_rules
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            return

    if parent.version >= 7.1:
        err, result = parent.utm.get_idps_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            parent.error = 1
            return
        idps_profiles = {x['name']: x['id'] for x in result}

        err, result = parent.utm.get_l7_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            parent.error = 1
            return
        l7_profiles = {x['name']: x['id'] for x in result}

        err, result = parent.utm.get_hip_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
            parent.error = 1
            return
        hip_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_firewall_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
        parent.error = 1
        return
    firewall_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)

        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило МЭ "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1
        if parent.version < 7.1:
            if 'apps' in item:
                item['apps'] = get_apps(parent, item['apps'], item['name'])
            else:
                item['apps'] = []
                item['apps_negate'] = False
            item.pop('ips_profile', None)
            item.pop('l7_profile', None)
            item.pop('hip_profiles', None)
            if parent.version >= 6:
                item.pop('apps_negate', None)
        else:
            item.pop('apps', None)
            item.pop('apps_negate', None)
            if 'ips_profile' in item and item['ips_profile']:
                try:
                    item['ips_profile'] = idps_profiles[item['ips_profile']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило МЭ "{item["name"]}"]. Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
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
                    parent.stepChanged.emit(f'RED|    Error [Правило МЭ "{item["name"]}"]. Не найден профиль приложений {err}. Загрузите профили приложений и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль приложений {err}.'
                    item['l7_profile'] = False
                    item['enabled'] = False
                    error = 1
            else:
                item['l7_profile'] = False
            if 'hip_profiles' in item:
                new_hip_profiles = []
                for hip in item['hip_profiles']:
                    try:
                        new_hip_profiles.append(hip_profiles[hip])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило МЭ "{item["name"]}"]. Не найден профиль HIP {err}. Загрузите профили HIP и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль HIP {err}.'
                        item['enabled'] = False
                        error = 1
                item['hip_profiles'] = new_hip_profiles
            else:
                item['hip_profile'] = []

        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['services'] = get_services(parent, item['services'], item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)

        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило МЭ "{item["name"]}" уже существует.')
            err, result = parent.utm.update_firewall_rule(firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило МЭ "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило МЭ "{item["name"]}" updated.')
        else:
            item['position'] = 'last' 
            err, result = parent.utm.add_firewall_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило МЭ "{item["name"]}" не импортировано]')
            else:
                firewall_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило МЭ "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил межсетевого экрана.')
    else:
        parent.stepChanged.emit('GREEN|    Правила межсетевого экрана импортированы в раздел "Политики сети/Межсетевой экран".')


def import_nat_rules(parent, path):
    """Импортируем список правил NAT"""
    json_file = os.path.join(path, 'config_nat_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил NAT в раздел "Политики сети/NAT и маршрутизация".')
#    parent.stepChanged.emit('LBLUE|    После импорта правила NAT будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0

    if not parent.scenarios_rules:
        if get_scenarios_rules(parent):     # Устанавливаем атрибут parent.scenarios_rules
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
            return

    err, result = parent.utm.get_gateways_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        parent.error = 1
        return
    ngfw_gateways = {x['name']: f'{x["id"]}:{x["node_name"]}' for x in result if 'name' in x}

    err, result = parent.utm.get_traffic_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
        parent.error = 1
        return
    nat_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1
        if parent.version >= 6:
            item['users'] = get_guids_users_and_groups(parent, item)
        else:
            item.pop('users', None)
        item['zone_in'] = get_zones_id(parent, 'src', item['zone_in'], item)
        item['zone_out'] = get_zones_id(parent, 'dst', item['zone_out'], item)
        item['source_ip'] = get_ips_id(parent, 'src', item['source_ip'], item)
        item['dest_ip'] = get_ips_id(parent, 'dst', item['dest_ip'], item)
        item['service'] = get_services(parent, item['service'], item)
        item['gateway'] = ngfw_gateways.get(item['gateway'], item['gateway'])
            
        if item['action'] == 'route':
            parent.stepChanged.emit(f'LBLUE|    [Правило "{item["name"]}"] Проверьте шлюз для правила ПБР. В случае отсутствия, установите вручную.')

        if item['name'] in nat_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_traffic_rule(nat_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" updated.')
        else:
            item['position'] = 'last' 
            err, result = parent.utm.add_traffic_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                nat_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
    else:
        parent.stepChanged.emit('GREEN|    Правила NAT импортированы в раздел "Политики сети/NAT и маршрутизация".')


def import_loadbalancing_rules(parent, path):
    """Импортируем правила балансировки нагрузки"""
    parent.stepChanged.emit('BLUE|Импорт правил балансировки нагрузки в раздел "Политики сети/Балансировка нагрузки".')
    err, tcpudp, icap, reverse = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {tcpudp}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки нагрузки.')
        parent.error = 1
        return
    import_loadbalancing_tcpudp(parent, path, tcpudp)
    import_loadbalancing_icap(parent, path, icap)
    import_loadbalancing_reverse(parent, path, reverse)


def import_loadbalancing_tcpudp(parent, path, tcpudp):
    """Импортируем балансировщики TCP/UDP"""
    json_file = os.path.join(path, 'config_loadbalancing_tcpudp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков TCP/UDP для импорта.')
        return
    elif err == 1:
        return

    parent.stepChanged.emit('BLUE|    Импорт балансировщиков TCP/UDP.')
    tcpudp_rules = {func.get_restricted_name(x['name']): x['id'] for x in tcpudp}
    error = 0

    for item in data:
        if parent.version < 7.1:
            item.pop('src_zones', None)
            item.pop('src_zones_negate', None)
            item.pop('src_ips', None)
            item.pop('src_ips_negate', None)
        else:
            item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
            item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in tcpudp_rules:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки TCP/UDP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_virtualserver_rule(tcpudp_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки TCP/UDP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_virtualserver_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                tcpudp_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки TCP/UDP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки TCP/UDP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила балансировки TCP/UDP импортированы.')


def import_loadbalancing_icap(parent, path, icap):
    """Импортируем балансировщики ICAP"""
    json_file = os.path.join(path, 'config_loadbalancing_icap.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков ICAP для импорта.')
        return
    elif err == 1:
        return

    parent.stepChanged.emit('BLUE|    Импорт балансировщиков ICAP.')
    icap_loadbalancing = {func.get_restricted_name(x['name']): x['id'] for x in icap}
    error = 0

    if not parent.icap_servers:
        if get_icap_servers(parent):      # Устанавливаем атрибут parent.icap_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
            return

    for item in data:
        try:
            item['profiles'] = [parent.icap_servers[x] for x in item['profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|       Error [Правило "{item["name"]}"]. Не найден сервер ICAP {err}. Импортируйте серверы ICAP и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
            item['profiles'] = []
            item['enabled'] = False
            error = 1

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in icap_loadbalancing:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки ICAP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_icap_loadbalancing_rule(icap_loadbalancing[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки ICAP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_icap_loadbalancing_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                icap_loadbalancing[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки ICAP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила балансировки ICAP импортированы.')


def import_loadbalancing_reverse(parent, path, reverse):
    """Импортируем балансировщики reverse-proxy"""
    json_file = os.path.join(path, 'config_loadbalancing_reverse.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err in (2, 3):
        parent.stepChanged.emit(f'GRAY|    Нет балансировщиков Reverse-proxy для импорта.')
        return
    elif err == 1:
        return

    parent.stepChanged.emit('BLUE|    Импорт балансировщиков Reverse-proxy.')
    if not parent.reverseproxy_servers:
        if get_reverseproxy_servers(parent):      # Устанавливаем атрибут parent.reverseproxy_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
            return

    reverse_rules = {func.get_restricted_name(x['name']): x['id'] for x in reverse}
    error = 0

    for item in data:
        try:
            item['profiles'] = [parent.reverseproxy_servers[x] for x in item['profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|       Error [Правило "{item["name"]}"]. Не найден сервер reverse-proxy {err}. Загрузите серверы reverse-proxy и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден сервер reverse-proxy {err}.'
            item['profiles'] = []
            item['enabled'] = False
            error = 1

        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in reverse_rules:
            parent.stepChanged.emit(f'uGRAY|       Правило балансировки reverse-proxy "{item["name"]}" уже существует.')
            err, result = parent.utm.update_reverse_loadbalancing_rule(reverse_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|          {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|          Правило балансировки reverse-proxy "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_reverse_loadbalancing_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                reverse_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|       Правило балансировки reverse-proxy "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил балансировки Reverse-proxy.')
    else:
        parent.stepChanged.emit('GREEN|    Правила балансировки Reverse-proxy импортированы.')


def import_shaper_rules(parent, path):
    """Импортируем список правил пропускной способности"""
    json_file = os.path.join(path, 'config_shaper_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
    error = 0

    if not parent.scenarios_rules:
        if get_scenarios_rules(parent):     # Устанавливаем атрибут parent.scenarios_rules
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
            return

    err, result = parent.utm.get_shaper_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        parent.error = 1
        return
    shaper_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_shaper_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
        parent.error = 1
        return
    shaper_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        if parent.version < 6:
            item.pop('limit', None)
            item.pop('limit_value', None)
            item.pop('limit_burst', None)
            item.pop('log', None)
            item.pop('log_session_start', None)
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['services'] = get_services(parent, item['services'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['apps'] = get_apps(parent, item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)
        try:
            item['pool'] = shaper_list[item['pool']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена полоса пропускания "{item["pool"]}". Импортируйте полосы пропускания и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена полоса пропускания "{item["pool"]}".'
            item['pool'] = 1
            item['enabled'] = False
            error = 1

        if item['name'] in shaper_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_shaper_rule(shaper_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило пропускной способности "{item["name"]}" updated.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_shaper_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
            else:
                shaper_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
    else:
        parent.stepChanged.emit('GREEN|    Правила пропускной способности импортированы в раздел "Политики сети/Пропускная способность".')


#----------------------------------------- Политики безопасности --------------------------------------------------
def import_content_rules(parent, path):
    """Импортируем список правил фильтрации контента"""
    json_file = os.path.join(path, 'config_content_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
    error = 0

    if not parent.scenarios_rules:
        if get_scenarios_rules(parent):     # Устанавливаем атрибут parent.scenarios_rules
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
            return

    if not parent.list_templates:
        if get_templates_list(parent):    # Устанавливаем атрибут parent.list_templates
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
            return

    err, result = parent.utm.get_nlists_list('morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        parent.error = 1
        return
    morphology_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        parent.error = 1
        return
    useragent_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_content_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
        parent.error = 1
        return
    content_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        if parent.version < 7.1:
            item.pop('layer', None)
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        try:
            item['blockpage_template_id'] = parent.list_templates[item['blockpage_template_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден шаблон страницы блокировки {err}. Импортируйте шаблоны страниц и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден шаблон страницы блокировки {err}.'
            item['blockpage_template_id'] = -1
            item['enabled'] = False
            error = 1

        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['url_categories'] = get_url_categories_id(parent, item)
        item['urls'] = get_urls_id(parent, item['urls'], item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)
        item['referers'] = get_urls_id(parent, item['referers'], item)
        if parent.version < 6:
            item.pop('referer_categories', None)
            item.pop('users_negate', None)
            item.pop('position_layer', None)
        else:
            item['referer_categories'] = get_url_categories_id(parent, item, referer=1)

        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Загрузите сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1

        new_morph_categories = []
        for x in item['morph_categories']:
            try:
                new_morph_categories.append(morphology_list[x])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список морфрлогии {err}. Загрузите списки морфологии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список морфрлогии {err}.'
                item['enabled'] = False
                error = 1
        item['morph_categories'] = new_morph_categories

        new_user_agents = []
        for x in item['user_agents']:
            try:
                new_user_agents.append(['list_id', useragent_list[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список UserAgent {err}. Загрузите списки Useragent браузеров и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список UserAgent {err}.'
                item['enabled'] = False
                error = 1
        item['user_agents'] = new_user_agents

        new_content_types = []
        for x in item['content_types']:
            try:
                new_content_types.append(parent.ngfw_data['mime'][x])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список типов контента {err}. Загрузите списки Типов контента и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                item['enabled'] = False
                error = 1
        item['content_types'] = new_content_types

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
            err, result = parent.utm.update_content_rule(content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило КФ "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило контентной фильтрации "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_content_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило КФ "{item["name"]}" не импортировано]')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
    else:
        parent.stepChanged.emit('GREEN|    Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".')


def import_safebrowsing_rules(parent, path):
    """Импортируем список правил веб-безопасности"""
    json_file = os.path.join(path, 'config_safebrowsing_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил веб-безопасности в раздел "Политики безопасности/Веб-безопасность".')
    error = 0

    err, result = parent.utm.get_safebrowsing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.')
        parent.error = 1
        return
    safebrowsing_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)
        item['url_list_exclusions'] = get_urls_id(parent, item['url_list_exclusions'], item)

        if item['name'] in safebrowsing_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило веб-безопасности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_safebrowsing_rule(safebrowsing_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило веб-безопасности "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило веб-безопасности "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_safebrowsing_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило веб-безопасности "{item["name"]}" не импортировано]')
            else:
                safebrowsing_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило веб-безопасности "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил веб-безопасности.')
    else:
        parent.stepChanged.emit('GREEN|    Правила веб-безопасности импортированны в раздел "Политики безопасности/Веб-безопасность".')


def import_tunnel_inspection_rules(parent, path):
    """Импортируем список правил инспектирования туннелей"""
    json_file = os.path.join(path, 'config_tunnelinspection_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования туннелей в раздел "Политики безопасности/Инспектирование туннелей".')
    error = 0

    err, rules = parent.utm.get_tunnel_inspection_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.')
        parent.error = 1
        return
    tunnel_inspect_rules = {func.get_restricted_name(x['name']): x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)

        if item['name'] in tunnel_inspect_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования туннелей "{item["name"]}" уже существует.')
            err, result = parent.utm.update_tunnel_inspection_rule(tunnel_inspect_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования туннелей "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования туннелей "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_tunnel_inspection_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования туннелей "{item["name"]}" не импортировано]')
            else:
                tunnel_inspect_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования туннелей "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования туннелей.')
    else:
        parent.stepChanged.emit('GREEN|    Правила инспектирования туннелей импортированны в раздел "Политики безопасности/Инспектирование туннелей".')


def import_ssldecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSL"""
    json_file = os.path.join(path, 'config_ssldecrypt_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSL в раздел "Политики безопасности/Инспектирование SSL".')
    error = 0

    ssl_forward_profiles = {}
    if parent.version >= 7:
        err, rules = parent.utm.get_ssl_forward_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
            parent.error = 1
            return
        ssl_forward_profiles = {x['name']: x['id'] for x in rules}
        ssl_forward_profiles[-1] = -1

    err, rules = parent.utm.get_ssldecrypt_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
        parent.error = 1
        return
    ssldecrypt_rules = {func.get_restricted_name(x['name']): x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['url_categories'] = get_url_categories_id(parent, item)
        item['urls'] = get_urls_id(parent, item['urls'], item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)
        if parent.version < 6:
            item.pop('ssl_profile_id', None)
        else:
            try:
                item['ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err} для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                item['ssl_profile_id'] = parent.ngfw_data['ssl_profiles']['Default SSL profile']
                item['enabled'] = False
                error = 1
        if parent.version < 7:
            item.pop('ssl_forward_profile_id', None)
            if item['action'] == 'decrypt_forward':
                item['action'] = 'decrypt'
        else:
            try:
                item['ssl_forward_profile_id'] = ssl_forward_profiles[item['ssl_forward_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль пересылки SSL {err} для правила "{item["name"]}". Загрузите профили SSL и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль пересылки SSL {err}.'
                item['ssl_forward_profile_id'] = -1
                item['enabled'] = False
                error = 1

        if item['name'] in ssldecrypt_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_ssldecrypt_rule(ssldecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSL "{item["name"]}"]')
                continue
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования SSL "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_ssldecrypt_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSL "{item["name"]}" не импортировано]')
                continue
            else:
                ssldecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSL "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Правила инспектирования SSL импортированны в раздел "Политики безопасности/Инспектирование SSL".')


def import_sshdecrypt_rules(parent, path):
    """Импортируем список правил инспектирования SSH"""
    json_file = os.path.join(path, 'config_sshdecrypt_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил инспектирования SSH в раздел "Политики безопасности/Инспектирование SSH".')
    error = 0

    err, rules = parent.utm.get_sshdecrypt_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
        parent.error = 1
        return
    sshdecrypt_rules = {x['name']: x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)
        if parent.version < 7.1:
            item.pop('layer', None)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)
        item['protocols'] = get_services(parent, item['protocols'], item)

        if item['name'] in sshdecrypt_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило инспектирования SSH "{item["name"]}" уже существует.')
            err, result = parent.utm.update_sshdecrypt_rule(sshdecrypt_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило инспектирования SSH "{item["name"]}"]')
                continue
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило инспектирования SSH "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_sshdecrypt_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило инспектирования SSH "{item["name"]}" не импортировано]')
                continue
            else:
                sshdecrypt_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило инспектирования SSH "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил инспектирования SSH.')
    else:
        parent.stepChanged.emit('GREEN|    Правила инспектирования SSH импортированны в раздел "Политики безопасности/Инспектирование SSH".')


def import_idps_rules(parent, path):
    """Импортируем список правил СОВ"""
    json_file = os.path.join(path, 'config_idps_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил СОВ в раздел "Политики безопасности/СОВ".')
    error = 0

    err, result = parent.utm.get_nlists_list('ipspolicy')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил СОВ.')
        parent.error = 1
        return
    idps_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_idps_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил СОВ.')
        parent.error = 1
        return
    idps_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        if parent.version < 7.0 and item['action'] == 'reset':
            item['action'] = 'drop'
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['services'] = get_services(parent, item['services'], item)
        try:
            item['idps_profiles'] = [idps_profiles[x] for x in item['idps_profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
            item['idps_profiles'] = [idps_profiles['ENTENSYS_IPS_POLICY'],]
            item['enabled'] = False
            error = 1
        if parent.version < 6:
            item.pop('idps_profiles_exclusions', None)
        else:
            try:
                item['idps_profiles_exclusions'] = [idps_profiles[x] for x in item['idps_profiles_exclusions']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error! Правило "{item["name"]}": Не найден профиль исключения СОВ {err}. Загрузите профили СОВ и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль исключения СОВ {err}.'
                item['idps_profiles_exclusions'] = []
                item['enabled'] = False
                error = 1

        if item['name'] in idps_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило СОВ "{item["name"]}" уже существует.')
            err, result = parent.utm.update_idps_rule(idps_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило СОВ "{item["name"]}"]')
                continue
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило СОВ "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_idps_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило СОВ "{item["name"]}" не импортировано]')
                continue
            else:
                idps_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило СОВ "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Правила СОВ импортированны в раздел "Политики безопасности/СОВ".')


def import_scada_rules(parent, path):
    """Импортируем список правил АСУ ТП"""
    json_file = os.path.join(path, 'config_scada_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил АСУ ТП в раздел "Политики безопасности/Правила АСУ ТП".')
    error = 0

    err, rules = parent.utm.get_scada_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил АСУ ТП.')
        parent.error = 1
        return
    scada_profiles = {func.get_restricted_name(x['name']): x['id'] for x in rules}

    err, rules = parent.utm.get_scada_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил АСУ ТП.')
        parent.error = 1
        return
    scada_rules = {func.get_restricted_name(x['name']): x['id'] for x in rules}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        try:
            item['services'] = [parent.ngfw_data['services'][x] for x in item['services']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сервис {err}. Загрузите список сервисов и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден сервис {err}.'
            item['services'] = []
            item['enabled'] = False
            error = 1
        try:
            item['scada_profiles'] = [scada_profiles[x] for x in item['scada_profiles']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль СОВ {err}. Загрузите профили СОВ и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль СОВ {err}.'
            item['scada_profiles'] = []
            item['enabled'] = False
            error = 1

        if item['name'] in scada_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило АСУ ТП "{item["name"]}" уже существует.')
            err, result = parent.utm.update_scada_rule(scada_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило АСУ ТП "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило АСУ ТП "{item["name"]}" обновлено.')
        else:
            if parent.version < 6:
                item.pop('position', None)
            else:
                item['position'] = 'last'
            err, result = parent.utm.add_scada_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило АСУ ТП "{item["name"]}" не импортировано]')
            else:
                scada_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило АСУ ТП "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил АСУ ТП.')
    else:
        parent.stepChanged.emit('GREEN|    Правила АСУ ТП импортированны в раздел "Политики безопасности/Правила АСУ ТП".')


def import_mailsecurity(parent, path):
    import_mailsecurity_rules(parent, path)
    import_mailsecurity_antispam(parent, path)
    import_mailsecurity_batv(parent, path)

def import_mailsecurity_rules(parent, path):
    """Импортируем список правил защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
    error = 0

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        parent.error = 1
        return
    email = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_mailsecurity_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
        parent.error = 1
        return
    mailsecurity_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['enabled'] = False
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        if parent.version < 6:
            item['protocol'] = list({'pop' if x[1] in ['POP3', 'POP3S'] else 'smtp' for x in item['services']})
            item.pop('services', None)
            item.pop('envelope_to_negate', None)
            item.pop('envelope_from_negate', None)
        else:
            if not item['services']:
                item['services'] = [['service', 'SMTP'], ['service', 'POP3'], ['service', 'SMTPS'], ['service', 'POP3S']]
            item['services'] = get_services(parent, item['services'], item)

        try:
            item['envelope_from'] = [[x[0], email[x[1]]] for x in item['envelope_from']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден список почтовых адресов {err}.'
            item['envelope_from'] = []
            item['enabled'] = False
            error = 1

        try:
            item['envelope_to'] = [[x[0], email[x[1]]] for x in item['envelope_to']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список почтовых адресов {err}. Загрузите список почтовых адресов и повторите попытку.')
            item['envelope_to'] = []
            item['enabled'] = False
            error = 1

        if parent.version < 7.1:
            item.pop('rule_log', None)
        if parent.version < 7:
            item.pop('dst_zones_negate', None)

        if item['name'] in mailsecurity_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_mailsecurity_rule(mailsecurity_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
                continue
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_mailsecurity_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}" не импортировано]')
                continue
            else:
                mailsecurity_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты почтового трафика.')
    else:
        parent.stepChanged.emit('GREEN|    Правила защиты почтового трафика импортированы в раздел "Политики безопасности/Защита почтового трафика".')


def import_mailsecurity_antispam(parent, path):
    """Импортируем dnsbl защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_dnsbl.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт настроек антиспама защиты почтового трафика в раздел "Политики безопасности/Защита почтового трафика".')
    parent.stepChanged.emit('BLUE|    Импорт настроек DNSBL.')

    data['white_list'] = get_ips_id(parent, 'white_list', data['white_list'], {'name': 'antispam DNSBL'})
    data['black_list'] = get_ips_id(parent, 'black_list', data['black_list'], {'name': 'antispam DNSBL'})

    err, result = parent.utm.set_mailsecurity_dnsbl(data)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|       {result}')
        parent.stepChanged.emit('ORANGE|       Произошла ошибка при импорте настроек DNSBL.')
    else:
        parent.stepChanged.emit(f'GREEN|       Список DNSBL импортирован.')


def import_mailsecurity_batv(parent, path):
    """Импортируем batv защиты почтового трафика"""
    json_file = os.path.join(path, 'config_mailsecurity_batv.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|    Импорт настройки BATV.')

    err, result = parent.utm.set_mailsecurity_batv(data)
    if err:
        parent.error = 1
        parent.stepChanged.emit(f'RED|       {result}')
        parent.stepChanged.emit('ORANGE|       Произошла ошибка при импорте настроек BATV.')
    else:
        parent.stepChanged.emit(f'GREEN|       Настройка BATV импортирована.')


def import_icap_servers(parent, path):
    """Импортируем список серверов ICAP"""
    json_file = os.path.join(path, 'config_icap_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов ICAP в раздел "Политики безопасности/ICAP-серверы".')
    error = 0

    if not parent.icap_servers:
        if get_icap_servers(parent):      # Устанавливаем атрибут parent.icap_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.icap_servers:
            parent.stepChanged.emit(f'uGRAY|    ICAP-сервер "{item["name"]}" уже существует.')
            err, result = parent.utm.update_icap_server(parent.icap_servers[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [ICAP-сервер "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       ICAP-сервер "{item["name"]}" обновлён.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_icap_server(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-сервер "{item["name"]}" не импортирован]')
            else:
                parent.icap_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-сервер "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Серверы ICAP импортированы в раздел "Политики безопасности/ICAP-серверы".')


def import_icap_rules(parent, path):
    """Импортируем список правил ICAP"""
    json_file = os.path.join(path, 'config_icap_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил ICAP в раздел "Политики безопасности/ICAP-правила".')
    error = 0

    if not parent.icap_servers:
        if get_icap_servers(parent):      # Устанавливаем атрибут parent.icap_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
            return

    err, err_msg, result, _ = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
        parent.error = 1
        return
    icap_loadbalancing = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_icap_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
        parent.error = 1
        return
    icap_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item.pop('time_created', None)
        item.pop('time_updated', None)

        new_servers = []
        for server in item['servers']:
            if server[0] == 'lbrule':
                try:
                    new_servers.append(['lbrule', icap_loadbalancing[server[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден балансировщик серверов ICAP {err}. Импортируйте балансировщики ICAP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден балансировщик серверов ICAP {err}.'
                    item['enabled'] = False
                    error = 1
            elif server[0] == 'profile':
                try:
                    new_servers.append(['profile', parent.icap_servers[server[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сервер ICAP {err}. Импортируйте сервера ICAP и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден сервер ICAP {err}.'
                    item['enabled'] = False
                    error = 1
        item['servers'] = new_servers

        item['users'] = get_guids_users_and_groups(parent, item)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['url_categories'] = get_url_categories_id(parent, item)
        item['urls'] = get_urls_id(parent, item['urls'], item)

        new_content_types = []
        for x in item['content_types']:
            try:
                new_content_types.append(parent.ngfw_data['mime'][x])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден список типов контента {err}. Импортируйте списки типов контента и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден список типов контента {err}.'
                item['enabled'] = False
                error = 1
        item['content_types'] = new_content_types

        if item['name'] in icap_rules:
            parent.stepChanged.emit(f'uGRAY|    ICAP-правило "{item["name"]}" уже существует.')
            err, result = parent.utm.update_icap_rule(icap_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [ICAP-правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       ICAP-правило "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_icap_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [ICAP-правило "{item["name"]}" не импортировано]')
            else:
                icap_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    ICAP-правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил ICAP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила ICAP импортированы в раздел "Политики безопасности/ICAP-правила".')


def import_dos_profiles(parent, path):
    """Импортируем список профилей DoS"""
    json_file = os.path.join(path, 'config_dos_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей DoS в раздел "Политики безопасности/Профили DoS".')
    error = 0

    err, result = parent.utm.get_dos_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
        parent.error = 1
        return
    dos_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in dos_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_dos_profile(dos_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль DoS "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль DoS "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_dos_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль DoS "{item["name"]}" не импортирован]')
            else:
                dos_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль DoS "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей DoS.')
    else:
        parent.stepChanged.emit('GREEN|    Профили DoS импортированы в раздел "Политики безопасности/Профили DoS".')


def import_dos_rules(parent, path):
    """Импортируем список правил защиты DoS"""
    json_file = os.path.join(path, 'config_dos_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил защиты DoS в раздел "Политики безопасности/Правила защиты DoS".')
    error = 0

    if not parent.scenarios_rules:
        if get_scenarios_rules(parent):     # Устанавливаем атрибут parent.scenarios_rules
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
            return

    err, result = parent.utm.get_dos_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        parent.error = 1
        return
    dos_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_dos_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
        parent.error = 1
        return
    dos_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['dst_zones'] = get_zones_id(parent, 'dst', item['dst_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        item['services'] = get_services(parent, item['services'], item)
        item['time_restrictions'] = get_time_restrictions_id(parent, item)
        if item['dos_profile']:
            try:
                item['dos_profile'] = dos_profiles[item['dos_profile']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль DoS {err}. Импортируйте профили DoS и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль DoS {err}.'
                item['dos_profile'] = False
                item['enabled'] = False
                error = 1
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сценарий {err}. Импортируйте сценарии и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сценарий {err}.'
                item['scenario_rule_id'] = False
                item['enabled'] = False
                error = 1

        if item['name'] in dos_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило защиты DoS "{item["name"]}" уже существует.')
            err, result = parent.utm.update_dos_rule(dos_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило защиты DoS "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило защиты DoS "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_dos_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило защиты DoS "{item["name"]}" не импортировано]')
            else:
                dos_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило защиты DoS "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил защиты DoS.')
    else:
        parent.stepChanged.emit('GREEN|    Правила защиты DoS импортированы в раздел "Политики безопасности/Правила защиты DoS".')


#------------------------------------------ Глобальный портал -----------------------------------------------------------
def import_proxyportal_rules(parent, path):
    """Импортируем список URL-ресурсов веб-портала"""
    parent.stepChanged.emit('BLUE|Импорт списка ресурсов веб-портала в раздел "Глобальный портал/Веб-портал".')
    json_file = os.path.join(path, 'config_web_portal.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    error = 0

    err, result = parent.utm.get_proxyportal_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
        parent.error = 1
        return
    list_proxyportal = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['users'] = get_guids_users_and_groups(parent, item)
        if parent.version < 7:
            item.pop('transparent_auth', None)
        if parent.version < 6:
            item.pop('mapping_url_ssl_profile_id', None)
            item.pop('mapping_url_certificate_id', None)
        else:
            try:
                if item['mapping_url_ssl_profile_id']:
                    item['mapping_url_ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][item['mapping_url_ssl_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                item['mapping_url_ssl_profile_id'] = 0
                item['enabled'] = False
                error = 1
            try:
                if item['mapping_url_certificate_id']:
                    item['mapping_url_certificate_id'] = parent.ngfw_data['certs'][item['mapping_url_certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['mapping_url_certificate_id'] = 0
                item['enabled'] = False
                error = 1

        if item['name'] in list_proxyportal:
            parent.stepChanged.emit(f'uGRAY|    Ресурс веб-портала "{item["name"]}" уже существует.')
            err, result = parent.utm.update_proxyportal_rule(list_proxyportal[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Ресурс веб-портала "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Ресурс веб-портала "{item["name"]}" обновлён.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_proxyportal_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Ресурс веб-портала "{item["name"]}" не импортирован]')
            else:
                list_proxyportal[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Ресурс веб-портала "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте ресурсов веб-портала.')
    else:
        parent.stepChanged.emit('GREEN|    Список ресурсов веб-портала импортирован в раздел "Глобальный портал/Веб-портал".')


def import_reverseproxy_servers(parent, path):
    """Импортируем список серверов reverse-прокси"""
    json_file = os.path.join(path, 'config_reverseproxy_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов reverse-прокси в раздел "Глобальный портал/Серверы reverse-прокси".')
    error = 0

    if not parent.reverseproxy_servers:
        if get_reverseproxy_servers(parent):      # Устанавливаем атрибут parent.reverseproxy_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.reverseproxy_servers:
            parent.stepChanged.emit(f'uGRAY|    Сервер reverse-прокси "{item["name"]}" уже существует.')
            err, result = parent.utm.update_reverseproxy_server(parent.reverseproxy_servers[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сервер reverse-прокси "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Сервер reverse-прокси "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_reverseproxy_server(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сервер reverse-прокси "{item["name"]}" не импортирован]')
            else:
                parent.reverseproxy_servers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сервер reverse-прокси "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов reverse-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера reverse-прокси импортированы в раздел "Глобальный портал/Серверы reverse-прокси".')


def import_reverseproxy_rules(parent, path):
    """Импортируем список правил reverse-прокси"""
    json_file = os.path.join(path, 'config_reverseproxy_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил reverse-прокси в раздел "Глобальный портал/Правила reverse-прокси".')
    error = 0

    err, err_msg, _, result = parent.utm.get_loadbalancing_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        parent.error = 1
        return
    reverse_loadbalancing = {func.get_restricted_name(x['name']): x['id'] for x in result}

    if not parent.reverseproxy_servers:
        if get_reverseproxy_servers(parent):      # Устанавливаем атрибут parent.reverseproxy_servers
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
            return

    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        parent.error = 1
        return
    useragent_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    if parent.version >= 7.1:
        if not parent.client_certificate_profiles:
            if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
                parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                return

        waf_profiles = {}
        if parent.utm.waf_license:  # Проверяем что есть лицензия на WAF
            # Получаем список профилей WAF. Если err=2, лицензия истекла или нет прав на API.
            err, result = parent.utm.get_waf_profiles_list()
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}')
                parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
                parent.error = 1
                return
            elif not err:
                waf_profiles = {x['name']: x['id'] for x in result}
        else:
            parent.stepChanged.emit('NOTE|    Нет лицензии на модуль WAF. Защита приложений WAF будет выключена в правилах.')

    err, result = parent.utm.get_reverseproxy_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
        parent.error = 1
        return
    reverseproxy_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['src_ips'] = get_ips_id(parent, 'src', item['src_ips'], item)
        item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)

        if not item['src_zones']:
            parent.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не указана src-зона.')
            continue

        try:
            for x in item['servers']:
                x[1] = parent.reverseproxy_servers[x[1]] if x[0] == 'profile' else reverse_loadbalancing[x[1]]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error: Правило "{item["name"]}" не импортировано. Не найден сервер reverse-прокси или балансировщик {err}. Импортируйте reverse-прокси или балансировщик и повторите попытку.')
            continue

        if parent.version < 6:
            item.pop('ssl_profile_id', None)
        else:
            if item['ssl_profile_id']:
                try:
                    item['ssl_profile_id'] = parent.ngfw_data['ssl_profiles'][item['ssl_profile_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль SSL {err}. Загрузите профили SSL и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль SSL {err}.'
                    item['ssl_profile_id'] = 0
                    item['is_https'] = False
                    item['enabled'] = False
                    error = 1
            else:
                item['is_https'] = False

        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.ngfw_data['certs'][item['certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Создайте сертификат и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = -1
                item['is_https'] = False
                item['enabled'] = False
                error = 1
        else:
            item['certificate_id'] = -1
            item['is_https'] = False

        new_user_agents = []
        for x in item['user_agents']:
            try:
                new_user_agents.append(['list_id', useragent_list[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден Useragent {err}. Импортируйте useragent браузеров и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден Useragent {err}.'
                item['enabled'] = False
                error = 1
        item['user_agents'] = new_user_agents

        if parent.version < 7.1:
            item.pop('user_agents_negate', None)
            item.pop('waf_profile_id', None)
            item.pop('client_certificate_profile_id', None)
        else:
            if item['client_certificate_profile_id']:
                item['client_certificate_profile_id'] = parent.client_certificate_profiles.get(item['client_certificate_profile_id'], 0)
                if not item['client_certificate_profile_id']:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}". Импортируйте профили пользовательских сертификатов и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя "{item["client_certificate_profile_id"]}".'
                    item['enabled'] = False
                    error = 1
            if item['waf_profile_id']:
                if parent.utm.waf_license:
                    try:
                        item['waf_profile_id'] = waf_profiles[item['waf_profile_id']]
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль WAF {err}. Импортируйте профили WAF и повторите попытку.')
                        item['description'] = f'{item["description"]}\nError: Не найден профиль WAF {err}.'
                        item['waf_profile_id'] = 0
                        item['enabled'] = False
                        error = 1
                else:
                    item['waf_profile_id'] = 0
                    item['description'] = f'{item["description"]}\nError: Нет лицензии на модуль WAF. Профиль WAF "{item["waf_profile_id"]}" не импортирован в правило.'

        if item['name'] in reverseproxy_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило reverse-прокси "{item["name"]}" уже существует.')
            err, result = parent.utm.update_reverseproxy_rule(reverseproxy_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило reverse-прокси "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило reverse-прокси "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_reverseproxy_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило reverse-прокси "{item["name"]}" не импортировано]')
            else:
                reverseproxy_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило reverse-прокси "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил reverse-прокси.')
    else:
        parent.stepChanged.emit('GREEN|    Правила reverse-прокси импортированы в раздел "Глобальный портал/Правила reverse-прокси".')
    parent.stepChanged.emit('LBLUE|    Проверьте флаг "Использовать HTTPS" во всех импортированных правилах! Если не установлен профиль SSL, выберите нужный.')

#--------------------------------------------------- WAF ----------------------------------------------------------------
def import_waf_custom_layers(parent, path):
    """Импортируем персональные WAF-слои. Для версии 7.1 и выше"""
    json_file = os.path.join(path, 'config_waf_custom_layers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт персональных слоёв WAF в раздел "WAF/Персональные WAF-слои".')
    if not parent.utm.waf_license:
        parent.stepChanged.emit('NOTE|    Нет лицензии на модуль WAF.')
        return
    error = 0

    err, result = parent.utm.get_waf_custom_layers_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
        parent.error = 1
        return
    waf_custom_layers = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in waf_custom_layers:
            parent.stepChanged.emit(f'uGRAY|    Персональный WAF-слой "{item["name"]}" уже существует.')
            err, result = parent.utm.update_waf_custom_layer(waf_custom_layers[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Персональный WAF-слой "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Персональный WAF-слой "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_waf_custom_layer(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Персональный WAF-слой "{item["name"]}" не импортирован]')
            else:
                waf_custom_layers[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Персональный WAF-слой "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте персональных слоёв WAF.')
    else:
        parent.stepChanged.emit('GREEN|    Персональные WAF-слои импортированы в раздел "WAF/Персональные WAF-слои".')


def import_waf_profiles(parent, path):
    """Импортируем профили WAF. Для версии 7.1 и выше"""
    json_file = os.path.join(path, 'config_waf_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей WAF в раздел "WAF/WAF-профили".')
    if not parent.utm.waf_license:
        parent.stepChanged.emit('NOTE|    Нет лицензии на модуль WAF.')
        return
    error = 0

    err, result = parent.utm.get_waf_technology_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        parent.error = 1
        return
    waf_technology = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_waf_custom_layers_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        parent.error = 1
        return
    waf_custom_layers = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_waf_system_layers_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        parent.error = 1
        return
    waf_system_layers = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_waf_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
        parent.error = 1
        return
    waf_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        new_layers = []
        for layer in item['layers']:
            if layer['type'] == 'custom_layer':
                try:
                    layer['id'] = waf_custom_layers[layer['id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Профиль "{item["name"]}"]. Не найден персональный WAF-слой {err}. Импортируйте персональные WAF-слои и повторите попытку.')
                    item['description'] = f'{item["description"]}\nError: Не найден персональный WAF-слой {err}.'
                    error = 1
                    continue
            else:
                if parent.utm.float_version >= 8.0:
                    parent.stepChanged.emit(f'sGREEN|    [Профиль "{item["name"]}"]. Не импортирован системный WAF-слой "{layer["id"]}". В версии 8 его пока нет')
                    item['description'] = f'{item["description"]}\nError: Не импортирован системный WAF-слой "{layer["id"]}".'
                    continue
                else:
                    try:
                        layer['id'] = waf_system_layers[layer['id']]
                        layer['protection_technologies'] = [waf_technology[x] for x in layer['protection_technologies']]
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Профиль "{item["name"]}"]. Не найден системный WAF-слой "{layer["id"]}" -  {err}.')
                        item['description'] = f'{item["description"]}\nError: Не найден системный WAF-слой "{layer["id"]}".'
                        error = 1
                        continue
            new_layers.append(layer)
        item['layers'] = new_layers

        if item['name'] in waf_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль WAF "{item["name"]}" уже существует.')
            err, result = parent.utm.update_waf_profile(waf_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль WAF "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль WAF "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_waf_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль WAF "{item["name"]}" не импортирован]')
            else:
                waf_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль WAF "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей WAF.')
    else:
        parent.stepChanged.emit('GREEN|    Профили WAF импортированы в раздел "WAF/WAF-профили".')

#--------------------------------------------------- VPN ----------------------------------------------------------------
def import_vpn_security_profiles(parent, path):
    """Импортируем список профилей безопасности VPN"""
    json_file = os.path.join(path, 'config_vpn_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей безопасности VPN в раздел "VPN/Профили безопасности VPN".')
    error = 0

    err, result = parent.utm.get_vpn_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности VPN.')
        parent.error = 1
        return
    security_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if parent.version < 6:
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
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_vpn_security_profile(security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_vpn_security_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
            else:
                security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Профили безопасности VPN импортированы в раздел "VPN/Профили безопасности VPN".')

def import_vpnclient_security_profiles(parent, path):
    """Импортируем клиентские профилей безопасности VPN. Для версии 7.1 и выше"""
    json_file = os.path.join(path, 'config_vpnclient_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт клиентских профилей безопасности VPN в раздел "VPN/Клиентские профили безопасности".')
    error = 0

    err, result = parent.utm.get_vpn_client_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
        parent.error = 1
        return
    security_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.ngfw_data['certs'][item['certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = 0
                error = 1

        if item['name'] in security_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_vpn_client_security_profile(security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_vpn_client_security_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
            else:
                security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Клиентские профили безопасности импортированы в раздел "VPN/Клиентские профили безопасности".')

def import_vpnserver_security_profiles(parent, path):
    """Импортируем серверные профилей безопасности VPN. Для версии 7.1 и выше"""
    json_file = os.path.join(path, 'config_vpnserver_security_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверных профилей безопасности VPN в раздел "VPN/Серверные профили безопасности".')
    error = 0

    if not parent.client_certificate_profiles:
        if get_client_certificate_profiles(parent): # Устанавливаем атрибут parent.client_certificate_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
            return

    err, result = parent.utm.get_vpn_server_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
        parent.error = 1
        return
    security_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['certificate_id']:
            try:
                item['certificate_id'] = parent.ngfw_data['certs'][item['certificate_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден сертификат {err}. Импортируйте сертификаты и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден сертификат {err}.'
                item['certificate_id'] = 0
                error = 1
        if item['client_certificate_profile_id']:
            try:
                item['client_certificate_profile_id'] = parent.client_certificate_profiles[item['client_certificate_profile_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль сертификата пользователя {err}. Импортируйте профили пользовательских сертификатов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найден профиль сертификата пользователя {err}.'
                item['client_certificate_profile_id'] = 0
                error = 1

        if item['name'] in security_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_vpn_server_security_profile(security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности VPN "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_vpn_server_security_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности VPN "{item["name"]}" не импортирован]')
            else:
                security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности VPN "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных профилей безопасности VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Серверные профили безопасности импортированы в раздел "VPN/Серверные профили безопасности".')


def import_vpn_networks(parent, path):
    """Импортируем список сетей VPN"""
    json_file = os.path.join(path, 'config_vpn_networks.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сетей VPN в раздел "VPN/Сети VPN".')
    error = 0

    err, result = parent.utm.get_vpn_networks()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
        parent.error = 1
        return
    vpn_networks = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['networks'] = get_vpn_networks(parent, item['networks'], item)
        if parent.version < 7.1:
            item.pop('ep_tunnel_all_routes', None)
            item.pop('ep_disable_lan_access', None)
            item.pop('ep_routes_include', None)
            item.pop('ep_routes_exclude', None)
        else:
            item['ep_routes_include'] = get_vpn_networks(parent, item['ep_routes_include'], item)
            item['ep_routes_exclude'] = get_vpn_networks(parent, item['ep_routes_exclude'], item)
        if 'error' in item:
            error = 1
            item.pop('error', None)

        if item['name'] in vpn_networks:
            parent.stepChanged.emit(f'uGRAY|    Сеть VPN "{item["name"]}" уже существует.')
            err, result = parent.utm.update_vpn_network(vpn_networks[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сеть VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Сеть VPN "{item["name"]}" обновлена.')
        else:
            err, result = parent.utm.add_vpn_network(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сеть VPN "{item["name"]}" не импортирована]')
            else:
                vpn_networks[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сеть VPN "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сетей VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Список сетей VPN импортирован в раздел "VPN/Сети VPN".')


def get_vpn_networks(parent, networks, rule):
    """Для функции import_vpn_networks"""
    new_networks = []
    for x in networks:
        try:
            new_networks.append(['list_id', parent.ngfw_data['ip_lists'][x[1]]] if x[0] == 'list_id' else x)
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список IP-адресов {err}. Импортируйте списки IP-адресов и повторите попытку.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список IP-адресов {err}.'
            rule['error'] = 1
    return new_networks


def import_vpn_client_rules(parent, path):
    """Импортируем список клиентских правил VPN"""
    json_file = os.path.join(path, 'config_vpn_client_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт клиентских правил VPN в раздел "VPN/Клиентские правила".')
    error = 0

    if parent.version < 7.1:
        err, result = parent.utm.get_vpn_security_profiles()
    else:
        err, result = parent.utm.get_vpn_client_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
        parent.error = 1
        return
    vpn_security_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_vpn_client_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
        parent.error = 1
        return
    vpn_client_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        try:
            item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль безопасности VPN {err}.'
            item['security_profile_id'] = ""
            item['enabled'] = False
            error = 1

        if parent.version < 7.1:
            if 'xauth_login' not in item:
                item['xauth_login'] = 'vpn'
                item['xauth_password'] = 'vpn'
                if parent.version >= 6:
                    item['protocol'] = 'l2tp'
                    item['subnet1'] = ''
                    item['subnet2'] = ''
            elif parent.version < 6:
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
            parent.stepChanged.emit(f'uGRAY|    Клиентское правило VPN "{item["name"]}" уже существует.')
            if parent.version < 7:
                continue    # Ошибка API update_vpn_client_rule для версий 5 и 6.
            err, result = parent.utm.update_vpn_client_rule(vpn_client_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Клиентское правило VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Клиентское правило VPN "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_vpn_client_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Клиентское правило VPN: "{item["name"]}" не импортировано]')
            else:
                vpn_client_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Клиентское правило VPN "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте клиентских правил VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Клиентские правила VPN импортированы в раздел "VPN/Клиентские правила".')


def import_vpn_server_rules(parent, path):
    """Импортируем список серверных правил VPN"""
    json_file = os.path.join(path, 'config_vpn_server_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверных правил VPN в раздел "VPN/Серверные правила".')
    error = 0

    if parent.version < 7.1:
        err, result = parent.utm.get_vpn_security_profiles()
    else:
        err, result = parent.utm.get_vpn_server_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        parent.error = 1
        return
    vpn_security_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_vpn_networks()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        parent.error = 1
        return
    vpn_networks = {func.get_restricted_name(x['name']): x['id'] for x in result}
    vpn_networks[False] = False

    err, result = parent.utm.get_vpn_server_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
        parent.error = 1
        return
    vpn_server_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item.pop('position_layer', None)
        item['src_zones'] = get_zones_id(parent, 'src', item['src_zones'], item)
        item['source_ips'] = get_ips_id(parent, 'src', item['source_ips'], item)
        if parent.version < 6:
            item.pop('dst_ips', None)
        else:
            item['dst_ips'] = get_ips_id(parent, 'dst', item['dst_ips'], item)
        item['users'] = get_guids_users_and_groups(parent, item)
        try:
            item['security_profile_id'] = vpn_security_profiles[item['security_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности VPN {err}. Загрузите профили безопасности VPN и повторите попытку.')
            parent.stepChanged.emit(f'RED|       Error: Правило "{item["name"]}" не импортировано.')
            error = 1
            continue
        try:
            item['tunnel_id'] = vpn_networks[item['tunnel_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена сеть VPN {err}. Загрузите сети VPN и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найдена сеть VPN {err}.'
            item['tunnel_id'] = False
            item['enabled'] = False
            error = 1
        try:
            item['auth_profile_id'] = parent.ngfw_data['auth_profiles'][item['auth_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль аутентификации {err}. Загрузите профили аутентификации и повторите попытку.')
            item['description'] = f'{item["description"]}\nError: Не найден профиль авторизации {err}.'
            item['auth_profile_id'] = False
            item['enabled'] = False
            error = 1

        if item['name'] in vpn_server_rules:
            parent.stepChanged.emit(f'uGRAY|    Серверное правило VPN "{item["name"]}" уже существует.')
            if parent.version < 6:
                continue    # Ошибка API update_vpn_client_rule для версий 5.
            err, result = parent.utm.update_vpn_server_rule(vpn_server_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Серверное правило VPN "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Серверное правило VPN "{item["name"]}" обновлено.')
        else:
            item['position'] = 'last'
            err, result = parent.utm.add_vpn_server_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Серверное правило VPN "{item["name"]}" не импортировано]')
            else:
                vpn_server_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Серверное правило VPN "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверных правил VPN.')
    else:
        parent.stepChanged.emit('GREEN|    Серверные правила VPN импортированы в раздел "VPN/Серверные правила".')


#------------------------------------------------ Библиотека ------------------------------------------------------------
def import_morphology_lists(parent, path):
    """Импортируем списки морфологии"""
    json_file = os.path.join(path, 'config_morphology_lists.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списков морфологии в раздел "Библиотеки/Морфология".')
    error = 0

    err, result = parent.utm.get_nlists_list('morphology')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
        parent.error = 1
        return
    morphology_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item.pop('list_type_update', None)
            item.pop('schedule', None)
            attributes = []
            attributes.append({'name': 'weight', 'value': item['attributes']['threshold']})
            attributes.append({'name': 'threat_level', 'value': item['attributes']['threat_level']})
            item['attributes'] = attributes

        if item['name'] in morphology_list:
            parent.stepChanged.emit(f'uGRAY|    Список морфологии "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(morphology_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Список морфологии "{item["name"]}"]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|       {result}')
            else:
                parent.stepChanged.emit(f'uGRAY|       Список морфологии "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список морфологии "{item["name"]}" не импортирован]')
                continue
            else:
                morphology_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список морфологии "{item["name"]}" импортирован.')

        if item['list_type_update'] == 'static':
            if content:
                err2, result2 = parent.utm.add_nlist_items(morphology_list[item['name']], content)
                if err2 == 2:
                    parent.stepChanged.emit(f'uGRAY|       {result2}')
                elif err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2}  [Список морфологии "{item["name"]}"]')
                else:
                    parent.stepChanged.emit(f'BLACK|       Содержимое списка морфологии "{item["name"]}" обновлено.')
            else:
                parent.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он пуст.')
        else:
            parent.stepChanged.emit(f'GRAY|       Содержимое списка морфологии "{item["name"]}" не обновлено так как он обновляется удалённо.')

    if parent.version == 7.0:
        parent.stepChanged.emit(f'rNOTE|    В версии 7.0 не импортируется содержимое списков морфологии, если прописаны слова в русском регистре.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков морфологии.')
    else:
        parent.stepChanged.emit('GREEN|    Списки морфологии импортированны в раздел "Библиотеки/Морфология".')


def import_services_list(parent, path):
    """Импортируем список сервисов раздела библиотеки"""
    json_file = os.path.join(path, 'config_services_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
    error = 0
    
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        for value in item['protocols']:
            if parent.version < 7.1:
                value.pop('alg', None)
                if parent.version < 6:
                    value.pop('app_proto', None)
                    if value['port'] in ('110', '995'):
                        value['proto'] = 'tcp'
        
        if item['name'] in parent.ngfw_data['services']:
            parent.stepChanged.emit(f'uGRAY|    Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_service(item)
            if err == 1:
                parent.stepChanged.emit(f'RED|    {result}  [Сервис "{item["name"]}"]')
                error = 1
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.ngfw_data['services'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов!')
    else:
        parent.stepChanged.emit('GREEN|    Список сервисов импортирован в раздел "Библиотеки/Сервисы"')


def import_services_groups(parent, path):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    json_file = os.path.join(path, 'config_services_groups_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп сервисов в раздел "Библиотеки/Группы сервисов".')
    error = 0

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        
        if item['name'] in parent.ngfw_data['service_groups']:
            parent.stepChanged.emit(f'uGRAY|    Группа сервисов "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.ngfw_data['service_groups'][item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Группа сервисов: "{item["name"]}"]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|       {result}')
            else:
                parent.stepChanged.emit(f'uGRAY|       Группа сервисов "{item["name"]}" обновлена.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов "{item["name"]}" не импортирована]')
                continue
            else:
                parent.ngfw_data['service_groups'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" импортирована.')

        if content:
            new_content = []
            for service in content:
                try:
                    service['value'] = parent.ngfw_data['services'][func.get_restricted_name(service['name'])]
                    new_content.append(service)
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|       Error: Не найден сервис "{err}". Загрузите сервисы и повторите попытку.')

            err2, result2 = parent.utm.add_nlist_items(parent.ngfw_data['service_groups'][item['name']], new_content)
            if err2 == 1:
                parent.stepChanged.emit(f'RED|       {result2}  [Группа сервисов "{item["name"]}"]')
                error = 1
            elif err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое группы сервисов "{item["name"]}" импортировано.')
        else:
            parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".')


def import_ip_lists(parent, path):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('BLUE|Импорт списков IP-адресов в раздел "Библиотеки/IP-адреса".')
    error = 0

    if not os.path.isdir(path):
        parent.stepChanged.emit("GRAY|    Нет списков IP-адресов для импорта.")
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit("GRAY|    Нет списков IP-адресов для импорта.")
        return

    # Импортируем все списки IP-адресов без содержимого (пустые).
    parent.stepChanged.emit(f'LBLUE|    Импортируем списки IP-адресов без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        if parent.version < 6:
            data['attributes'] = [{'name': 'threat_level', 'value': data['attributes']['threat_level']}]
            data.pop('list_type_update', None)
            data.pop('schedule', None)
        if data['name'] in parent.ngfw_data['ip_lists']:
            parent.stepChanged.emit(f'uGRAY|    Список IP-адресов "{data["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.ngfw_data['ip_lists'][data['name']], data)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Список IP-адресов "{data["name"]}"]')
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|       Список IP-адресов "{data["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_nlist(data)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирован]')
            else:
                parent.ngfw_data['ip_lists'][data['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')

    # Добавляем содержимое в уже добавленные списки IP-адресов.
    parent.stepChanged.emit(f'LBLUE|    Импортируем содержимое списков IP-адресов.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        try:
            list_id = parent.ngfw_data['ip_lists'][data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Ошибка! Нет IP-листа "{data["name"]}" в списках IP-адресов NGFW.')
            parent.stepChanged.emit(f'RED|    Ошибка! Содержимое не добавлено в список IP-адресов "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            new_content = []
            for item in data['content']:
                if 'list' in item:
                    if parent.version >= 7:
                        try:
                            item['list'] = parent.ngfw_data['ip_lists'][item['list']]
                            new_content.append(item)
                        except KeyError:
                            parent.stepChanged.emit(f'RED|    Ошибка! Нет IP-листа "{item["list"]}" в списках IP-адресов NGFW.')
                            parent.stepChanged.emit(f'RED|    Ошибка! Список "{item["list"]}" не добавлен в список IP-адресов "{data["name"]}".')
                            error = 1
                    else:
                        parent.stepChanged.emit(f'GRAY|    В список "{data["name"]}" не добавлен "{item["list"]}". Данная версия не поддерживает содержимое в виде списков IP-адресов.')
                else:
                    new_content.append(item)

            err2, result2 = parent.utm.add_nlist_items(list_id, new_content)
            if err2 == 1:
                parent.stepChanged.emit(f'RED|    {result2}  [Список IP-адресов "{data["name"]}"]')
                error = 1
            elif err2 == 2:
                parent.stepChanged.emit(f'GRAY|    {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка IP-адресов "{data["name"]}" импортировано.')
        else:
            parent.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".')


def import_useragent_lists(parent, path):
    """Импортируем списки Useragent браузеров"""
    json_file = os.path.join(path, 'config_useragents_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Useragent браузеров" в раздел "Библиотеки/Useragent браузеров".')
    error = 0
    err, result = parent.utm.get_nlists_list('useragent')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
        parent.error = 1
        return
    useragent_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        if item['name'] in useragent_list:
            parent.stepChanged.emit(f'uGRAY|    Список Useragent "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(useragent_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Список Useragent {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|       {result}')
            else:
                parent.stepChanged.emit(f'BLACK|       Список Useragent "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Useragent "{item["name"]}" не импортирован]')
                continue
            else:
                useragent_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список Useragent "{item["name"]}" импортирован.')

        if content:
            err2, result2 = parent.utm.add_nlist_items(useragent_list[item['name']], content)
            if err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            elif err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Список Useragent: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое списка Useragent "{item["name"]}" импортировано.')
        else:
            parent.stepChanged.emit(f'GRAY|       Список Useragent "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков Useragent браузеров.')
    else:
        parent.stepChanged.emit('GREEN|    Список "Useragent браузеров" импортирован в раздел "Библиотеки/Useragent браузеров".')


def import_mime_lists(parent, path):
    """Импортируем списки Типов контента"""
    json_file = os.path.join(path, 'config_mime_types.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Типы контента" в раздел "Библиотеки/Типы контента".')
    error = 0
    err, result = parent.utm.get_nlists_list('mime')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mime_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        if item['name'] in mime_list:
            parent.stepChanged.emit(f'GRAY|    Список Типов контента "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(mime_list[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список Типов контента: "{item["name"]}"]')
                continue
            else:
                mime_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список Типов контента "{item["name"]}" импортирован.')

        if content:
            err2, result2 = parent.utm.add_nlist_items(mime_list[item['name']], content)
            if err2 == 2:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            elif err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Список Типов контента: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое списка Типов контента "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Список Типов контента "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков "Типы контента".')
    else:
        parent.stepChanged.emit('GREEN|    Списки "Типы контента" импортированы в раздел "Библиотеки/Типы контента".')


def import_url_lists(parent, path):
    """Импортируем списки URL"""
    parent.stepChanged.emit('BLUE|Импорт списков URL в раздел "Библиотеки/Списки URL".')
    error = 0

    if not os.path.isdir(path):
        parent.stepChanged.emit("GRAY|    Нет списков URL для импорта.")
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit("GRAY|    Нет списков URL для импорта.")
        return

    # Импортируем все списки URL без содержимого (пустые).
    parent.stepChanged.emit(f'LBLUE|    Импортируем списки URL без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        if parent.version < 6:
            data['attributes'] = [{'name': 'threat_level', 'value': 3}]
            data.pop('list_type_update', None)
            data.pop('schedule', None)
        elif parent.version < 7.1:
            data['attributes'] = {}
        else:
            if not data['attributes'] or 'threat_level' in data['attributes']:
                data['attributes'] = {'list_compile_type': 'case_insensitive'}

        if data['name'] in parent.ngfw_data['url_lists']:
            parent.stepChanged.emit(f'GRAY|    Список URL "{data["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.ngfw_data['url_lists'][data['name']], data)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список URL: "{data["name"]}"]')
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(data)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Список URL: "{data["name"]}" не импортирован]')
            else:
                parent.ngfw_data['url_lists'][data['name']] = result
                parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

    # Добавляем содержимое в уже добавленные списки URL.
    parent.stepChanged.emit(f'LBLUE|    Импортируем содержимое списков URL.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file, mode=1)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        try:
            list_id = parent.ngfw_data['url_lists'][data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|    Ошибка! Нет листа URL "{data["name"]}" в списках URL листов NGFW.')
            parent.stepChanged.emit(f'RED|    Ошибка! Содержимое не добавлено в список URL "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            err2, result2 = parent.utm.add_nlist_items(list_id, data['content'])
            if err2 == 1:
                parent.stepChanged.emit(f'RED|    {result2}  [Список URL: "{data["name"]}" - содержимое не импортировано]')
                error = 1
            elif err2 == 2:
                parent.stepChanged.emit(f'GRAY|    {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка URL "{data["name"]}" обновлено. Added {result2} record.')
        else:
            parent.stepChanged.emit(f'GRAY|    Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.')
    else:
        parent.stepChanged.emit('GREEN|    Списки URL импортированы в раздел "Библиотеки/Списки URL".')


def import_time_restricted_lists(parent, path):
    """Импортируем содержимое календарей"""
    json_file = os.path.join(path, 'config_calendars.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
    error = 0

    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        if item['name'] in parent.ngfw_data['calendars']:
            parent.stepChanged.emit(f'GRAY|    Календарь "{item["name"]}" уже существует.')
            err, result = parent.utm.update_nlist(parent.ngfw_data['calendars'][item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Календарь: {item["name"]}]')
                continue
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_nlist(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Календарь: "{item["name"]}" не импортирован]')
                continue
            else:
                parent.ngfw_data['calendars'][item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

        if parent.version < 6:
            parent.stepChanged.emit(f'GRAY|       На версию 5 невозможно импортировать сожержимое календарей. Добавьте содержимое вручную.')
            continue
        if content:
            if parent.utm.version_hight >= 7 and parent.utm.version_midle >= 1:
                for value in content:
                    err2, result2 = parent.utm.add_nlist_item(parent.ngfw_data['calendars'][item['name']], value)
                    if err2 == 2:
                        parent.stepChanged.emit(f'GRAY|       Элемент "{value["name"]}" уже существует в календаре "{itm["name"]}".')
                    elif err2 == 1:
                        error = 1
                        parent.stepChanged.emit(f'RED|       {result2}  [Календарь: "{item["name"]}"]')
                    else:
                        parent.stepChanged.emit(f'BLACK|       Элемент "{value["name"]}" календаря "{item["name"]}" добавлен.')
            else:
                err2, result2 = parent.utm.add_nlist_items(parent.ngfw_data['calendars'][item['name']], content)
                if err2 == 2:
                    parent.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2}  [Календарь: "{item["name"]}"]')
                else:
                    parent.stepChanged.emit(f'BLACK|       Содержимое календаря "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Календари" импортирован в раздел "Библиотеки/Календари".')


def import_shaper_list(parent, path):
    """Импортируем список Полос пропускания раздела библиотеки"""
    json_file = os.path.join(path, 'config_shaper_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
    error = 0

    err, result = parent.utm.get_shaper_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
        parent.error = 1
        return
    shaper_list = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in shaper_list:
            parent.stepChanged.emit(f'GRAY|    Полоса пропускания "{item["name"]}" уже существует.')
            err, result = parent.utm.update_shaper(shaper_list[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: {item["name"]} не обновлена]')
            else:
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_shaper(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: "{item["name"]}" не импортирована]')
            else:
                shaper_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Полосы пропускания" импортирован в раздел "Библиотеки/Полосы пропускания".')


def import_scada_profiles(parent, path):
    """Импортируем список профилей АСУ ТП"""
    json_file = os.path.join(path, 'config_scada_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка профилей АСУ ТП в раздел "Библиотеки/Профили АСУ ТП".')
    error = 0

    err, result = parent.utm.get_scada_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Профили АСУ ТП".')
        parent.error = 1
        return
    scada_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if parent.version < 6:
            new_units = []
            for unit in item['units']:
                if unit['protocol'] != 'opcua':
                    new_units.append(unit)
            item['units'] = new_units

        if item['name'] in scada_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль АСУ ТП "{item["name"]}" уже существует.')
            err, result = parent.utm.update_scada(scada_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль АСУ ТП: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль АСУ ТП "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_scada(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль АСУ ТП: "{item["name"]}"]')
            else:
                scada_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль АСУ ТП "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Профили АСУ ТП".')
    else:
        parent.stepChanged.emit('GREEN|    Список профилей АСУ ТП импортирован в раздел "Библиотеки/Профили АСУ ТП".')


def import_templates_list(parent, path):
    """
    Импортируем список шаблонов страниц.
    После создания шаблона, он инициализируется страницей HTML по умолчанию для данного типа шаблона.
    """
    json_file = os.path.join(path, 'config_templates_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка шаблонов страниц в раздел "Библиотеки/Шаблоны страниц".')
    error = 0
    html_files = os.listdir(path)

    if not parent.list_templates:
        if get_templates_list(parent):    # Устанавливаем атрибут parent.list_templates
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
            return

    for item in data:
        if item['name'] in parent.list_templates:
            parent.stepChanged.emit(f'GRAY|    Шаблон страницы "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template(parent.list_templates[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Шаблон страницы: "{item["name"]}" не импортирован]')
                continue
            else:
                parent.list_templates[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Шаблон страницы "{item["name"]}" импортирован.')

        if f"{item['name']}.html" in html_files:
            with open(os.path.join(path, f'{item["name"]}.html'), "br") as fh:
                file_data = fh.read()
            err2, result2 = parent.utm.set_template_data(parent.list_templates[item['name']], file_data)
            if err2:
                parent.stepChanged.emit(f'RED|       {result2} [Страница "{item["name"]}.html" не импортирована]')
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|       Страница "{item["name"]}.html" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка шаблонов страниц.')
    else:
        parent.stepChanged.emit('GREEN|    Список шаблонов страниц импортирован в раздел "Библиотеки/Шаблоны страниц".')


def import_url_categories(parent, path):
    """Импортируем группы URL категорий с содержимым на UTM"""
    json_file = os.path.join(path, 'config_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Категории URL".')
    error = 0

    for item in data:
        if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                'Recommended for morphology checking', 'Recommended for virus check']:
            content = item.pop('content')
            item.pop('last_update', None)
            item.pop('guid', None)
            item['name'] = func.get_restricted_name(item['name'])
            if parent.version < 6:
                item['attributes'] = []
                item.pop('list_type_update', None)
                item.pop('schedule', None)
            if item['name'] in parent.ngfw_data['url_categorygroups']:
                parent.stepChanged.emit(f'GRAY|    Группа URL категорий "{item["name"]}" уже существует.')
                err, result = parent.utm.update_nlist(parent.ngfw_data['url_categorygroups'][item['name']], item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий: {item["name"]}]')
                    continue
                else:
                    parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" updated.')
            else:
                err, result = parent.utm.add_nlist(item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий: "{item["name"]}" не импортирована]')
                    continue
                else:
                    parent.ngfw_data['url_categorygroups'][item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')
                
            if parent.version < 6:
                parent.stepChanged.emit(f'GRAY|       На версию 5 невозможно импортировать сожержимое URL категорий. Добавьте содержимое вручную.')
                continue
            if content:
                err2, result2 = parent.utm.add_nlist_items(parent.ngfw_data['url_categorygroups'][item['name']], content)
                if err2 == 2:
                    parent.stepChanged.emit(f'GRAY|       {result2}')
                elif err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2}  [Список: "{item["name"]}"]')
                else:
                    parent.stepChanged.emit(f'BLACK|       Содержимое списка "{item["name"]}" обновлено.')
            else:
                parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте URL категорий.')
    else:
        parent.stepChanged.emit('GREEN|    Категории URL категорий импортированы в раздел "Библиотеки/Категории URL".')


def import_custom_url_category(parent, path):
    """Импортируем изменённые категории URL"""
    json_file = os.path.join(path, 'custom_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт категорий URL раздела "Библиотеки/Изменённые категории URL".')
    error = 0

    err, result = parent.utm.get_custom_url_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
        parent.error = 1
        return
    custom_url = {x['name']: x['id'] for x in result}

    for item in data:
        try:
            item['categories'] = [parent.ngfw_data['url_categories'][x] for x in item['categories']]
        except KeyError as keyerr:
            parent.stepChanged.emit(f'RED|    Error: В правиле "{item["name"]}" обнаружена несуществующая категория {keyerr}. Правило  не добавлено.')
            continue
        if item['name'] in custom_url:
            parent.stepChanged.emit(f'GRAY|    URL категория "{item["name"]}" уже существует.')
            err, result = parent.utm.update_custom_url(custom_url[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    URL категория "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_custom_url(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [URL категория: "{item["name"]}" не импортирована]')
            else:
                custom_url[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Изменённая категория URL "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте изменённых категорий URL.')
    else:
        parent.stepChanged.emit('GREEN|    Изменённые категории URL категорий импортированы в раздел "Библиотеки/Изменённые категории URL".')


def import_application_signature(parent, path):
    """Импортируем список "Приложения" на UTM для версии 7.1 и выше"""
    json_file = os.path.join(path, 'config_applications.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт пользовательских приложений в раздел "Библиотеки/Приложения".')
    error = 0

    err, result = parent.utm.get_version71_apps(query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
        parent.error = 1
        return
    apps = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('signature_id', None)

        new_l7categories = []
        for category in item['l7categories']:
            try:
                new_l7categories.append(parent.ngfw_data['l7_categories'][category])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Категория "{err}" не существует [Правило "{item["name"]}"]. Категория не добавлена.')
                error = 1
        item['l7categories'] = new_l7categories

        if item['name'] in apps:
            parent.stepChanged.emit(f'GRAY|    Приложение "{item["name"]}" уже существует.')
            err, result = parent.utm.update_version71_app(apps[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Приложение: {item["name"]}]')
            elif err == 2:
                parent.stepChanged.emit(f'GRAY|       {result}')
            else:
                parent.stepChanged.emit(f'BLACK|       Приложение "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_version71_app(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Приложение: "{item["name"]}" не импортировано]')
            else:
                apps[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Приложение "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Пользовательские приложения импортированы в раздел "Библиотеки/Приложения".')


def import_app_profiles(parent, path):
    """Импортируем профили приложений. Только для версии 7.1 и выше."""
    json_file = os.path.join(path, 'config_app_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей приложений раздела "Библиотеки/Профили приложений".')
    error = 0

    err, result = parent.utm.get_l7_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
        parent.error = 1
        return
    l7profiles = {x['name']: x['id'] for x in result}

    for item in data:
        new_overrides = []
        for app in item['overrides']:
            try:
                app['id'] = parent.ngfw_data['l7_apps'][app['id']]
                new_overrides.append(app)
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error: Не найдено приложение "{err}" [Правило: "{item["name"]}"].')
                error = 1
        item['overrides'] = new_overrides

        if item['name'] in l7profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль приложений "{item["name"]}" уже существует.')
            err, result = parent.utm.update_l7_profile(l7profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль приложений: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль приложений "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_l7_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль приложений: "{item["name"]}" не импортирован]')
            else:
                l7profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль приложений "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Профили приложений импортированы в раздел "Библиотеки/Профили приложений".')


def import_application_groups(parent, path):
    """Импортируем группы приложений."""
    json_file = os.path.join(path, 'config_application_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп приложений раздела "Библиотеки/Группы приложений".')
    error = 0

    if parent.version >= 7.1:
        parent.stepChanged.emit('NOTE|    Загрузка списка приложений с NGFW, это может быть долго...')
        err, result = parent.utm.get_version71_apps()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
            parent.error = 1
            return
        apps = {x['name']: x['signature_id'] for x in result}
    else:
        apps = parent.ngfw_data['l7_apps']

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        err = execute_add_update_nlist(parent, parent.ngfw_data['application_groups'], item, 'Группа приложений')
        if err:
            error = 1
            continue

        if content:
            new_content = []
            for app in content:
                if 'name' not in app:     # Это бывает при некорректном добавлении приложения через API
                    parent.stepChanged.emit(f'RED|       Error: Приложение "{app}" не добавлено так как не содержит имя. [Группа приложений "{item["name"]}"].')
                    error = 1
                    continue
                try:
                    signature_id = apps[app['name']]
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|       Error: Не найдено приложение "{app["name"]}" [Группа приложений "{item["name"]}"]. Приложение не импортировано.')
                    error = 1
                    continue
                new_content.append({'value': signature_id})
            content = new_content

            err = execute_add_nlist_items(parent, parent.ngfw_data['application_groups'][item['name']], item['name'], content)
            if err:
                error = 1
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Группы приложений импортированы в раздел "Библиотеки/Группы приложений".')


def import_email_groups(parent, path):
    """Импортируем группы почтовых адресов."""
    json_file = os.path.join(path, 'config_email_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп почтовых адресов раздела "Библиотеки/Почтовые адреса".')
    error = 0

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
        parent.error = 1
        return
    emailgroups = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        err = execute_add_update_nlist(parent, emailgroups, item, 'Группа почтовых адресов')
        if err:
            error = 1
            continue

        if content:
            err = execute_add_nlist_items(parent, emailgroups[item['name']], item['name'], content)
            if err:
                error = 1
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп почтовых адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Группы почтовых адресов импортированы в раздел "Библиотеки/Почтовые адреса".')


def import_phone_groups(parent, path):
    """Импортируем группы телефонных номеров."""
    json_file = os.path.join(path, 'config_phone_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп телефонных номеров раздела "Библиотеки/Номера телефонов".')
    error = 0

    err, result = parent.utm.get_nlist_list('phonegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
        parent.error = 1
        return
    phonegroups = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        if parent.version < 6:
            item['attributes'] = []
            item.pop('list_type_update', None)
            item.pop('schedule', None)

        err = execute_add_update_nlist(parent, phonegroups, item, 'Группа телефонных номеров')
        if err:
            error = 1
            continue

        if content:
            err = execute_add_nlist_items(parent, phonegroups[item['name']], item['name'], content)
            if err:
                error = 1
        else:
            parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп телефонных номеров.')
    else:
        parent.stepChanged.emit('GREEN|    Группы телефонных номеров импортированы в раздел "Библиотеки/Номера телефонов".')


def import_custom_idps_signature(parent, path):
    """Импортируем пользовательские сигнатуры СОВ. Только для версии 7.1 и выше"""
    json_file = os.path.join(path, 'custom_idps_signatures.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт пользовательских сигнатур СОВ в раздел "Библиотеки/Сигнатуры СОВ".')
    error = 0

    err, result = parent.utm.get_idps_signatures_list(query={'query': 'owner = You'})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    signatures = {x['msg']: x['id'] for x in result}

    for item in data:
        if item['msg'] in signatures:
            parent.stepChanged.emit(f'GRAY|    Сигнатура СОВ "{item["msg"]}" уже существует.')
            err, result = parent.utm.update_idps_signature(signatures[item['msg']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сигнатура СОВ: {item["msg"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|       Сигнатура СОВ "{item["msg"]}" updated.')
        else:
            err, result = parent.utm.add_idps_signature(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сигнатура СОВ: "{item["msg"]}" не импортирована]')
                continue
            else:
                signatures[item['msg']] = result
                parent.stepChanged.emit(f'BLACK|    Сигнатура СОВ "{item["msg"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте пользовательских сигнатур СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Пользовательские сигнатуры СОВ импортированы в раздел "Библиотеки/Сигнатуры СОВ".')


def import_idps_profiles(parent, path):
    """Импортируем профили СОВ"""
    json_file = os.path.join(path, 'config_idps_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей СОВ в раздел "Библиотеки/Профили СОВ".')
    error = 0

    if parent.version < 6:
        parent.stepChanged.emit('RED|    Импорт профилей СОВ на версию 5 не поддерживается.')
        error = 1
    elif parent.version < 7.1:
        err, result = parent.utm.get_nlist_list('ipspolicy')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
            parent.error = 1
            return
        idps = {func.get_restricted_name(x['name']): x['id'] for x in result}

        for item in data:
            if 'filters' in item:
                parent.stepChanged.emit('RED|    Импорт профилей СОВ версий 7.1 и выше на более старые версии не поддерживается.')
                error = 1
                break

            item['name'] = func.get_restricted_name(item['name'])
            content = item.pop('content')
            item.pop('last_update', None)

            err = execute_add_update_nlist(parent, idps, item, 'Профиль СОВ')
            if err:
                error = 1
                continue
            if content:
                new_content = []
                for signature in content:
                    if 'value' not in signature:
                        parent.stepChanged.emit(f'bRED|    Сигнатура "{signature["msg"]}" пропущена так как формат не соответствует целевой системе.')
                        error = 1
                        continue
                    new_content.append({'value': signature['value']})
                content = new_content

                err = execute_add_nlist_items(parent, idps[item['name']], item['name'], content)
                if err:
                    error = 1
            else:
                parent.stepChanged.emit(f'GRAY|       Список "{item["name"]}" пуст.')
    else:
        err, result = parent.utm.get_idps_profiles_list()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
            parent.error = 1
            return
        profiles = {x['name']: x['id'] for x in result}

        err, result = parent.utm.get_idps_signatures_list(query={'query': 'owner = You'})
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
            parent.error = 1
            return
        custom_idps = {x['msg']: x['id'] for x in result}

        for item in data:
            if 'filters' not in item:
                parent.stepChanged.emit('RED|    Импорт профилей СОВ старых версий не поддерживается для версий 7.1 и выше.')
                error = 1
                break
            # Исключаем отсутствующие сигнатуры. Получаем ID сигнатур по имени так как ID может не совпадать.
            new_overrides = []
            for signature in item['overrides']:
                try:
                    if 1000000 < signature['signature_id'] < 1099999:
                        signature['id'] = custom_idps[signature['msg']]
#                    signature.pop('signature_id', None)
#                    signature.pop('msg', None)
                    new_overrides.append(signature)
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error: Не найдена сигнатура "{err}" [Профиль СОВ "{item["name"]}"].')
                    error = 1
            item['overrides'] = new_overrides

            if item['name'] in profiles:
                parent.stepChanged.emit(f'GRAY|    Профиль СОВ "{item["name"]}" уже существует.')
                err, result = parent.utm.update_idps_profile(profiles[item['name']], item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result}  [Профиль СОВ: {item["name"]}]')
                else:
                    parent.stepChanged.emit(f'BLACK|       Профиль СОВ "{item["name"]}" updated.')
            else:
                err, result = parent.utm.add_idps_profile(item)
                if err:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}  [Профиль СОВ: "{item["name"]}" не импортирован]')
                else:
                    profiles[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Профиль СОВ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей СОВ.')
    else:
        parent.stepChanged.emit('GREEN|    Профили СОВ импортированы в раздел "Библиотеки/Профили СОВ".')


def import_notification_profiles(parent, path):
    """Импортируем список профилей оповещения"""
    json_file = os.path.join(path, 'config_notification_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
    error = 0

    if not parent.notification_profiles:
        if get_notification_profiles_list(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in parent.notification_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль оповещения "{item["name"]}" уже существует.')
            err, result = parent.utm.update_notification_profile(parent.notification_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль оповещения: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль оповещения "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_notification_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: "{item["name"]}" не импортирован]')
                continue
            else:
                parent.notification_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
                
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Профили оповещений импортированы в раздел "Библиотеки/Профили оповещений".')


def import_netflow_profiles(parent, path):
    """Импортируем список профилей netflow"""
    json_file = os.path.join(path, 'config_netflow_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей netflow в раздел "Библиотеки/Профили netflow".')
    error = 0

    err, result = parent.utm.get_netflow_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
        parent.error = 1
        return
    profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль netflow "{item["name"]}" уже существует.')
            err, result = parent.utm.update_netflow_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль netflow: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль netflow "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_netflow_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль netflow: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль netflow "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей netflow.')
    else:
        parent.stepChanged.emit('GREEN|    Профили netflow импортированы в раздел "Библиотеки/Профили netflow".')


def import_lldp_profiles(parent, path):
    """Импортируем список профилей LLDP"""
    json_file = os.path.join(path, 'config_lldp_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей LLDP в раздел "Библиотеки/Профили LLDP".')
    error = 0

    err, result = parent.utm.get_lldp_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
        parent.error = 1
        return
    profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль LLDP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_lldp_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль LLDP: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль LLDP "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_lldp_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль LLDP: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль LLDP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей LLDP.')
    else:
        parent.stepChanged.emit('GREEN|    Профили LLDP импортированы в раздел "Библиотеки/Профили LLDP".')


def import_ssl_profiles(parent, path):
    """Импортируем список профилей SSL"""
    json_file = os.path.join(path, 'config_ssl_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей SSL в раздел "Библиотеки/Профили SSL".')
    error = 0

    for item in data:
        if parent.version < 7.1:
            item.pop('supported_groups', None)
        else:
            if 'supported_groups' not in item:
                item['supported_groups'] = []
        item['name'] = func.get_restricted_name(item['name'])
        ssl_profiles = parent.ngfw_data['ssl_profiles']
        if item['name'] in ssl_profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_ssl_profile(ssl_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль SSL: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_ssl_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль SSL: "{item["name"]}" не импортирован]')
            else:
                ssl_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Профили SSL импортированы в раздел "Библиотеки/Профили SSL".')


def import_ssl_forward_profiles(parent, path):
    """Импортируем профили пересылки SSL"""
    json_file = os.path.join(path, 'config_ssl_forward_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей пересылки SSL в раздел "Библиотеки/Профили пересылки SSL".')
    error = 0

    err, result = parent.utm.get_ssl_forward_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
        parent.error = 1
        return
    profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль пересылки SSL "{item["name"]}" уже существует.')
            err, result = parent.utm.update_ssl_forward_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль пересылки SSL: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль пересылки SSL "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_ssl_forward_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль пересылки SSL: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль пересылки SSL "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей пересылки SSL.')
    else:
        parent.stepChanged.emit('GREEN|    Профили пересылки SSL импортированы в раздел "Библиотеки/Профили пересылки SSL".')


def import_hip_objects(parent, path):
    """Импортируем HIP объекты"""
    json_file = os.path.join(path, 'config_hip_objects.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт HIP объектов в раздел "Библиотеки/HIP объекты".')
    error = 0

    if parent.utm.float_version >= 8.0:
        parent.stepChanged.emit(f'ORANGE|    Импорт HIP объектов не доступен в версии {parent.version}.')
        return

    err, result = parent.utm.get_hip_objects_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    HIP объект "{item["name"]}" уже существует.')
            err, result = parent.utm.update_hip_object(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [HIP объект: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       HIP объект "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_hip_object(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP объект: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    HIP объект "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP объектов.')
    else:
        parent.stepChanged.emit('GREEN|    HIP объекты импортированы в раздел "Библиотеки/HIP объекты".')


def import_hip_profiles(parent, path):
    """Импортируем HIP профили"""
    json_file = os.path.join(path, 'config_hip_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт HIP профилей в раздел "Библиотеки/HIP профили".')
    error = 0

    if parent.utm.float_version >= 8.0:
        parent.stepChanged.emit(f'ORANGE|    Импорт HIP профилей не доступен в версии {parent.version}.')
        return

    err, result = parent.utm.get_hip_objects_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
        parent.error = 1
        return
    hip_objects = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_hip_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        for obj in item['hip_objects']:
            obj['id'] = hip_objects[obj['id']]
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    HIP профиль "{item["name"]}" уже существует.')
            err, result = parent.utm.update_hip_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [HIP профиль: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       HIP профиль "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_hip_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [HIP профиль: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    HIP профиль "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте HIP профилей.')
    else:
        parent.stepChanged.emit('GREEN|    HIP профили импортированы в раздел "Библиотеки/HIP профили".')


def import_bfd_profiles(parent, path):
    """Импортируем профили BFD"""
    json_file = os.path.join(path, 'config_bfd_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей BFD в раздел "Библиотеки/Профили BFD".')
    error = 0

    err, result = parent.utm.get_bfd_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль BFD "{item["name"]}" уже существует.')
            err, result = parent.utm.update_bfd_profile(profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль BFD: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Профиль BFD "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_bfd_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль BFD: "{item["name"]}" не импортирован]')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль BFD "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей BFD.')
    else:
        parent.stepChanged.emit('GREEN|    Профили BFD импортированы в раздел "Библиотеки/Профили BFD".')


def import_useridagent_syslog_filters(parent, path):
    """Импортируем syslog фильтры UserID агента"""
    json_file = os.path.join(path, 'config_useridagent_syslog_filters.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт syslog фильтров UserID агента в раздел "Библиотеки/Syslog фильтры UserID агента".')
    error = 0
    err, result = parent.utm.get_useridagent_filters_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
        parent.error = 1
        return
    filters = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in filters:
            parent.stepChanged.emit(f'GRAY|    Фильтр "{item["name"]}" уже существует.')
            err, result = parent.utm.update_useridagent_filter(filters[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Фильтр: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Фильтр "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_useridagent_filter(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Фильтр: "{item["name"]}" не импортирован]')
            else:
                filters[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Фильтр "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте syslog фильтров UserID агента.')
    else:
        parent.stepChanged.emit('GREEN|    Syslog фильтры UserID агента импортированы в раздел "Библиотеки/Syslog фильтры UserID агента".')


def import_scenarios(parent, path):
    """Импортируем список сценариев"""
    json_file = os.path.join(path, 'config_scenarios.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка сценариев в раздел "Библиотеки/Сценарии".')
    error = 0

    if not parent.scenarios_rules:
        if get_scenarios_rules(parent):     # Устанавливаем атрибут parent.scenarios_rules
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
            return

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        new_conditions = []
        for condition in item['conditions']:
            if condition['kind'] == 'application':
                condition['apps'] = get_apps(parent, condition['apps'], item['name'])
            elif condition['kind'] == 'mime_types':
                try:
                    condition['content_types'] = [parent.ngfw_data['mime'][x] for x in condition['content_types']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Не найден тип контента "{err}". Загрузите типы контента и повторите попытку.')
                    condition['content_types'] = []
            elif condition['kind'] == 'url_category':
                condition['url_categories'] = get_url_categories_id(parent, condition['url_categories'], item['name'])
            elif condition['kind'] == 'health_check':
                if parent.version < 6:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Условие "Проверка состояния" не поддерживается в версии 5.')
                    continue
                elif parent.version == 7.0:
                    parent.stepChanged.emit(f'bRED|    Error! Сценарий "{item["name"]}": Условие "Проверка состояния" нельзя импортировать в версию 7.0.')
                    continue
            new_conditions.append(condition)
        item['conditions'] = new_conditions

        if item['name'] in parent.scenarios_rules:
            parent.stepChanged.emit(f'GRAY|    Сценарий "{item["name"]}" уже существует.')
            err, result = parent.utm.update_scenarios_rule(parent.scenarios_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Сценарий: {item["name"]}]')
                continue
            else:
                parent.stepChanged.emit(f'BLACK|       Сценарий "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_scenarios_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Сценарий: "{item["name"]}" не импортирован]')
                continue
            else:
                parent.scenarios_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Сценарий "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка сценариев.')
    else:
        parent.stepChanged.emit('GREEN|    Список сценариев импортирован в раздел "Библиотеки/Сценарии".')


#--------------------------------------------------- Оповещения ---------------------------------------------------------
def import_notification_alert_rules(parent, path):
    """Импортируем список правил оповещений"""
    json_file = os.path.join(path, 'config_alert_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт правил оповещений в раздел "Диагностика и мониторинг/Оповещения/Правила оповещений".')
    error = 0

    if not parent.notification_profiles:
        if get_notification_profiles_list(parent):      # Устанавливаем атрибут parent.notification_profiles
            parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
            return

    err, result = parent.utm.get_nlist_list('emailgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    email_group = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_nlist_list('phonegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    phone_group = {func.get_restricted_name(x['name']): x['id'] for x in result}

    err, result = parent.utm.get_notification_alert_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
        parent.error = 1
        return
    alert_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        try:
            item['notification_profile_id'] = parent.notification_profiles[item['notification_profile_id']]
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль оповещений {err}. Импортируйте профили оповещений и повторите попытку.')
            parent.stepChanged.emit(f'RED|       Error: Правило "{item["name"]}" не импортировано.')
            error = 1
            continue

        new_emails = []
        for x in item['emails']:
            try:
                new_emails.append(['list_id', email_group[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа почтовых адресов {err}. Загрузите почтовые адреса и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа почтовых адресов {err}.'
                item['enabled'] = False
                error = 1
        item['emails'] = new_emails

        new_phones = []
        for x in item['phones']:
            try:
                new_phones.append(['list_id', phone_group[x[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найдена группа телефонных номеров {err}. Загрузите номера телефонов и повторите попытку.')
                item['description'] = f'{item["description"]}\nError: Не найдена группа телефонных номеров {err}.'
                item['enabled'] = False
                error = 1
        item['phones'] = new_phones

        if item['name'] in alert_rules:
            parent.stepChanged.emit(f'uGRAY|    Правило оповещения "{item["name"]}" уже существует.')
            err, result = parent.utm.update_notification_alert_rule(alert_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило оповещения "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило оповещения "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_notification_alert_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило оповещения: "{item["name"]}" не импортировано]')
            else:
                alert_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило оповещения "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Правила оповещений импортированы в раздел "Диагностика и мониторинг/Оповещения/Правила оповещений".')


def import_snmp_security_profiles(parent, path):
    """Импортируем профили безопасности SNMP"""
    json_file = os.path.join(path, 'config_snmp_profiles.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей безопасности SNMP в раздел "Диагностика и мониторинг/Оповещения/Профили безопасности SNMP".')
    error = 0

    err, result = parent.utm.get_snmp_security_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
        parent.error = 1
        return
    snmp_security_profiles = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] in snmp_security_profiles:
            parent.stepChanged.emit(f'uGRAY|    Профиль безопасности SNMP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_snmp_security_profile(snmp_security_profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Профиль безопасности SNMP "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Профиль безопасности SNMP "{item["name"]}" обновлён.')
        else:
            err, result = parent.utm.add_snmp_security_profile(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль безопасности SNMP "{item["name"]}" не импортирован]')
            else:
                snmp_security_profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль безопасности SNMP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей безопасности SNMP.')
    else:
        parent.stepChanged.emit('GREEN|    Профили безопасности SNMP импортированы в раздел "Диагностика и мониторинг/Оповещения/Профили безопасности SNMP".')


def import_snmp_rules(parent, path):
    """Импортируем список правил SNMP"""
    json_file = os.path.join(path, 'config_snmp_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка правил SNMP в раздел "Диагностика и мониторинг/Оповещения/SNMP".')
    error = 0

    if parent.version >= 7.1:
        err, result = parent.utm.get_snmp_security_profiles()
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        snmp_security_profiles = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_snmp_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    snmp_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if parent.version >= 7.1:
            if 'snmp_security_profile' in item:
                if item['snmp_security_profile']:
                    try:
                        item['snmp_security_profile'] = snmp_security_profiles[item['snmp_security_profile']]
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{item["name"]}"]. Не найден профиль безопасности SNMP {err}. Импортируйте профили безопасности SNMP и повторите попытку.')
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
            parent.stepChanged.emit(f'uGRAY|    Правило SNMP "{item["name"]}" уже существует.')
            err, result = parent.utm.update_snmp_rule(snmp_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило SNMP "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'uGRAY|       Правило SNMP "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_snmp_rule(item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило SNMP "{item["name"]}" не импортировано]')
            else:
                snmp_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило SNMP "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил SNMP.')
    else:
        parent.stepChanged.emit('GREEN|    Правила SNMP импортированы в раздел "Диагностика и мониторинг/Оповещения/SNMP".')


def import_snmp_settings(parent, path):
    """Импортируем параметры SNMP. Для версии 7.1 и выше."""
    parent.stepChanged.emit('BLUE|Импорт параметров SNMP в раздел "Диагностика и мониторинг/Оповещения/Параметры SNMP".')

    import_snmp_engine(parent, path)
    import_snmp_sys_name(parent, path)
    import_snmp_sys_location(parent, path)
    import_snmp_sys_description(parent, path)

    parent.stepChanged.emit('GREEN|    Параметры SNMP импортированы  в раздел "Диагностика и мониторинг/Оповещения/Параметры SNMP".')

def import_snmp_engine(parent, path):
    json_file = os.path.join(path, 'config_snmp_engine.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.set_snmp_engine(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте SNMP Engine ID.')
    else:
        parent.stepChanged.emit('BLACK|    SNMP Engine ID импортирован.')

def import_snmp_sys_name(parent, path):
    json_file = os.path.join(path, 'config_snmp_sysname.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.set_snmp_sysname(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте значения SNMP SysName.')
    else:
        parent.stepChanged.emit('BLACK|    Значение SNMP SysName импортировано.')

def import_snmp_sys_location(parent, path):
    json_file = os.path.join(path, 'config_snmp_syslocation.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.set_snmp_syslocation(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте значения SNMP SysLocation.')
    else:
        parent.stepChanged.emit('BLACK|    Значение SNMP SysLocation импортировано.')

def import_snmp_sys_description(parent, path):
    json_file = os.path.join(path, 'config_snmp_sysdescription.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.set_snmp_sysdescription(data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте значения SNMP SysDescription.')
    else:
        parent.stepChanged.emit('BLACK|    Значение SNMP SysDescription импортировано.')

#------------------------------------------------------------------------------------------------------------------------
def pass_function(parent, path):
    """Функция заглушка"""
    parent.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')

import_funcs = {
    "Morphology": import_morphology_lists,
    "Services": import_services_list,
    "ServicesGroups": import_services_groups,
    "IPAddresses": import_ip_lists,
    "Useragents": import_useragent_lists,
    "ContentTypes": import_mime_lists,
    "URLLists": import_url_lists,
    "TimeSets": import_time_restricted_lists,
    "BandwidthPools": import_shaper_list,
    "SCADAProfiles": import_scada_profiles,
    "ResponcePages": import_templates_list,
    "URLCategories": import_url_categories,
    "OverURLCategories": import_custom_url_category,
    "Applications": import_application_signature,
    "ApplicationProfiles": import_app_profiles,
    "ApplicationGroups": import_application_groups,
    "Emails": import_email_groups,
    "Phones": import_phone_groups,
    "IPDSSignatures": import_custom_idps_signature,
    "IDPSProfiles": import_idps_profiles,
    "NotificationProfiles": import_notification_profiles,
    "NetflowProfiles": import_netflow_profiles,
    "LLDPProfiles": import_lldp_profiles,
    "SSLProfiles": import_ssl_profiles,
    "SSLForwardingProfiles": import_ssl_forward_profiles,
    "HIDObjects": import_hip_objects,
    "HIDProfiles": import_hip_profiles,
    "BfdProfiles": import_bfd_profiles,
    "UserIdAgentSyslogFilters": import_useridagent_syslog_filters,
    "Scenarios": import_scenarios,
    'Zones': import_zones,
    'Interfaces': import_interfaces,
    'Gateways': import_gateways,
    'AuthServers': import_auth_servers,
    'AuthProfiles': import_auth_profiles,
    'CaptiveProfiles': import_captive_profiles,
    'CaptivePortal': import_captive_portal_rules,
    'Groups': import_local_groups,
    'Users': import_local_users,
    'TerminalServers': import_terminal_servers,
    'MFAProfiles': import_2fa_profiles,
    'UserIDagent': import_userid_agent,
    'BYODPolicies': import_byod_policy,
    'BYODDevices': pass_function,
    'Certificates': pass_function,
    'UserCertificateProfiles': import_users_certificate_profiles,
    'GeneralSettings': import_general_settings,
    'DeviceManagement': pass_function,
    'Administrators': pass_function,
    'DNS': import_dns_config,
    'DHCP': import_dhcp_subnets,
    'VRF': import_vrf,
    'WCCP': import_wccp_rules,
    'Routes': pass_function,
    'OSPF': pass_function,
    'BGP': pass_function,
    'Firewall': import_firewall_rules,
    'NATandRouting': import_nat_rules,
    "ICAPServers": import_icap_servers,
    "ReverseProxyServers": import_reverseproxy_servers,
    'LoadBalancing': import_loadbalancing_rules,
    'TrafficShaping': import_shaper_rules,
    "ContentFiltering": import_content_rules,
    "SafeBrowsing": import_safebrowsing_rules,
    "TunnelInspection": import_tunnel_inspection_rules,
    "SSLInspection": import_ssldecrypt_rules,
    "SSHInspection": import_sshdecrypt_rules,
    "IntrusionPrevention": import_idps_rules,
    "MailSecurity": import_mailsecurity,
    "ICAPRules": import_icap_rules,
    "DoSProfiles": import_dos_profiles,
    "DoSRules": import_dos_rules,
    "SCADARules": import_scada_rules,
    "CustomWafLayers": import_waf_custom_layers,
    "SystemWafRules": pass_function,
    "WAFprofiles": import_waf_profiles,
    "WebPortal": import_proxyportal_rules,
    "ReverseProxyRules": import_reverseproxy_rules,
    "ServerSecurityProfiles": import_vpnserver_security_profiles,
    "ClientSecurityProfiles": import_vpnclient_security_profiles,
    "SecurityProfiles": import_vpn_security_profiles,
    "VPNNetworks": import_vpn_networks,
    "ServerRules": import_vpn_server_rules,
    "ClientRules": import_vpn_client_rules,
    "AlertRules": import_notification_alert_rules,
    "SNMPSecurityProfiles": import_snmp_security_profiles,
    "SNMP": import_snmp_rules,
    "SNMPParameters": import_snmp_settings,
}

############################# Служебные функции #####################################
def get_ips_id(parent, mode, rule_ips, rule):
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
                new_rule_ips.append(['list_id', parent.ngfw_data['ip_lists'][ips[1]]])
            elif ips[0] == 'urllist_id':
                if parent.version < 6:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{rule["name"]}"]. Список доменов "{ips[1]}" не добавлен в источник/назначение. Версия 5 не поддерживает данный функционал.')
                else:
                    new_rule_ips.append(['urllist_id', parent.ngfw_data['url_lists'][ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список {mode}-адресов "{ips[1]}". Загрузите списки в библиотеки и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список {mode}-адресов "{ips[1]}".'
            rule['enabled'] = False
            parent.error = 1
    return new_rule_ips

def get_zones_id(parent, mode, zones, rule):
    """
    Получить ID зон. Если зона не существует на NGFW, то она пропускается.
    mode - принимает значения: src | dst (для формирования сообщений).
    """
    new_zones = []
    for zone_name in zones:
        try:
            new_zones.append(parent.ngfw_data['zones'][zone_name])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена {mode}-зона "{zone_name}". Импортируйте зоны и повторите попытку.')
            rule['description'] = f'{rule["description"]}\nError: Не найдена {mode}-зона "{zone_name}".'
            rule['enabled'] = False
            parent.error = 1
    return new_zones

def get_urls_id(parent, urls, rule):
    """Получить ID списков URL. Если список не существует на NGFW, он пропускается."""
    new_urls = []
    for item in urls:
        try:
            new_urls.append(parent.ngfw_data['url_lists'][item])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден список URL "{item}". Загрузите списки URL и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найден список URL "{item}".'
            rule['enabled'] = False
            parent.error = 1
    return new_urls

def get_url_categories_id(parent, rule, referer=0):
    """Получить ID категорий URL и групп категорий URL. Если список не существует на NGFW, он пропускается."""
    new_categories = []
    rule_data = rule['referer_categories'] if referer else rule['url_categories']
    for item in rule_data:
        try:
            if item[0] == 'list_id':
                new_categories.append(['list_id', parent.ngfw_data['url_categorygroups'][item[1]]])
            elif item[0] == 'category_id':
                new_categories.append(['category_id', parent.ngfw_data['url_categories'][item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена категория URL "{item[1]}". Загрузите категории URL и повторите импорт.')
            rule['description'] = f'{rule["description"]}\nError: Не найдена категория URL "{item[1]}".'
            rule['enabled'] = False
            parent.error = 1
    return new_categories

def get_guids_users_and_groups(parent, rule):
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
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule["name"]}"]. Не указано имя пользователя в "{item}".')
                if user_name:
                    err, result = parent.utm.get_ldap_user_guid(ldap_domain, user_name)
                    if err:
                        parent.stepChanged.emit(f'RED|    {result}  [Rule "{rule["name"]}"]')
                        rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID пользователя "{user_name}" - {result}.'
                        rule['enabled'] = False
                        parent.error = 1
                    elif not result:
                        parent.stepChanged.emit(f'RED|    Error [Rule "{rule["name"]}"]. Нет LDAP-коннектора для домена "{ldap_domain}". Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                        rule['description'] = f'{rule["description"]}\nError: Нет пользователя "{user_name}" в домене или LDAP-коннектора для домена "{ldap_domain}".'
                        rule['enabled'] = False
                        parent.error = 1
                    else:
                        new_users.append(['user', result])
                else:
                    try:
                        new_users.append(['user', parent.ngfw_data['local_users'][item[1]]])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден локальный пользователь "{err}". Импортируйте локальных пользователей.')
                        rule['description'] = f'{rule["description"]}\nError: Не найден локальный пользователь "{err}".'
                        rule['enabled'] = False
                        parent.error = 1
            case 'group':
                group_name = None
                try:
                    ldap_domain, _, group_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule["name"]}"]. Не указано имя группы в "{item}".')
                if group_name:
                    err, result = parent.utm.get_ldap_group_guid(ldap_domain, group_name)
                    if err:
                        parent.stepChanged.emit(f'RED|    {result}  [Rule "{rule["name"]}"]')
                        rule['description'] = f'{rule["description"]}\nError: Не удалось получить ID группы "{group_name}" - {result}.'
                        rule['enabled'] = False
                        parent.error = 1
                    elif not result:
                        parent.stepChanged.emit(f'RED|    Error [Rule "{rule["name"]}"]. Нет LDAP-коннектора для домена "{ldap_domain}". Импортируйте и настройте LDAP-коннектор. Затем повторите импорт.')
                        rule['description'] = f'{rule["description"]}\nError: Нет группы "{group_name}" в домене или LDAP-коннектора для домена "{ldap_domain}".'
                        rule['enabled'] = False
                        parent.error = 1
                    else:
                        new_users.append(['group', result])
                else:
                    try:
                        new_users.append(['group', parent.ngfw_data['local_groups'][item[1]]])
                    except KeyError as err:
                        parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]: Не найдена группа пользователей "{err}"]. Импортируйте группы пользователей.')
                        rule['description'] = f'{rule["description"]}\nError: Не найдена группа пользователей "{err}".'
                        rule['enabled'] = False
                        parent.error = 1
    return new_users

def get_services(parent, service_list, rule):
    """Получаем ID сервисов по их именам. Если сервис не найден, то он пропускается."""
    new_service_list = []
    if parent.version < 7:
        for item in service_list:
            if item[0] == 'list_id':
                parent.stepChanged.emit(f'bRED|    Error [Правило "{rule["name"]}"]. Группа сервисов "{item[1]}" не добавлена. В версии 6 группы сервисов не поддерживаются.')
            else:
                try:
                    new_service_list.append(parent.ngfw_data['services'][item[1]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден сервис "{item[1]}". Импортируйте сервисы и повторите попытку.')
                    rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
                    rule['enabled'] = False
                    parent.error = 1
    else:
        for item in service_list:
            try:
                if item[0] == 'service':
                    new_service_list.append(['service', parent.ngfw_data['services'][item[1]]])
                elif item[0] == 'list_id':
                    new_service_list.append(['list_id', parent.ngfw_data['service_groups'][item[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден сервис "{item[1]}". Загрузите сервисы и повторите импорт.')
                rule['description'] = f'{rule["description"]}\nError: Не найден сервис "{item[1]}".'
                rule['enabled'] = False
                parent.error = 1
    return new_service_list

def get_time_restrictions_id(parent, rule):
    """Получить ID календарей. Если не существуют на NGFW, то пропускается."""
    new_schedules = []
    for cal_name in rule['time_restrictions']:
        try:
            new_schedules.append(parent.ngfw_data['calendars'][cal_name])
        except KeyError as err:
            parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найден календарь "{cal_name}".')
            rule['description'] = f'{rule["description"]}\nError: Не найден календарь "{cal_name}".'
            rule['enabled'] = False
            parent.error = 1
    return new_schedules

def get_apps(parent, rule):
    """Определяем ID приложения или группы приложений по именам."""
    new_app_list = []
    for app in rule['apps']:
        if app[0] == 'ro_group':
            if app[1] == 'All':
                if parent.version >= 6:
                    new_app_list.append(['ro_group', 0])
                else:
                    parent.stepChanged.emit(f'bRED|    Error [Правило "{rule["name"]}"]. Категорию "All" нельзя добавить в версии 5.')
            else:
                try:
                    new_app_list.append(['ro_group', parent.ngfw_data['l7_categories'][app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена категория l7 "{app[1]}".')
                    parent.stepChanged.emit('RED|    Возможно нет лицензии и UTM не получил список категорий l7. Установите лицензию и повторите попытку.')
                    rule['description'] = f'{rule["description"]}\nError: Не найдена категория l7 "{app[1]}".'
                    rule['enabled'] = False
                    parent.error = 1
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.ngfw_data['application_groups'][app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдена группа приложений l7 "{app[1]}".')
                rule['description'] = f'{rule["description"]}\nError: Не найдена группа приложений l7 "{app[1]}".'
                rule['enabled'] = False
                parent.error = 1
        elif app[0] == 'app':
            if parent.version < 7:
                try:
                    new_app_list.append(['app', parent.ngfw_data['l7_apps'][app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'RED|    Error [Правило "{rule["name"]}"]. Не найдено приложение "{app[1]}".')
                    parent.stepChanged.emit('RED|    Возможно нет лицензии и UTM не получил список приложений l7. Установите лицензию и повторите попытку.')
                    rule['description'] = f'{rule["description"]}\nError: Не найдено приложение "{app[1]}".'
                    rule['enabled'] = False
                    parent.error = 1
            else:
                parent.stepChanged.emit(f'NOTE|    Правило "{rule["name"]}": приложение {app[1]} не добавлено, так как в версии 7.0 отдельное приложение добавить нельзя.')

    return new_app_list

def execute_add_update_nlist(parent, ngfw_named_list, item, item_note):
    """Обновляем существующий именованный список или создаём новый именованный список"""
    if item['name'] in ngfw_named_list:
        parent.stepChanged.emit(f'GRAY|    {item_note} "{item["name"]}" уже существует.')
        err, result = parent.utm.update_nlist(ngfw_named_list[item['name']], item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}  [{item_note}: {item["name"]}]')
            return 1
        elif err == 2:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.stepChanged.emit(f'BLACK|    {item_note} "{item["name"]}" updated.')
    else:
        err, result = parent.utm.add_nlist(item)
        if err:
            parent.stepChanged.emit(f'RED|    {result}  [{item_note}: "{item["name"]}"]')
            return 1
        else:
            ngfw_named_list[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    {item_note} "{item["name"]}" импортирована.')
    return 0

def execute_add_nlist_items(parent, list_id, item_name, content):
    """Импортируем содержимое в именованный список"""
    err, result = parent.utm.add_nlist_items(list_id, content)
    if err == 2:
        parent.stepChanged.emit(f'GRAY|       {result}')
    elif err == 1:
        parent.stepChanged.emit(f'RED|       {result}  [Список: "{item_name}"]')
        return 1
    else:
        parent.stepChanged.emit(f'BLACK|       Содержимое списка "{item_name}" обновлено.')
    return 0

def add_new_nlist(utm, name, nlist_type, content):
    """Добавляем в библиотеку новый nlist с содержимым."""
    nlist = {
        'name': name,
        'description': '',
        'type': nlist_type,
        'list_type_update': 'static',
        'schedule': 'disabled',
        'attributes': {'threat_level': 3},
    }
    err, list_id = utm.add_nlist(nlist)
    if err:
        return err, list_id
    err, result = utm.add_nlist_items(list_id, content)
    if err:
        return err, result
    return 0, list_id

def add_empty_vrf(utm, vrf_name):
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
    err, result = utm.add_vrf(vrf)
    if err:
        return err, result
    return 0, result    # Возвращаем ID добавленного VRF

def get_scenarios_rules(parent):
    """Устанавливаем значение атрибута parent.scenarios_rules"""
    err, result = parent.utm.get_scenarios_rules()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.scenarios_rules = {func.get_restricted_name(x['name']): x['id'] for x in result}
    return 0

def get_client_certificate_profiles(parent):
    """
    Получаем список профилей пользовательских сертификатов и
    устанавливаем значение атрибута parent.client_certificate_profiles
    """
    err, result = parent.utm.get_client_certificate_profiles()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.client_certificate_profiles = {x['name']: x['id'] for x in result}
    parent.client_certificate_profiles[0] = 0
    return 0

def get_notification_profiles_list(parent):
    """Получаем список профилей оповещения и устанавливаем значение атрибута parent.notification_profiles"""
    err, result = parent.utm.get_notification_profiles_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.notification_profiles = {func.get_restricted_name(x['name']): x['id'] for x in result}
    parent.notification_profiles[-5] = -5
    return 0

def get_templates_list(parent):
    """Получаем список шаблонов страниц и устанавливаем значение атрибута parent.list_templates"""
    err, result = parent.utm.get_templates_list()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.list_templates = {x['name']: x['id'] for x in result}
    parent.list_templates[-1] = -1
    return 0

def get_icap_servers(parent):
    """Получаем список серверов ICAP и устанавливаем значение атрибута parent.icap_servers"""
    err, result = parent.utm.get_icap_servers()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.icap_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}
    return 0

def get_reverseproxy_servers(parent):
    """Получаем список серверов reverse-proxy и устанавливаем значение атрибута parent.reverseproxy_servers"""
    err, result = parent.utm.get_reverseproxy_servers()
    if err:
        parent.stepChanged.emit(f'RED|       {result}')
        parent.error = 1
        return 1
    parent.reverseproxy_servers = {func.get_restricted_name(x['name']): x['id'] for x in result}
    return 0

