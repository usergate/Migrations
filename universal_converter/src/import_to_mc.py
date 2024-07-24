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
# Классы импорта разделов конфигурации на UserGate Management Center версии 7.
# Версия 1.8
#

import os, sys, json, time
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QInputDialog


class ImportAll(QThread):
    """Импортируем всю конфигурацию в шаблон MC"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, config_path, all_points, template_id, arguments, node_name):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.all_points = all_points

        self.template_id = template_id
        self.template_name = None
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
        self.ldap_servers = {}
        self.application_groups = {}
        self.l7_categories = {}
        self.mc_zones = {}
        self.mc_services = {}
        self.mc_servicegroups = {}
        self.mc_iplists = {}
        self.mc_url_lists = {}
        self.mc_time_restrictions = {}
        self.error = 0

    def run(self):
        """Импортируем всё в пакетном режиме"""
        err, result = self.utm.fetch_device_template(self.template_id)
        if err:
            self.stepChanged.emit('iRED|Не удалось получить имя шаблона. {result}')
            self.template_name = 'None'
        else:
            self.template_name = result['name']

        err, result = get_ldap_servers(self)
        if err == 1:
            self.stepChanged.emit(f'bRED|    {result}')
            error = 1
        else:
            self.ldap_servers = result

        path_dict = {}
        for item in self.all_points:
            top_level_path = os.path.join(self.config_path, item['path'])
            for point in item['points']:
                path_dict[point] = os.path.join(top_level_path, point)
        for key, value in import_funcs.items():
            if key in path_dict:
                value(self, path_dict[key])

        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт конфигурации завершён.\n')


class ImportSelectedPoints(QThread):
    """Импортируем выделенный раздел конфигурации на NGFW"""
    stepChanged = pyqtSignal(str)

    def __init__(self, utm, config_path, selected_path, selected_points, template_id, arguments, node_name):
        super().__init__()
        self.utm = utm

        self.config_path = config_path
        self.selected_path = selected_path
        self.selected_points = selected_points

        self.template_id = template_id
        self.template_name = None
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
        self.ldap_servers = {}
        self.application_groups = {}
        self.l7_categories = {}
        self.mc_zones = {}
        self.mc_services = {}
        self.mc_servicegroups = {}
        self.mc_iplists = {}
        self.mc_url_lists = {}
        self.mc_time_restrictions = {}
        self.error = 0


    def run(self):
        """Импортируем определённый раздел конфигурации"""
        err, result = self.utm.fetch_device_template(self.template_id)
        if err:
            self.stepChanged.emit('iRED|Не удалось получить имя шаблона. {result}')
            self.template_name = 'None'
        else:
            self.template_name = result['name']

        err, result = get_ldap_servers(self)
        if err == 1:
            self.stepChanged.emit(f'bRED|    {result}')
            error = 1
        else:
            self.ldap_servers = result

        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            if point in import_funcs:
                import_funcs[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')

        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт конфигурации завершён.\n')


def import_general_settings(parent, path):
    """Импортируем раздел 'UserGate/Настройки'."""
    import_ui(parent, path)
    import_modules(parent, path)
    import_ntp_settings(parent, path)

def import_ui(parent, path):
    """Импортируем часовой пояс"""
    json_file = os.path.join(path, 'config_settings_ui.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт часового пояса в "Настройки/Настройки интерфейса/Часовой пояс".')

    params = {'ui_timezone': 'Часовой пояс'}
    error = 0
    
    time_zone = data['ui_timezone']
    data['ui_timezone'] = {'value': time_zone}
    err, result = parent.utm.set_template_settings(parent.template_id, data)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        parent.stepChanged.emit(f'BLACK|    Часовой пояс установлен в значение "{time_zone}".')

    out_message = 'GREEN|    Импортирован часовой пояс в раздел "Настройки/Настройки интерфейса/Часовой пояс".'
    parent.stepChanged.emit('ORANGE|    Ошибка импорта часового пояса!' if error else out_message)

def import_modules(parent, path):
    """Импортируем модули"""
    json_file = os.path.join(path, 'config_settings_modules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    parent.stepChanged.emit('BLUE|Импорт домена captive-портала в "Настройки/Модули".')

    params = {
        'auth_captive': 'Домен Auth captive-портала',
        'logout_captive': 'Домен Logout captive-портала',
        'block_page_domain': 'Домен страницы блокировки',
        'ftpclient_captive': 'FTP поверх HTTP домен',
        'ftp_proxy_enabled': 'FTP поверх HTTP'
    }
    error = 0
    
    for key in data:
        if key in params:
            setting = {}
            setting[key] = {'value': data[key]}
            err, result = parent.utm.set_template_settings(parent.template_id, setting)
            if err:
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
                parent.error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Изменён "{params[key]}".')

    out_message = 'GREEN|    Настройки домена captive-портала импортированы в раздел "Настройки/Модули".'
    parent.stepChanged.emit('ORANGE|    Импорт домена captive-портала прошёл с ошибками.' if error else out_message)

def import_ntp_settings(parent, path):
    """Импортируем настройки NTP"""
    json_file = os.path.join(path, 'config_ntp.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    parent.stepChanged.emit('BLUE|Импорт настроек NTP раздела "Настройки/Настройки времени сервера".')

    error = 0
    for i, ntp_server in enumerate(data['ntp_servers']):
        ns = {f'ntp_server{i+1}': {'value': ntp_server}}
        err, result = parent.utm.set_template_settings(parent.template_id, ns)
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    NTP-сервер {ntp_server} добавлен.')

    err, result = parent.utm.set_template_settings(parent.template_id, {'ntp_enabled': {'value': data['ntp_enabled']}})
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
        parent.error = 1
    else:
        parent.stepChanged.emit(f'BLACK|    Использование NTP {"включено" if data["ntp_enabled"] else "отключено"}.')

    out_message = 'GREEN|    Импортированы сервера NTP в раздел "Настройки/Настройки времени сервера".'
    parent.stepChanged.emit('ORANGE|    Произоша ошибка при импорте настроек NTP.' if error else out_message)


def import_dns_config(parent, path):
    """Импортируем раздел 'UserGate/DNS'."""
    import_dns_servers(parent, path)
    import_dns_rules(parent, path)
    import_dns_static(parent, path)

def import_dns_servers(parent, path):
    """Импортируем список системных DNS серверов"""
    json_file = os.path.join(path, 'config_dns_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    parent.stepChanged.emit('BLUE|Импорт системных DNS серверов в раздел "Сеть/DNS/Системные DNS-серверы".')

    error = 0
    for item in data:
        item.pop('is_bad', None)
        err, result = parent.utm.add_template_dns_server(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    DNS сервер "{item["dns"]}" добавлен.')

    out_message = 'GREEN|    Импортированы системные DNS-сервера в раздел "Сеть/DNS/Системные DNS-серверы".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте DNS-серверов.' if error else out_message)

def import_dns_rules(parent, path):
    """Импортируем правила DNS-прокси"""
    json_file = os.path.join(path, 'config_dns_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    parent.stepChanged.emit('BLUE|Импорт правил DNS-прокси в раздел "Сеть/DNS/DNS-прокси/Правила DNS".')

    error = 0
    for item in data:
        err, result = parent.utm.add_template_dns_rule(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Правило DNS-прокси "{item["name"]}" импортировано.')

    out_message = 'GREEN|    Импортированы правила DNS-прокси в раздел "Сеть/DNS/DNS-прокси/Правила DNS".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил DNS-прокси.' if error else out_message)

def import_dns_static(parent, path):
    """Импортируем статические записи DNS"""
    json_file = os.path.join(path, 'config_dns_static.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return
    parent.stepChanged.emit('BLUE|Импорт статических записей DNS в раздел "Сеть/DNS/DNS-прокси/Статические записи".')

    error = 0
    for item in data:
        err, result = parent.utm.add_template_dns_static_record(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Статическая запись DNS "{item["name"]}" импортирована.')

    out_message = 'GREEN|    Статические записи DNS импортированы в раздел "Сеть/DNS/DNS-прокси/Статические записи".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте статических записей DNS.' if error else out_message)


def import_zones(parent, path):
    """Импортируем зоны на NGFW, если они есть."""
    json_file = os.path.join(path, 'config_zones.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    parent.stepChanged.emit('BLUE|Импорт зон в раздел "Сеть/Зоны".')

    service_ids = {
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
        'SCADA': 'ffffff03-ffff-ffff-ffff-ffffff000017',
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
        'Endpoints connect': 'ffffff03-ffff-ffff-ffff-ffffff000033'
    }

    error = 0
    for zone in data:
        new_services_access = []
        for service in zone['services_access']:
            if service['enabled']:
                if service['allowed_ips'] and isinstance(service['allowed_ips'][0], list):
                    allowed_ips = []
                    for item in service['allowed_ips']:
                        if item[0] == 'list_id':
                            try:
                                item[1] = parent.mc_iplists[item[1]]
                            except KeyError as err:
                                parent.stepChanged.emit(f'bRED|    Зона "{zone["name"]}": в контроле доступа "{service["service_id"]}" не найден список IP-адресов "{err}".')
                                error = 1
                        allowed_ips.append(item)
                    service['allowed_ips'] = allowed_ips
                service['service_id'] = service_ids.get(service['service_id'], 'ffffff03-ffff-ffff-ffff-ffffff000001')
                new_services_access.append(service)
        zone['services_access'] = new_services_access
        err, result = parent.utm.add_template_zone(parent.template_id, zone)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Зона "{zone["name"]}" импортирована.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.')
    else:
        parent.stepChanged.emit('GREEN|    Зоны импортированы в раздел "Сеть/Зоны".')


def import_interfaces(parent, path):
    import_vlans(parent, path)
    import_ipip_interface(parent, path)

def import_ipip_interface(parent, path):
    """Импортируем интерфесы IP-IP."""
    json_file = os.path.join(path, 'config_interfaces.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    # Проверяем что есть интерфейсы IP-IP для импорта.
    is_gre = False
    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'] == 'gre':
            is_gre = True
    if not is_gre:
        return

    parent.stepChanged.emit('BLUE|Импорт интерфейсов IP-IP в раздел "Сеть/Интерфейсы".')
    err, result = parent.utm.get_template_interfaces_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    ngfw_gre = [x['name'] for x in result if x['kind'] == 'tunnel' and x['name'].startswith('gre')]

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    error = 0
    gre_num = 0
    for item in ngfw_gre:
        if int(item[3:]) > gre_num:
            gre_num = int(item[3:])

    for item in data:
        if 'kind' in item and item['kind'] == 'tunnel' and item['name'] == 'gre':
            gre_num += 1
            item.pop('id', None)      # удаляем readonly поле
            item.pop('master', None)      # удаляем readonly поле
            item.pop('mac', None)
            item['node_name'] = parent.node_name
            item['enabled'] = False   # Отключаем интерфейс. После импорта надо включить руками.

            item['name'] = f"{item['name']}{gre_num}"
            if item['zone_id']:
                try:
                    item['zone_id'] = parent.mc_zones[item['zone_id']]
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Для интерфейса IP-IP "{item["name"]}" не найдена зона "{item["zone_id"]}". Импортируйте зоны и повторите попытку.')
                    item['zone_id'] = 0

            new_ipv4 = []
            for ip in item['ipv4']:
                err, result = func.unpack_ip_address(ip)
                if err:
                    parent.stepChanged.emit(f'bRED|    Не удалось преобразовать IP: "{ip}" для VLAN {item["vlan_id"]}. IP-адрес использован не будет. Error: {result}')
                else:
                    new_ipv4.append(result)
            if not new_ipv4:
                item['config_on_device'] = True
            item['ipv4'] = new_ipv4

            err, result = parent.utm.add_template_interface(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    Error: Интерфейс IP-IP {item["ipv4"]} не импортирован!')
                parent.stepChanged.emit(f'RED|    {result}')
                error = 1
            else:
                parent.stepChanged.emit(f'BLACK|    Добавлен интерфейс IP-IP {item["ipv4"]}.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка создания интерфейса IP-IP!')
    else:
        parent.stepChanged.emit('GREEN|    Интерфейсы IP-IP импортированы в раздел "Сеть/Интерфейсы".')
        parent.stepChanged.emit('LBLUE|    Установите зону импортированным интерфейсам IP-IP.')


def import_vlans(parent, path):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    parent.stepChanged.emit('BLUE| Импорт VLAN в раздел "Сеть/Интерфейсы"')
    error = 0
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        if parent.ngfw_vlans == 1:
            parent.error = 1
        return

    if not parent.mc_zones:
        err = set_mc_zones(parent)
        if err:
            return

    for item in parent.iface_settings:
        if item['kind'] == 'vlan':
            current_port = parent.new_vlans[item['vlan_id']]['port']
            current_zone = parent.new_vlans[item['vlan_id']]['zone']
            if item["vlan_id"] in parent.ngfw_vlans:
                parent.stepChanged.emit(f"GRAY|    VLAN {item['vlan_id']} уже существует на порту {parent.ngfw_vlans[item['vlan_id']]}")
                continue
            if current_port == "Undefined":
                parent.stepChanged.emit(f"rNOTE|    VLAN {item['vlan_id']} не импортирован так как для него не назначен порт.")
                continue

            item.pop('running', None)
            item.pop('master', None)
            item.pop('mac', None)
            item['node_name'] = parent.node_name
            item['config_on_device'] = False
            item['link'] = current_port
            item['name'] = f'{current_port}.{item["vlan_id"]}'
            try:
                item['zone_id'] = 0 if current_zone == "Undefined" else parent.mc_zones[current_zone]
            except KeyError as err:
                parent.stepChanged.emit(f"bRED|    В шаблоне не найдена зона {err} для VLAN {item['vlan_id']}. Импортируйте зоны и повторите попытку.")
                item['zone_id'] = 0
            new_ipv4 = []
            for ip in item['ipv4']:
                err, result = func.unpack_ip_address(ip)
                if err:
                    parent.stepChanged.emit(f'bRED|    Не удалось преобразовать IP: "{ip}" для VLAN {item["vlan_id"]}. IP-адрес использован не будет. Error: {result}')
                else:
                    new_ipv4.append(result)
            if not new_ipv4:
                item['mode'] = 'manual'
            item['ipv4'] = new_ipv4

            err, result = parent.utm.add_template_interface(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'RED|    Интерфейс {item["name"]} не импортирован. Error: {result}')
                error = 1
                parent.error = 1
            else:
                parent.ngfw_vlans[item['vlan_id']] = item['name']
                parent.stepChanged.emit(f'BLACK|    Добавлен VLAN {item["vlan_id"]}, name: {item["name"]}, zone: {current_zone}.')

    out_message = 'GREEN|    Интерфейсы VLAN импортированы в раздел "Сеть/Интерфейсы".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при создания интерфейсов VLAN.' if error else out_message)


def import_gateways(parent, path):
    """Импортируем список шлюзов"""
    json_file = os.path.join(path, 'config_gateways.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    if isinstance(parent.ngfw_ports, int) and parent.ngfw_ports == 3:
        parent.stepChanged.emit(f'ORANGE|    Импорт шлюзов отменён из-за отсутствия портов на узле {parent.node_name} шаблона.')
        if parent.ngfw_ports == 1:
            parent.error = 1
        return

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    gateways_list = {x.get('name', x['ipv4']): x['id'] for x in result}
    error = 0

    for item in data:
        if not item['is_automatic']:
            item['node_name'] = parent.node_name
            if item['name'] in gateways_list:
                err, result = parent.utm.update_template_gateway(parent.template_id, gateways_list[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|    Error: Шлюз "{item["name"]}" не обновлён. {result}')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" уже существует - Updated!')
            else:
                err, result = parent.utm.add_template_gateway(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    Error:  Шлюз "{item["name"]}" не импортирован. {result}')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Шлюз "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте шлюзов.')
    else:
        parent.stepChanged.emit('GREEN|    Шлюзы импортированы в раздел "Сеть/Шлюзы".')


def import_dhcp_subnets(parent, path):
    """Импортируем настойки DHCP"""
    parent.stepChanged.emit('BLUE|Импорт настроек DHCP раздела "Сеть/DHCP".')
    if isinstance(parent.ngfw_ports, int):
        parent.stepChanged.emit(parent.dhcp_settings)
        if parent.ngfw_ports == 1:
            parent.error = 1
        return
    error = 0

    err, result = parent.utm.get_dhcp_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mc_dhcp_subnets = [x['name'] for x in result]

    for item in parent.dhcp_settings:
        if item['iface_id'] == 'Undefined':
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как для него не указан порт.')
            continue
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in mc_dhcp_subnets:
            parent.stepChanged.emit(f'GRAY|    DHCP subnet "{item["name"]}" не добавлен так как уже существует.')
            continue
        if item['iface_id'] not in parent.ngfw_ports:
            parent.stepChanged.emit(f'rNOTE|    DHCP subnet "{item["name"]}" не добавлен так как порт: {item["iface_id"]} не существует на МС.')
            continue
        item['node_name'] = parent.node_name

        err, result = parent.utm.add_dhcp_subnet(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [subnet "{item["name"]}"]')
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.')
        else:
            parent.stepChanged.emit(f'BLACK|    DHCP subnet "{item["name"]}" импортирован.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте настроек DHCP.')
    else:
        parent.stepChanged.emit('GREEN|    Настройки DHCP импортированы в раздел "Сеть/DHCP".')


def import_vrf(parent, path):
    """Импортируем виртуальный маршрутизатор по умолчанию"""
    json_file = os.path.join(path, 'config_vrf.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт виртуального маршрутизатора по умолчанию в раздел "Сеть/Виртуальные маршрутизаторы".')
    if isinstance(parent.ngfw_ports, int) and parent.ngfw_ports == 3:
        parent.stepChanged.emit(f'ORANGE|    Импорт виртуального маршрутизатора отменён из-за отсутствия портов на узле {parent.node_name} шаблона.')
        if parent.ngfw_ports == 1:
            parent.error = 1
        return

    parent.stepChanged.emit('LBLUE|    Добавляемые маршруты будут в не активном состоянии. Необходимо проверить маршрутизацию и включить их.')
    parent.stepChanged.emit('LBLUE|    Если вы используете BGP, после импорта включите нужные фильтры in/out для BGP-соседей и Routemaps в свойствах соседей.')
    parent.stepChanged.emit('LBLUE|    Если вы используете OSPF, после импорта установите нужный профиль BFD для каждого интерфейса в настройках OSPF.')
    
    err, result = parent.utm.get_template_vrf_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return

    virt_routers = {x['name']: x['id'] for x in result}
    error = 0    
    
    for item in data:
        item['node_name'] = parent.node_name
        for x in item['routes']:
            x['enabled'] = False
            x['name'] = func.get_restricted_name(x['name'])
        if item['ospf']:
            item['ospf']['enabled'] = False
            for x in item['ospf']['interfaces']:
                x['bfd_profile'] = -1
        if item['rip']:
            item['rip']['enabled'] = False
        if item['pimsm']:
            item['pimsm']['enabled'] = False
        if item['bgp']:
            item['bgp']['enabled'] = False
            for x in item['bgp']['neighbors']:
                x['filter_in'] = []
                x['filter_out'] = []
                x['routemap_in'] = []
                x['routemap_out'] = []

        try:
            if item['name'] in virt_routers:
                err, result = parent.utm.update_template_vrf(parent.template_id, virt_routers[item['name']], item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [vrf: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    VRF "{item["name"]}" уже существует - Updated!')
            else:
                err, result = parent.utm.add_template_vrf(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result} [vrf: "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|    Создан виртуальный маршрутизатор "{item["name"]}".')
        except OverflowError as err:
            parent.stepChanged.emit(f'RED|    Произошла ошибка при импорте виртуального маршрутизатора "{item["name"]}" [{err}].')
            error = 1
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте виртуального маршрутизатора.')
    else:
        parent.stepChanged.emit('GREEN|    Виртуальный маршрутизатор импортирован в раздел "Сеть/Виртуальные маршрутизаторы".')


def import_local_groups(parent, path):
    """Импортируем список локальных групп пользователей"""
    json_file = os.path.join(path, 'config_groups.json')
    err, groups = func.read_json_file(parent, json_file)
    if err:
        return
    err, result = parent.utm.get_template_groups_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    local_groups = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('BLUE|Импорт локальных групп пользователей в раздел "Пользователи и устройства/Группы".')
    parent.stepChanged.emit(f'LBLUE|    Если используются доменные пользователи, необходимы настроенные LDAP-коннекторы в "Управление областью/Каталоги пользователей"')
    error = 0

    for item in groups:
        users = item.pop('users')
        item['name'] = func.get_restricted_name(item['name'])
        err, result = parent.utm.add_template_group(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}') # В версиях 6 и выше проверяется что группа уже существует.
        else:
            local_groups[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Локальная группа "{item["name"]}" импортирована.')

        # Добавляем доменных пользователей в группу.
        parent.stepChanged.emit(f'LBLUE|       Добавляем доменных пользователей в группу "{item["name"]}".')
        for user_name in users:
            user_array = user_name.split(' ')
            if len(user_array) > 1 and ('\\' in user_array[1]):
                domain, name = user_array[1][1:len(user_array[1])-1].split('\\')
                try:
                    ldap_id = parent.ldap_servers[domain.lower()]
                except KeyError:
                    parent.stepChanged.emit(f'bRED|       Доменный пользователь "{user_name}" не импортирован в группу "{item["name"]}". Нет LDAP-коннектора для домена "{domain}".')
                else:
                    err1, result1 = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, name)
                    if err1:
                        parent.stepChanged.emit(f'RED|       {result1}')
                        error = 1
                        continue
                    elif not result1:
                        parent.stepChanged.emit(f'NOTE|       Нет пользователя "{user_name}" в домене "{domain}". Доменный пользователь не импортирован в группу "{item["name"]}".')
                        continue
                    err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, local_groups[item['name']], result1)
                    if err2:
                        parent.stepChanged.emit(f'RED|       {result2}  [{user_name}]')
                        error = 1
                    else:
                        parent.stepChanged.emit(f'BLACK|       Пользователь "{user_name}" добавлен в группу "{item["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных групп пользователей.')
    else:
        parent.stepChanged.emit('GREEN|    Локальные группы пользователей импортирован в раздел "Пользователи и устройства/Группы".')


def import_local_users(parent, path):
    """Импортируем список локальных пользователей"""
    json_file = os.path.join(path, 'config_users.json')
    err, users = func.read_json_file(parent, json_file)
    if err:
        return

    err, result = parent.utm.get_template_users_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    local_users = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_groups_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    local_groups = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('BLUE|Импорт локальных пользователей в раздел "Пользователи и устройства/Пользователи".')
    error = 0
    for item in users:
        user_groups = item.pop('groups', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['auth_login'] = func.get_restricted_userlogin(item['auth_login'])
        err, result = parent.utm.add_template_user(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.') # В версиях 6 и выше проверяется что пользователь уже существует.
        else:
            local_users[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Добавлен локальный пользователь "{item["name"]}".')

        # Добавляем пользователя в группу.
        for group in user_groups:
            try:
                group_guid = local_groups[group]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|       Не найдена группа {err} для пользователя {item["name"]}. Импортируйте список групп и повторите импорт пользователей.')
            else:
                err2, result2 = parent.utm.add_user_in_template_group(parent.template_id, group_guid, local_users[item['name']])
                if err2:
                    parent.stepChanged.emit(f'RED|       {result2}  [User: {item["name"]}, Group: {group}]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Пользователь "{item["name"]}" добавлен в группу "{group}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте локальных пользователей.')
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

    error = 0
    parent.stepChanged.emit('BLUE|Импорт серверов LDAP в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить LDAP-коннекторы, ввести пароль и импортировать keytab файл.')
 
    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='ldap')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        ldap_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in ldap_servers:
                parent.stepChanged.emit(f'GRAY|    LDAP-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['keytab_exists'] = False
                item['type'] = 'ldap'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    ldap_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации LDAP "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов LDAP.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера LDAP импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_ntlm_server(parent, path):
    """Импортируем список серверов NTLM"""
    json_file = os.path.join(path, 'config_ntlm_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    error = 0
    parent.stepChanged.emit('BLUE|Импорт серверов NTLM в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить импортированные сервера аутентификации.')

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='ntlm')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        ntlm_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in ntlm_servers:
                parent.stepChanged.emit(f'GRAY|    NTLM-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'ntlm'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    ntlm_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации NTLM "{item["name"]}" импортироан.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов NTLM.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера NTLM импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_radius_server(parent, path):
    """Импортируем список серверов RADIUS"""
    json_file = os.path.join(path, 'config_radius_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов RADIUS в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить сервера RADIUS и ввести пароль.')
    error = 0

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='radius')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        radius_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in radius_servers:
                parent.stepChanged.emit(f'GRAY|    RADIUS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'radius'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    radius_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации RADIUS "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов RADIUS.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера RADIUS импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_tacacs_server(parent, path):
    """Импортируем список серверов TACACS+"""
    json_file = os.path.join(path, 'config_tacacs_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт серверов TACACS+ в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить сервера TACACS+ и ввести секретный ключ.')
    error = 0

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='tacacs_plus')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        tacacs_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in tacacs_servers:
                parent.stepChanged.emit(f'GRAY|    TACACS-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'tacacs_plus'
                item.pop("cc", None)
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    tacacs_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации TACACS+ "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов TACACS+.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера TACACS+ импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_saml_server(parent, path):
    """Импортируем список серверов SAML"""
    json_file = os.path.join(path, 'config_saml_servers.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.get_template_certificates_list(parent.template_id)
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    template_certs = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('BLUE|Импорт серверов SAML в раздел "Пользователи и устройства/Серверы аутентификации".')
    parent.stepChanged.emit(f'LBLUE|    После импорта необходимо включить сервера SAML и загрузить SAML metadata.')
    error = 0

    err, result = parent.utm.get_template_auth_servers(parent.template_id, servers_type='saml_idp')
    if err == 1:
        parent.stepChanged.emit(f'RED|    {result}')
        error = 1
    else:
        saml_servers = {x['name']: x['id'] for x in result}

        for item in data:
            item['name'] = func.get_restricted_name(item['name'])
            if item['name'] in saml_servers:
                parent.stepChanged.emit(f'GRAY|    SAML-сервер "{item["name"]}" уже существует.')
            else:
                item['enabled'] = False
                item['type'] = 'saml_idp'
                item.pop("cc", None)
                if item['certificate_id']:
                    try:
                        item['certificate_id'] = template_certs[item['certificate_id']]
                    except KeyError:
                        parent.stepChanged.emit(f'bRED|    Для "{item["name"]}" не найден сертификат "{item["certificate_id"]}".')
                        item['certificate_id'] = 0
                err, result = parent.utm.add_template_auth_server(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'RED|    {result}')
                    error = 1
                else:
                    saml_servers[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервер аутентификации SAML "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте серверов SAML.')
    else:
        parent.stepChanged.emit('GREEN|    Сервера SAML импортированы в раздел "Пользователи и устройства/Серверы аутентификации".')


def import_services_list(parent, path):
    """Импортируем список сервисов раздела библиотеки"""
    parent.stepChanged.emit('BLUE|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')
    json_file = os.path.join(path, 'config_services_list.json')
    err, data = func.read_json_file(parent, json_file)
    if err:
        return

    if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
        return

    error = 0
    for item in data:
        if item:
            if item['name'] in parent.mc_services:
                parent.stepChanged.emit(f'GRAY|    Сервис "{item["name"]}" уже существует.')
            else:
                err, result = parent.utm.add_template_service(parent.template_id, item)
                if err == 3:
                    parent.stepChanged.emit(f'GRAY|    {result}')
                elif err == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|    {result}')
                else:
                    parent.mc_services[item['name']] = result
                    parent.stepChanged.emit(f'BLACK|    Сервис "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при добавлении сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Список сервисов импортирован в раздел "Библиотеки/Сервисы"')


def import_services_groups(parent, path):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    json_file = os.path.join(path, 'config_services_groups_list.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    out_message = 'GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    error = 0
    
    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])

        if item['name'] in parent.mc_servicegroups:
            parent.stepChanged.emit(f'GRAY|    Группа сервисов "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_nlist(parent.template_id, parent.mc_servicegroups[item['name']], item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Группа сервисов: "{item["name"]}"]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.')
            else:
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа сервисов: "{item["name"]}" не импортирована]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}.')
            else:
                parent.mc_servicegroups[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Группа сервисов "{item["name"]}" добавлена.')

        if content:
            new_content = []
            for service in content:
                try:
                    service['value'] = parent.mc_services[service['name']]
                    new_content.append(service)
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|      Error: Не найден сервис "{err}". Загрузите сервисы в шаблон и повторите попытку.')

            err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, parent.mc_servicegroups[item['name']], new_content)
            if err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2} [Группа сервисов: "{item["name"]}"]')
            elif err2 == 3:
                parent.stepChanged.emit(f'GRAY|       {result2}')
            else:
                parent.stepChanged.emit(f'BLACK|       Содержимое группы сервисов "{item["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'GRAY|       Нет содержимого в группе сервисов "{item["name"]}".')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп сервисов.')
    else:
        parent.stepChanged.emit('GREEN|    Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".')


def import_ip_lists(parent, path):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('BLUE|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

    if not os.path.isdir(path):
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit('GRAY|    Нет списков IP-адресов для импорта.')
        return

    if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
        return

    error = 0
    # Импортируем все списки IP-адресов без содержимого (пустые).
    parent.stepChanged.emit('LBLUE|    Импортируем списки IP-адресов без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        err, result = parent.utm.add_template_nlist(parent.template_id, data)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Список IP-адресов "{data["name"]}" не импортирована]')
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}.')
        else:
            parent.mc_iplists[data['name']] = result
            parent.stepChanged.emit(f'BLACK|    Список IP-адресов "{data["name"]}" импортирован.')

    # Добавляем содержимое в уже добавленные списки IP-адресов.
    parent.stepChanged.emit('LBLUE|    Импортируем содержимое списков IP-адресов.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        try:
            list_id = parent.mc_iplists[data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|   Error: Нет IP-листа "{data["name"]}" в списках IP-адресов шаблона МС.')
            parent.stepChanged.emit(f'RED|   Error: Содержимое не добавлено в список IP-адресов "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            new_content = []
            for item in data['content']:
                if 'list' in item:
                    try:
                        item['list'] = parent.mc_iplists[func.get_restricted_name(item['list'])]
                        new_content.append(item)
                    except KeyError:
                        parent.stepChanged.emit(f'RED|   Error: Нет IP-листа "{item["list"]}" в списках IP-адресов шаблона МС.')
                        parent.stepChanged.emit(f'RED|   Error: Содержимое "{item["list"]}" не добавлено в список IP-адресов "{data["name"]}".')
                        error = 1
                else:
                    new_content.append(item)
            if not new_content:
                parent.stepChanged.emit(f'ORANGE|    Список "{data["name"]}" не импортирован так как он пуст.')
                continue

            err, result = parent.utm.add_template_nlist_items(parent.template_id, list_id, new_content)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Список IP-адресов: "{data["name"]}"]')
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка IP-адресов "{data["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'ORANGE|    Список "{data["name"]}" не импортирован так как он пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков IP-адресов.')
    else:
        parent.stepChanged.emit('GREEN|    Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".')


def import_url_lists(parent, path):
    """Импортировать списки URL на UTM"""
    parent.stepChanged.emit('BLUE|Импорт списков URL раздела "Библиотеки/Списки URL".')
        
    if not os.path.isdir(path):
        parent.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
        return
    files_list = os.listdir(path)
    if not files_list:
        parent.stepChanged.emit('GRAY|    Нет списков URL для импорта.')
        return

    if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
        return

    error = 0
    # Импортируем все списки URL без содержимого (пустые).
    parent.stepChanged.emit('LBLUE|    Импортируем списки URL без содержимого.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        content = data.pop('content')
        data.pop('last_update', None)
        if not data['attributes'] or 'threat_level' in data['attributes']:
            data['attributes'] = {'list_compile_type': 'case_sensitive'}

        err, result = parent.utm.add_template_nlist(parent.template_id, data)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Список URL "{data["name"]}" не импортирована]')
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.mc_url_lists[data['name']] = result
            parent.stepChanged.emit(f'BLACK|    Список URL "{data["name"]}" импортирован.')

    # Импортируем содержимое в уже добавленные списки URL.
    parent.stepChanged.emit('LBLUE|    Импортируем содержимое списков URL.')
    for file_name in files_list:
        json_file = os.path.join(path, file_name)
        err, data = func.read_json_file(parent, json_file)
        if err:
            continue

        data['name'] = func.get_restricted_name(data['name'])
        try:
            list_id = parent.mc_url_lists[data['name']]
        except KeyError:
            parent.stepChanged.emit(f'RED|   Error: Нет листа URL "{data["name"]}" в списках URL шаблона МС.')
            parent.stepChanged.emit(f'RED|   Error: Содержимое не добавлено в список IP-адресов "{data["name"]}".')
            error = 1
            continue
        if data['content']:
            err, result = parent.utm.add_template_nlist_items(parent.template_id, list_id, data['content'])
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result} [Список URL: "{data["name"]}"]')
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                parent.stepChanged.emit(f'BLACK|    Содержимое списка URL "{data["name"]}" обновлено. Added {result} record')
        else:
            parent.stepChanged.emit(f'GRAY|   Список URL "{data["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списков URL.')
    else:
        parent.stepChanged.emit('GREEN|    Списки URL импортированы в раздел "Библиотеки/Списки URL".')


def import_shaper_list(parent, path):
    """Импортируем список Полос пропускания раздела библиотеки"""
    json_file = os.path.join(path, 'config_shaper_list.json')
    err, data = func.read_json_file(parent, json_file)
    if err:
        return

    err, result = parent.utm.get_template_shapers_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('BLUE|Импорт списка "Полосы пропускания" в раздел "Библиотеки/Полосы пропускания".')
    error = 0

    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in shaper_list:
            parent.stepChanged.emit(f'GRAY|    Полоса пропускания "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_shaper(parent.template_id, shaper_list[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_shaper(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Полоса пропускания: "{item["name"]}"]')
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                shaper_list[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Полоса пропускания "{item["name"]}" импортирована.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Полосы пропускания".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Полосы пропускания" импортирован в раздел "Библиотеки/Полосы пропускания".')


def import_url_categories(parent, path):
    """Импортировать группы URL категорий с содержимым на UTM"""
    json_file = os.path.join(path, 'config_url_categories.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')
    error = 0
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

#    err, result = parent.utm.get_url_categories()
#    if err:
#        parent.stepChanged.emit(f'1|{result}')
#        parent.error = 1
#        return
#    url_categories = {x['name']: x['id'] for x in result}

    for item in data:
        if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                'Recommended for morphology checking', 'Recommended for virus check']:
            content = item.pop('content')
            item.pop('last_update', None)
            item.pop('guid', None)
            item['name'] = func.get_restricted_name(item['name'])
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err == 1:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Группа URL категорий "{item["name"]}" не импортирована]')
                continue
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                url_category_groups[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Группа URL категорий "{item["name"]}" импортирована.')

            for category in content:
#                try:
#                    category_url = {'category_id': url_categories[category['name']]}
#                except KeyError as err:
#                    parent.stepChanged.emit(f'4|   Ошибка! URL категория "{category["name"]}" не импортирована. Нет такой категории на UG NGFW.')
#                    error = 1
#                    continue
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, url_category_groups[item['name']], category)
                if err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       Категория "{category["name"]}" уже существует.')
                elif err2 == 1:
                    parent.stepChanged.emit(f'RED|       {result2}  [Группа категорий "{item["name"]}"]')
                    error = 1
                else:
                    parent.stepChanged.emit(f'BLACK|       Добавлена категория "{category["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп URL категорий.')
    else:
        parent.stepChanged.emit('GREEN|    Группы URL категорий импортированы в раздел "Библиотеки/Категории URL".')


def import_application_groups(parent, path):
    """Импортировать группы приложений на UTM"""
    json_file = os.path.join(path, 'config_application_groups.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт групп приложений в раздел "Библиотеки/Группы приложений".')

    err, result = parent.utm.get_l7_apps(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    l7_app_id = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'applicationgroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    parent.application_groups = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        content = item.pop('content')
        item.pop('last_update', None)
        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Группа приложений "{item["name"]}" не импортирована]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.application_groups[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Группа приложений "{item["name"]}" импортирована.')

        for app in content:
            if 'name' not in app:   # Так бывает при некорректном добавлении приложения через API
                parent.stepChanged.emit(f'bRED|       Приложение "{app}" не добавлено в группу, так как не содержит имя. [Группа приложений "{item["name"]}"]')
                continue
            try:
                app['value'] = l7_app_id[app['name']]
            except KeyError as err:
                parent.stepChanged.emit(f'RED|       Error: Приложение "{app["name"]}" не добавлено в группу. Такого приложения нет на UG NGFW. [Группа приложений "{item["name"]}"]')
                error = 1
                continue

            err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, parent.application_groups[item['name']], app) 
            if err2 == 1:
                error = 1
                parent.stepChanged.emit(f'RED|       {result2}  [Группа приложений "{item["name"]}"]')
            elif err2 == 3:
                parent.stepChanged.emit(f'GRAY|       Приложение "{app["name"]}" уже существует в группе приложений "{item["name"]}".')
            else:
                parent.stepChanged.emit(f'BLACK|       Добавлено приложение "{app["name"]}".')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте групп приложений.')
    else:
        parent.stepChanged.emit('GREEN|    Группы приложений импортированы в раздел "Библиотеки/Группы приложений".')


def import_time_restricted_lists(parent, path):
    """Импортируем содержимое календарей"""
    json_file = os.path.join(path, 'config_calendars.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт списка "Календари" в раздел "Библиотеки/Календари".')
    if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
        return

    error = 0
    for item in data:
        content = item.pop('content')
        item.pop('last_update', None)
        item['name'] = func.get_restricted_name(item['name'])
        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            error = 1
            parent.stepChanged.emit(f'RED|    {result}  [Календарь "{item["name"]}" не импортирован]')
            continue
        elif err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        else:
            parent.mc_time_restrictions[item['name']] = result
            parent.stepChanged.emit(f'BLACK|    Календарь "{item["name"]}" импортирован.')

        if content:
            for value in content:
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, parent.mc_time_restrictions[item['name']], value)
                if err2 == 1:
                    error = 1
                    parent.stepChanged.emit(f'RED|       {result2}  [Календарь: "{item["name"]}"]')
                elif err2 == 3:
                    parent.stepChanged.emit(f'GRAY|       Элемент "{value["name"]}" уже существует в календаре "{item["name"]}".')
                else:
                    parent.stepChanged.emit(f'BLACK|       Элемент "{value["name"]}" календаря "{item["name"]}" добавлен.')
        else:
            parent.stepChanged.emit(f'GRAY|       Календарь "{item["name"]}" пуст.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте списка "Календари".')
    else:
        parent.stepChanged.emit('GREEN|    Список "Календари" импортирован в раздел "Библиотеки/Календари".')


def import_notification_profiles(parent, path):
    """Импортируем список профилей оповещения"""
    json_file = os.path.join(path, 'config_notification_profiles.json')
    err, data = func.read_json_file(parent, json_file)
    if err:
        return

    parent.stepChanged.emit('BLUE|Импорт профилей оповещений в раздел "Библиотеки/Профили оповещений".')
    err, result = parent.utm.get_template_notification_profiles_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    profiles = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        if item['name'] in profiles:
            parent.stepChanged.emit(f'GRAY|    Профиль оповещения "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_notification_profile(parent.template_id, profiles[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_notification_profile(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Профиль оповещения: "{item["name"]}"]')
            elif err == 3:
                parent.stepChanged.emit(f'GRAY|    {result}')
            else:
                profiles[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Профиль оповещения "{item["name"]}" импортирован.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте профилей оповещений.')
    else:
        parent.stepChanged.emit('GREEN|    Профили оповещений импортированы в раздел "Библиотеки/Профили оповещений".')


def import_firewall_rules(parent, path):
    """Импортировать список правил межсетевого экрана"""
    parent.stepChanged.emit('BLUE|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')
    json_file = os.path.join(path, 'config_firewall_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    err, result = parent.utm.get_template_firewall_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    firewall_rules = {x['name']: x['id'] for x in result}

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    if not parent.mc_time_restrictions:
        if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
            return

    error = 0
    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item.pop('apps', None)
        item.pop('apps_negate', None)
        item['name'] = func.get_restricted_name(item['name'])
    
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['ips_profile'] = False
        item['l7_profile'] = False
        item['hip_profile'] = []
        item['src_zones'] = get_zones(parent, item['src_zones'], item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], item["name"])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.ldap_servers else []
        item['services'] = get_services(parent, item['services'], item['name'])
        item['time_restrictions'] = get_time_restrictions(parent, item['time_restrictions'], item['name'])
        
        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'GRAY|    Правило МЭ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_firewall_rule(parent.template_id, firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило МЭ: "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило МЭ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_firewall_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило МЭ: "{item["name"]}"]')
            else:
                firewall_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|   Правило МЭ "{item["name"]}" импортировано.')
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
    parent.stepChanged.emit('LBLUE|    После импорта правила NAT будут в не активном состоянии. Необходимо проверить и включить нужные.')
    error = 0

    if not parent.scenarios_rules:
        set_scenarios_rules(parent)

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    mc_gateways = {x['name']: f'{x["id"]}:{x["node_name"]}' for x in result if 'name' in x}

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    err, result = parent.utm.get_template_traffic_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    nat_rules = {x['name']: x['id'] for x in result}

    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['zone_in'] = get_zones(parent, item['zone_in'], item['name'])
        item['zone_out'] = get_zones(parent, item['zone_out'], item['name'])
        item['source_ip'] = get_ips(parent, item['source_ip'], item['name'])
        item['dest_ip'] = get_ips(parent, item['dest_ip'], item['name'])
        item['service'] = get_services(parent, item['service'], item['name'])
        item['gateway'] = mc_gateways.get(item['gateway'], item['gateway'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.ldap_servers else []
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
            
        if item['action'] == 'route':
            parent.stepChanged.emit(f'LBLUE|    Проверьте шлюз для правила ПБР "{item["name"]}". В случае отсутствия, установите вручную.')

        if item['name'] in nat_rules:
            parent.stepChanged.emit(f'GRAY|    Правило "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_traffic_rule(parent.template_id, nat_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_traffic_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                nat_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило "{item["name"]}" импортировано.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил NAT.')
    else:
        parent.stepChanged.emit('GREEN|    Правила NAT импортированы в раздел "Политики сети/NAT и маршрутизация".')


def import_shaper_rules(parent, path):
    """Импортируем список правил пропускной способности"""
    parent.stepChanged.emit('BLUE|Импорт правил пропускной способности в раздел "Политики сети/Пропускная способность".')
    json_file = os.path.join(path, 'config_shaper_rules.json')
    err, data = func.read_json_file(parent, json_file)
    if err:
        return
    error = 0

    if not parent.scenarios_rules:
        set_scenarios_rules(parent)

    if not parent.mc_zones:
        if set_mc_zones(parent):     # Устанавливаем атрибут parent.mc_zones
            return

    if not parent.mc_services:
        if set_mc_services(parent):     # Устанавливаем атрибут parent.mc_services
            return

    if not parent.mc_servicegroups:
        if set_mc_servicegroups(parent):     # Устанавливаем атрибут parent.mc_servicegroups
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    if not parent.mc_time_restrictions:
        if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
            return

    err, result = parent.utm.get_template_shapers_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_shaper_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    shaper_rules = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_l7_categories()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    parent.l7categories = {x['name']: x['id'] for x in result}

    if not parent.application_groups:
        err, result = parent.utm.get_template_nlists_list(parent.template_id, 'applicationgroup')
        if err:
            parent.stepChanged.emit(f'RED|    {result}')
            parent.error = 1
            return
        parent.application_groups = {x['name']: x['id'] for x in result}

    parent.stepChanged.emit('LBLUE|    После импорта правила пропускной способности будут в не активном состоянии. Необходимо проверить и включить нужные.')
    for item in data:
        item['name'] = func.get_restricted_name(item['name'])
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
        item['src_zones'] = get_zones(parent, item['src_zones'], item['name'])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], item['name'])
        item['src_ips'] = get_ips(parent, item['src_ips'], item['name'])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], item['name'])
        item['services'] = get_services(parent, item['services'], item['name'])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.ldap_servers else []
        item['apps'] = get_apps(parent, item['apps'], item['name'])
        item['time_restrictions'] = get_time_restrictions(parent, item['time_restrictions'], item['name'])
        try:
            item['pool'] = shaper_list[item['pool']]
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найдена полоса пропускания "{item["pool"]}". Импортируйте полосы пропускания и повторите попытку.')
            item['pool'] = 1
            error = 1

        if item['name'] in shaper_rules:
            parent.stepChanged.emit(f'GRAY|    Правило пропускной способности "{item["name"]}" уже существует.')
            err, result = parent.utm.update_template_shaper_rule(parent.template_id, shaper_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило: {item["name"]}]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило пропускной способности "{item["name"]}" updated.')
        else:
            err, result = parent.utm.add_template_shaper_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило: {item["name"]}]')
            else:
                shaper_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило пропускной способности "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил пропускной способности.')
    else:
        parent.stepChanged.emit('GREEN|    Правила пропускной способности импортированы в раздел "Политики сети/Пропускная способность".')


def import_content_rules(parent, path):
    """Импортировать список правил фильтрации контента"""
    parent.stepChanged.emit('BLUE|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')
    json_file = os.path.join(path, 'config_content_rules.json')
    err, data = func.read_json_file(parent, json_file, mode=1)
    if err:
        return

    if not parent.scenarios_rules:
        set_scenarios_rules(parent)

    err, result = parent.utm.get_template_content_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    content_rules = {x['name']: x['id'] for x in result}

    if not parent.mc_zones:     # Устанавливаем атрибут parent.mc_zones
        if set_mc_zones(parent):
            return

    if not parent.mc_iplists:
        if set_mc_iplists(parent):     # Устанавливаем атрибут parent.mc_iplists
            return

    if not parent.mc_url_lists:
        if set_mc_url_lists(parent):     # Устанавливаем атрибут parent.mc_url_lists
            return

    if not parent.mc_time_restrictions:
        if set_mc_time_restrictions(parent):     # Устанавливаем атрибут parent.mc_time_restrictions
            return

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_url_categories()
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    url_categories = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        item.pop('time_created', None)
        item.pop('time_updated', None)
        item['name'] = func.get_restricted_name(item['name'])
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones(parent, item['src_zones'], item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], item["name"])
        item['users'] = get_guids_users_and_groups(parent, item['users'], item['name']) if parent.ldap_servers else []
        item['url_categories'] = get_url_categories_id(parent, item['url_categories'], url_category_groups, url_categories, item["name"])
        item['urls'] = get_urls_id(parent, item['urls'], item["name"])
        item['time_restrictions'] = get_time_restrictions(parent, item['time_restrictions'], item['name'])
        if item['scenario_rule_id']:
            try:
                item['scenario_rule_id'] = parent.scenarios_rules[item['scenario_rule_id']]
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Правило "{item["name"]}": не найден сценарий "{err}". Загрузите сценарии и повторите попытку.')
                item['scenario_rule_id'] = False
            

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'GRAY|    Правило контентной фильтрации "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_content_rule(parent.template_id, content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|       {result}  [Правило "{item["name"]}"]')
            else:
                parent.stepChanged.emit(f'BLACK|       Правило контентной фильтрации "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_content_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'RED|    {result}  [Правило "{item["name"]}"]')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'BLACK|    Правило контентной фильтрации "{item["name"]}" добавлено.')

    if error:
        parent.error = 1
        parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте правил контентной фильтрации.')
    else:
        parent.stepChanged.emit('GREEN|    Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".')


#------------------------------------------------------------------------------------------------------------------------
def pass_function(parent, path):
    """Функция заглушка"""
    parent.stepChanged.emit(f'GRAY|Импорт раздела "{path.rpartition("/")[2]}" в настоящее время не реализован.')

import_funcs = {
    "Morphology": pass_function, # import_morphology_lists
    "Services": import_services_list,
    "ServicesGroups": import_services_groups,
    "IPAddresses": import_ip_lists,
    "Useragents": pass_function, # import_useragent_lists
    "ContentTypes": pass_function, # import_mime_lists
    "URLLists": import_url_lists,
    "TimeSets": import_time_restricted_lists,
    "BandwidthPools": import_shaper_list,
    "SCADAProfiles": pass_function, # import_scada_profiles
    "ResponcePages": pass_function, # import_templates_list
    "URLCategories": import_url_categories,
    "OverURLCategories": pass_function, # import_custom_url_category
    "Applications": pass_function, # import_application_signature
    "ApplicationProfiles": pass_function, # import_app_profiles
    "ApplicationGroups": import_application_groups,
    "Emails": pass_function, # import_email_groups,
    "Phones": pass_function, # import_phone_groups,
    "IPDSSignatures": pass_function, # import_custom_idps_signature,
    "IDPSProfiles": pass_function, # import_idps_profiles,
    "NotificationProfiles": import_notification_profiles,
    "NetflowProfiles": pass_function, # import_netflow_profiles,
    "LLDPProfiles": pass_function, # import_lldp_profiles,
    "SSLProfiles": pass_function, # import_ssl_profiles,
    "SSLForwardingProfiles": pass_function, # import_ssl_forward_profiles,
    "HIDObjects": pass_function, # import_hip_objects,
    "HIDProfiles": pass_function, # import_hip_profiles,
    "BfdProfiles": pass_function, # import_bfd_profiles,
    "UserIdAgentSyslogFilters": pass_function, # import_useridagent_syslog_filters,
    'Certificates': pass_function,
    'UserCertificateProfiles': pass_function, # import_users_certificate_profiles,
    'GeneralSettings': import_general_settings,
#    'DeviceManagement': pass_function,
#    'Administrators': pass_function,
    'Zones': import_zones,
    'Interfaces': import_interfaces,
    'Gateways': import_gateways,
    'DNS': import_dns_config,
    'DHCP': import_dhcp_subnets,
    'VRF': import_vrf,
    'WCCP': pass_function, # import_wccp_rules,
    'AuthServers': import_auth_servers,
    'AuthProfiles': pass_function, # import_auth_profiles,
    'CaptiveProfiles': pass_function, # import_captive_profiles,
    'CaptivePortal': pass_function, # import_captive_portal_rules,
    'Groups': import_local_groups,
    'Users': import_local_users,
    'TerminalServers': pass_function, # import_terminal_servers,
    'MFAProfiles': pass_function, # import_2fa_profiles,
    'UserIDagent': pass_function, # import_userid_agent,
    'BYODPolicies': pass_function, # import_byod_policy,
    'BYODDevices': pass_function,
    'Firewall': import_firewall_rules,
    'NATandRouting': import_nat_rules,
    "ICAPServers": pass_function, # import_icap_servers,
    "ReverseProxyServers": pass_function, # import_reverseproxy_servers,
    'LoadBalancing': pass_function, # import_loadbalancing_rules,
    'TrafficShaping': import_shaper_rules,
    "ContentFiltering": import_content_rules,
    "SafeBrowsing": pass_function, # import_safebrowsing_rules,
    "TunnelInspection": pass_function, # import_tunnel_inspection_rules,
    "SSLInspection": pass_function, # import_ssldecrypt_rules,
    "SSHInspection": pass_function, # import_sshdecrypt_rules,
    "IntrusionPrevention": pass_function, # import_idps_rules,
    "Scenarios": pass_function, # import_scenarios,
    "MailSecurity": pass_function, # import_mailsecurity,
    "ICAPRules": pass_function, # import_icap_rules,
    "DoSProfiles": pass_function, # import_dos_profiles,
    "DoSRules": pass_function, # import_dos_rules,
    "SCADARules": pass_function, # import_scada_rules,
    "CustomWafLayers": pass_function, # import_waf_custom_layers,
    "SystemWafRules": pass_function, # pass_function,
    "WAFprofiles": pass_function, # import_waf_profiles,
    "WebPortal": pass_function, # import_proxyportal_rules,
    "ReverseProxyRules": pass_function, # import_reverseproxy_rules,
    "ServerSecurityProfiles": pass_function, # import_vpnserver_security_profiles,
    "ClientSecurityProfiles": pass_function, # import_vpnclient_security_profiles,
    "SecurityProfiles": pass_function, # import_vpn_security_profiles,
    "VPNNetworks": pass_function, # import_vpn_networks,
    "ServerRules": pass_function, # import_vpn_server_rules,
    "ClientRules": pass_function, # import_vpn_client_rules,
    "AlertRules": pass_function, # import_notification_alert_rules,
    "SNMPSecurityProfiles": pass_function, # import_snmp_security_profiles,
    "SNMP": pass_function, # import_snmp_rules,
    "SNMPParameters": pass_function, # import_snmp_settings,
}

######################################### Служебные функции ################################################
def get_ips(parent, rule_ips, rule_name):
    """Получить UID-ы списков IP-адресов. Если список IP-адресов не существует на MC, то он пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        if ips[0] == 'geoip_code':
            new_rule_ips.append(ips)
        try:
            if ips[0] == 'list_id':
                new_rule_ips.append(['list_id', parent.mc_iplists[ips[1]]])
            elif ips[0] == 'urllist_id':
                new_rule_ips.append(['urllist_id', parent.mc_url_lists[ips[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найден список IP-адресов "{ips[1]}". Загрузите списки в библиотеку и повторите импорт.')
    return new_rule_ips


def get_zones(parent, zones, rule_name):
    """Получить UID-ы зон. Если зона не существует на MC, то она пропускается."""
    new_zones = []
    for zone in zones:
        try:
            new_zones.append(parent.mc_zones[zone])
        except KeyError as err:
            error = 1
            parent.stepChanged.emit(f'bRED|    Error! Не найдена зона {zone} для правила {rule_name}.')
    return new_zones


def get_guids_users_and_groups(parent, users, rule_name):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if not users:
        return []

    new_users = []
    for item in users:
        match item[0]:
            case 'special':
                new_users.append(item)
            case 'user':
                user_name = None
                try:
                    ldap_domain, _, user_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Не указано имя пользователя в {item}')
                if user_name:
                    try:
                        ldap_id = parent.ldap_servers[ldap_domain.lower()]
                    except KeyError:
                        parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет LDAP-коннектора для домена "{ldap_domain}"')
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                        if err:
                            parent.stepChanged.emit(f'bRED|    {result}  [Правило "{rule_name}"]')
                        elif not result:
                            parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет пользователя "{user_name}" в домене "{ldap_domain}"!')
                        else:
                            new_users.append(['user', result])
            case 'group':
                group_name = None
                try:
                    ldap_domain, _, group_name = item[1].partition("\\")
                except IndexError:
                    parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Не указано имя группы в {item}')
                if group_name:
                    try:
                        ldap_id = parent.ldap_servers[ldap_domain.lower()]
                    except KeyError:
                        parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет LDAP-коннектора для домена "{ldap_domain}"')
                    else:
                        err, result = parent.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                        if err:
                            parent.stepChanged.emit(f'bRED|    {result}  [Правило "{rule_name}"]')
                        elif not result:
                            parent.stepChanged.emit(f'NOTE|    Error [Правило "{rule_name}"]: Нет группы "{group_name}" в домене "{ldap_domain}"!')
                        else:
                            new_users.append(['group', result])
    return new_users


def get_services(parent, service_list, rule_name):
    """Получаем ID сервисов по из именам. Если сервис не найден, то он пропускается."""
    new_service_list = []
    for item in service_list:
        try:
            if item[0] == 'service':
                new_service_list.append(['service', parent.mc_services[item[1]]])
            elif item[0] == 'list_id':
                new_service_list.append(['list_id', parent.mc_servicegroups[item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило {rule_name}]: Не найден сервис "{item[1]}".')
    return new_service_list


def get_url_categories_id(parent, url_categories, mc_urlcategory_groups, mc_urlcategories, rule_name):
    """Получаем ID категорий URL и групп категорий URL. Если список не существует на MC, то он пропускается."""
    new_categories = []
    for item in url_categories:
        try:
            if item[0] == 'list_id':
                new_categories.append(['list_id', mc_urlcategory_groups[item[1]]])
            if item[0] == 'category_id':
                new_categories.append(['category_id', mc_urlcategories[item[1]]])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило {rule_name}]: Не найдена категория URL "{item[1]}". Загрузите категории URL и повторите импорт.')
    return new_categories


def get_urls_id(parent, urls, rule_name):
    """Получаем ID списков URL. Если список не существует на MC, то он пропускается."""
    new_urls = []
    for item in urls:
        try:
            new_urls.append(parent.mc_url_lists[item])
        except KeyError as err:
            parent.stepChanged.emit(f'bRED|    Error [Правило {rule_name}]: Не найден список URL "{item}". Загрузите списки URL и повторите импорт.')
    return new_urls


def get_ldap_servers(parent):
    """
    Получаем список всех активных LDAP-серверов области.
    Выдаём словарь: {"имя_домена": "id_ldap-коннектора", ...}.
    """
    parent.stepChanged.emit('BLUE|Проверяем статус LDAP-коннекторов в каталогах пользователей области.')
    err, result = parent.utm.get_usercatalog_ldap_servers()
    if err:
        return 1, result
    if not result:
        parent.stepChanged.emit('NOTE|    Нет доступных LDAP-серверов в области. Доменные пользователи не будут импортированы.')
        return 2, {}

    err, result2 = parent.utm.get_usercatalog_servers_status()
    if err:
        return 1, result2
    servers_status = {item['id']: item['status'] for item in result2}

    ldap_servers = {}
    for srv in result:
        if servers_status[srv['id']] == 'connected':
            for domain in srv['domains']:
                ldap_servers[domain.lower()] = srv['id']
            parent.stepChanged.emit(f'BLACK|    LDAP-коннектор "{srv["name"]}" - статус: "{servers_status[srv["id"]]}".')
        else:
            parent.stepChanged.emit(f'bRED|    LDAP-коннектор "{srv["name"]}" в каталогах пользователей области имеет не корректный статус: "{servers_status[srv["id"]]}".')
    if not ldap_servers:
        parent.stepChanged.emit(f'GRAY|    Нет подключённых LDAP-коннекторов в каталогах пользователей области. Доменные пользователи не будут импортированы.')
    return 0, ldap_servers


def get_apps(parent, array_apps, rule_name):
    """Определяем ID приложения или группы приложений по именам."""
    new_app_list = []
    for app in array_apps:
        if app[0] == 'ro_group':
            if app[1] == 'All':
                new_app_list.append(['ro_group', 0])
            else:
                try:
                    new_app_list.append(['ro_group', parent.l7_categories[app[1]]])
                except KeyError as err:
                    parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена категория l7 "{app[1]}".')
                    parent.stepChanged.emit(f'bRED|    Возможно нет лицензии и MC не получил список категорий l7. Установите лицензию и повторите попытку.')
        elif app[0] == 'group':
            try:
                new_app_list.append(['group', parent.application_groups[app[1]]])
            except KeyError as err:
                parent.stepChanged.emit(f'bRED|    Error! Правило "{rule_name}": Не найдена группа приложений l7 "{app[1]}".')
    return new_app_list


def get_time_restrictions(parent, time_restrictions, rule_name):
    """Получаем ID календарей шаблона по их именам. Если календарь не найден в шаблоне, то он пропускается."""
    new_schedules = []
    for name in time_restrictions:
        try:
            new_schedules.append(parent.mc_time_restrictions[name])
        except KeyError:
            parent.stepChanged.emit(f'bRED|    Error [Правило "{rule_name}"]: Не найден календарь "{name}".')
    return new_schedules


def set_scenarios_rules(parent):
    """Получаем список сценариев шаблона и устанавливаем значение атрибута parent.scenarios_rules"""
    err, result = parent.utm.get_template_scenarios_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    parent.scenarios_rules = {x['name']: x['id'] for x in result}

def set_mc_zones(parent):
    """Получаем список зон шаблона и заполняем атрибут parent.mc_zones"""
    err, result = parent.utm.get_template_zones_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.mc_zones = {x['name']: x['id'] for x in result}
    return 0

def set_mc_services(parent):
    """Получаем список сервисов шаблона и заполняем атрибут parent.mc_services"""
    err, result = parent.utm.get_template_services_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.mc_services = {x['name']: x['id'] for x in result}
    return 0

def set_mc_servicegroups(parent):
    """Получаем список групп сервисов из шаблона и заполняем атрибут parent.mc_servicegroups"""
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'servicegroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.mc_servicegroups = {x['name']: x['id'] for x in result}
    return 0

def set_mc_iplists(parent):
    """Получаем список листов IP-адресов из шаблона и заполняем атрибут parent.mc_iplists"""
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'network')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.mc_iplists = {x['name']: x['id'] for x in result}
    return 0

def set_mc_url_lists(parent):
    """Получаем список URL листов из шаблона и заполняем атрибут parent.mc_url_lists"""
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'url')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.mc_url_lists = {x['name']: x['id'] for x in result}
    return 0

def set_mc_time_restrictions(parent):
    """Получаем список календарей из шаблона и заполняем атрибут parent.mc_time_restrictions"""
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'timerestrictiongroup')
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return 1
    parent.mc_time_restrictions = {x['name']: x['id'] for x in result}
    return 0

