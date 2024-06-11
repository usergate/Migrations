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
# Версия 1.3
#

import os, sys, json, time
import common_func as func
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QInputDialog


class ImportAll(QThread):
    """Импортируем всю конфигурацию в шаблон MC"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, template_id, utm_vlans, utm_zones, new_vlans, ifaces):
        super().__init__()
        self.utm = utm
        self.template_id = template_id
        self.utm_vlans = utm_vlans
        self.utm_zones = utm_zones
        self.new_vlans = new_vlans
        self.ifaces = ifaces
        self.error = 0

    def run(self):
        """Импортируем всё в пакетном режиме"""
#        import_zones(self)
#        import_vlans(self)
#        import_gateways(self)
#        import_ui(self)
#        import_modules(self)
#        import_dns_servers(self)
#        import_ntp_settings(self)
#        import_static_routes(self)
#        import_services(self)
#        import_services_groups(self)
#        import_ip_lists(self)
#        import_url_lists(self)
#        import_url_categories(self)
#        import_application_groups(self)
#        import_firewall_rules(self)
#        import_content_rules(self)
        self.stepChanged.emit('6|Импорт конфигурации прошёл с ошибками!' if self.error else '5|Импорт всей конфигурации прошёл успешно.')


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
        self.node_name = node_name
        self.ngfw_ports = arguments['ngfw_ports']
        self.dhcp_settings = arguments['dhcp_settings']
        self.ngfw_vlans = arguments['ngfw_vlans']
        self.new_vlans = arguments['new_vlans']
        self.iface_settings = arguments['iface_settings']

        self.version = float(f'{self.utm.version_hight}.{self.utm.version_midle}')
        self.scenarios_rules = {}           # Устанавливается через функцию set_scenarios_rules()
        self.error = 0

    def run(self):
        """Импортируем определённый раздел конфигурации"""
#        err, self.ngfw_data = read_bin_file(self)
#        if err:
#            parent.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван!')
#            return

        for point in self.selected_points:
            current_path = os.path.join(self.selected_path, point)
            print(current_path)
            if point in import_funcs:
                import_funcs[point](self, current_path)
            else:
                self.error = 1
                self.stepChanged.emit(f'RED|Не найдена функция для импорта {point}!')

#        if write_bin_file(self, self.ngfw_data):
#            self.stepChanged.emit('iRED|Импорт конфигурации на UserGate NGFW прерван! Не удалось записать служебные данные.')
#            return

        self.stepChanged.emit('iORANGE|Импорт конфигурации прошёл с ошибками!\n' if self.error else 'iGREEN|Импорт конфигурации завершён.\n')


class ImportStaticRoutes(QThread):
    """Импортируем статические маршруты в Виртуальный маршрутизатор по умолчанию"""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, template_id, node_name):
        super().__init__()
        self.utm = utm
        self.template_id = template_id
        self.node_name = node_name
        self.error = 0

    def run(self):
        import_static_routes(self)


class ImportVlans(QThread):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    stepChanged = pyqtSignal(str)
    
    def __init__(self, utm, template_id, node_name, utm_vlans, utm_zones, new_vlans, ifaces):
        super().__init__()
        self.utm = utm
        self.template_id = template_id
        self.node_name = node_name
        self.utm_vlans = utm_vlans
        self.utm_zones = utm_zones
        self.new_vlans = new_vlans
        self.ifaces = ifaces
        self.error = 0

    def run(self):
        import_vlans(self)


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
    for item in data:
        new_services_access = []
        for service in item['services_access']:
            if service['enabled']:
                service['service_id'] = service_ids.get(service['service_id'], 'ffffff03-ffff-ffff-ffff-ffffff000001')
                new_services_access.append(service)
        item['services_access'] = new_services_access
        err, result = parent.utm.add_template_zone(parent.template_id, item)
        if err == 3:
            parent.stepChanged.emit(f'GRAY|    {result}')
        elif err == 1:
            parent.stepChanged.emit(f'RED|    {result}')
            error = 1
            parent.error = 1
        else:
            parent.stepChanged.emit(f'BLACK|    Зона "{item["name"]}" импортирована.')

    out_message = 'GREEN|    Зоны импортированы в раздел "Сеть/Зоны".'
    parent.stepChanged.emit('ORANGE|    Произошла ошибка при импорте зон.' if error else out_message)


def import_vlans(parent, path):
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    parent.stepChanged.emit('BLUE| Импорт VLAN в раздел "Сеть/Интерфейсы"')
    error = 0
    if isinstance(parent.ngfw_vlans, int):
        parent.stepChanged.emit(parent.new_vlans)
        if parent.ngfw_vlans == 1:
            parent.error = 1
        return

    err, result = parent.utm.get_template_zones_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'RED|    {result}')
        parent.error = 1
        return
    else:
        parent.utm_zones = {x['name']: x['id'] for x in result}

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
                item['zone_id'] = 0 if current_zone == "Undefined" else parent.utm_zones[current_zone]
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


def import_gateways(parent):
    """Импортируем список шлюзов"""
    parent.stepChanged.emit('0|Импорт шлюзов в раздел "Сеть/Шлюзы".')
    json_file = "data_ug/Network/Gateways/config_gateways.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта шлюзов!', '2|Нет шлюзов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_template_gateways_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
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
                    parent.stepChanged.emit(f'{err}|{result} Шлюз "{item["name"]}"')
                    error = 1
                else:
                    parent.stepChanged.emit(f'2|Шлюз "{item["name"]}" уже существует - Updated!')
            else:
                err, result = parent.utm.add_template_gateway(parent.template_id, item)
                if err:
                    parent.stepChanged.emit(f'1|{result}')
                    error = 1
                else:
                    gateways_list[item['name']] = result
                    parent.stepChanged.emit(f'2|Шлюз "{item["name"]}" добавлен.')
    if error:
        parent.error = 1
    parent.stepChanged.emit('4|Ошибка импорта шлюзов!' if error else '5|Шлюзы импортированы в раздел "Сеть/Шлюзы".')

def import_static_routes(parent):
    """Импортируем статические маршруты в Виртуальный маршрутизатор по умолчанию"""
    parent.stepChanged.emit('0|Импорт статических маршрутов в Виртуальный маршрутизатор по умолчанию.')

    json_file = "data_ug/Network/VRF/config_routers.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта статических маршрутов!', '2|Нет статических маршрутов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_template_vrf_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    virt_routers = {x['name']: x['id'] for x in result}
    error = 0    
    out_message = '5|Статические маршруты импортированы в Виртуальный маршрутизатор по умолчанию.'
    
    for item in data:
        item['node_name'] = parent.node_name
        if item['name'] in virt_routers:
            err, result = parent.utm.update_template_vrf(parent.template_id, virt_routers[item['name']], item)
            if err:
                parent.stepChanged.emit(f'1|{result}')
                error = 1
        else:
            err, result = parent.utm.add_template_vrf(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'1|{result}')
                error = 1
            else:
                parent.stepChanged.emit(f'2|Создан виртуальный маршрутизатор "{item["name"]}".')
    if not error:
        parent.stepChanged.emit('6|Добавленные маршруты не активны. Необходимо проверить маршрутизацию и включить их.')
    else:
        parent.error = 1
    parent.stepChanged.emit('4|Ошибка импорта статических маршрутов!' if error else out_message)

def import_services_list(parent):
    """Импортируем список сервисов раздела библиотеки"""
    parent.stepChanged.emit('0|Импорт списка сервисов в раздел "Библиотеки/Сервисы"')

    json_file = "data_ug/Libraries/Services/config_services.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта списка сервисов!', '2|Нет сервисов для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_template_services_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result}
    error = 0
    
    for item in data:
        if item['name'] in services_list:
            parent.stepChanged.emit(f'3|Сервис "{item["name"]}" уже существует.')
        else:
            err, result = parent.utm.add_template_service(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'{err}|{result}')
                if err == 1:
                    error = 1
                    parent.error = 1
            else:
                services_list[item['name']] = result
                parent.stepChanged.emit(f'2|Сервис "{item["name"]}" добавлен.')

    out_message = '5|Список сервисов импортирован в раздел "Библиотеки/Сервисы"'
    parent.stepChanged.emit('4|Произошла ошибка при добавлении сервисов!' if error else out_message)

def import_services_groups(parent):
    """Импортируем группы сервисов в раздел Библиотеки/Группы сервисов"""
    parent.stepChanged.emit('0|Импорт групп сервисов раздела "Библиотеки/Группы сервисов".')

    err, result = parent.utm.get_template_services_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'servicegroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    srv_groups = {x['name']: x['id'] for x in result}

    out_message = '5|Группы сервисов импортированы в раздел "Библиотеки/Группы сервисов".'
    error = 0
    
    if os.path.isdir('data_ug/Libraries/ServicesGroups'):
        files_list = os.listdir('data_ug/Libraries/ServicesGroups')
        if files_list:
            for file_name in files_list:
                json_file = f"data_ug/Libraries/ServicesGroups/{file_name}"
                err, services_group = read_json_file(json_file, '2|Ошибка импорта группы сервисов!', '2|Нет группы сервисов для импорта.')
                if err:
                    parent.stepChanged.emit(services_group)
                    parent.error = 1
                    return

                content = services_group.pop('content')
                err, result = parent.utm.add_template_nlist(parent.template_id, services_group)
                if err:
                    parent.stepChanged.emit(f'{err}|{result}')
                    if err == 1:
                        parent.stepChanged.emit(f'1|Ошибка! Группа сервисов "{services_group["name"]}" не импортирована.')
                        error = 1
                        continue
                else:
                    parent.stepChanged.emit(f'2|Добавлена группа сервисов: "{services_group["name"]}".')
                    srv_groups[services_group['name']] = result
                if content:
                    for item in content:
                        try:
                            item['value'] = services_list[item['name']]
                        except KeyError:
                            parent.stepChanged.emit(f'4|   Ошибка! Нет сервиса "{item["name"]}" в списке сервисов NGFW.')
                            parent.stepChanged.emit(f'4|   Ошибка! Сервис "{item["name"]}" не добавлен в группу сервисов "{services_group["name"]}".')
                    err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, srv_groups[services_group['name']], content)
                    if err2:
                        parent.stepChanged.emit(f'{err2}|   {result2}')
                        if err2 == 1:
                            error = 1
                    else:
                        parent.stepChanged.emit(f'2|   Содержимое группы сервисов "{services_group["name"]}" обновлено.')
                else:
                    parent.stepChanged.emit(f'2|   Список "{services_group["name"]}" пуст.')
        else:
            out_message = "2|Нет групп сервисов для импорта."
    else:
        out_message = "2|Нет групп сервисов для импорта."
    if error:
        parent.error = 1
    parent.stepChanged.emit('4|Произошла ошибка при добавлении групп сервисов!' if error else out_message)

def import_ip_lists(parent):
    """Импортируем списки IP адресов"""
    parent.stepChanged.emit('0|Импорт списков IP-адресов раздела "Библиотеки/IP-адреса".')

    if not os.path.isdir('data_ug/Libraries/IPAddresses'):
        parent.stepChanged.emit("2|Нет списков IP-адресов для импорта.")
        return

    files_list = os.listdir('data_ug/Libraries/IPAddresses')
    if not files_list:
        parent.stepChanged.emit("2|Нет списков IP-адресов для импорта.")
        return

    error = 0
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    ngfw_ip_lists = {x['name']: x['id'] for x in result}

    # Добаляем списки IP-адресов без содержимого (пустые).
    for file_name in files_list:
        json_file = f"data_ug/Libraries/IPAddresses/{file_name}"
        err, ip_list = read_json_file(json_file, '2|Ошибка импорта списка IP-адресов!', '2|Нет списка IP-адресов для импорта.')
        if err:
            parent.stepChanged.emit(ip_list)
            parent.error = 1
            return

        content = ip_list.pop('content')
        err, result = parent.utm.add_template_nlist(parent.template_id, ip_list)
        if err:
            parent.stepChanged.emit(f'{err}|{result}')
            if err == 1:
                parent.stepChanged.emit(f'1|Ошибка! Список IP-адресов "{ip_list["name"]}" не импортирован.')
                error = 1
                continue
        else:
            ngfw_ip_lists[ip_list['name']] = result
            parent.stepChanged.emit(f'2|Добавлен список IP-адресов: "{ip_list["name"]}".')

    # Добавляем содержимое в уже добавленные списки IP-адресов.
    for file_name in files_list:
        with open(f"data_ug/Libraries/IPAddresses/{file_name}", "r") as fh:
            ip_list = json.load(fh)
        content = ip_list.pop('content')
        if content:
            for item in content:
                if 'list' in item:
                    try:
                        item['list'] = ngfw_ip_lists[item['list'][1]]
                    except KeyError:
                        parent.stepChanged.emit(f'4|   Ошибка! Нет IP-листа "{item["list"][1]}" в списках IP-адресов NGFW.')
                        parent.stepChanged.emit(f'4|   Ошибка! Содержимое не добавлено в список IP-адресов "{ip_list["name"]}".')
                        error = 1
                        break
            try:
                named_list_id = ngfw_ip_lists[ip_list['name']]
            except KeyError:
                parent.stepChanged.emit(f'4|   Ошибка! Нет IP-листа "{ip_list["name"]}" в списках IP-адресов NGFW.')
                parent.stepChanged.emit(f'4|   Ошибка! Содержимое не добавлено в список IP-адресов "{ip_list["name"]}".')
                error = 1
                continue
            err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, named_list_id, content)
            if err2:
                parent.stepChanged.emit(f'{err2}|Список "{ip_list["name"]}" - {result2}')
                if err2 == 1:
                    error = 1
            else:
                parent.stepChanged.emit(f'2|Содержимое списка "{ip_list["name"]}" обновлено.')
        else:
            parent.stepChanged.emit(f'2|Список "{ip_list["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = '5|Списки IP-адресов импортированы в раздел "Библиотеки/IP-адреса".'
    parent.stepChanged.emit('4|Произошла ошибка при импорте списков IP-адресов!' if error else out_message)

def import_url_lists(parent):
    """Импортировать списки URL на UTM"""
    parent.stepChanged.emit('0|Импорт списков URL раздела "Библиотеки/Списки URL".')
        
    if not os.path.isdir('data_ug/Libraries/URLLists'):
        parent.stepChanged.emit('2|Нет списков URL для импорта.')
        return

    files_list = os.listdir('data_ug/Libraries/URLLists')
    if not files_list:
        parent.stepChanged.emit('2|Нет списков URL для импорта.')
        return

    error = 0
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'url')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    url_list = {x['name']: x['id'] for x in result}

    for file_name in files_list:
        json_file = f"data_ug/Libraries/URLLists/{file_name}"
        err, data = read_json_file(json_file, '2|Ошибка импорта списка URL!', '2|Нет списка URL для импорта.')
        if err:
            parent.stepChanged.emit(data)
            parent.error = 1
            return

        content = data.pop('content')
        err, result = parent.utm.add_template_nlist(parent.template_id, data)
        if err:
            parent.stepChanged.emit(f'{err}|{result}')
            if err == 1:
                parent.stepChanged.emit(f'1|Ошибка! Список URL "{data["name"]}" не импортирован.')
                error = 1
                continue
        else:
            url_list[data['name']] = result
            parent.stepChanged.emit(f'2|Добавлен список URL: "{data["name"]}".')

        if content:
            for item in content:
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, url_list[data['name']], item)
                if err2:
                    parent.stepChanged.emit(f'{err2}|   {result2}')
                    if err2 == 1:
                        error = 1
                else:
                    parent.stepChanged.emit(f'2|   URL "{item["value"]}" добавлен.')
        else:
            parent.stepChanged.emit(f'2|   Список "{data["name"]}" пуст.')

    if error:
        parent.error = 1
    out_message = '5|Списки URL импортированы в раздел "Библиотеки/Списки URL".'
    parent.stepChanged.emit('4|Произошла ошибка при импорте списков URL!' if error else out_message)

def import_url_categories(parent):
    """Импортировать группы URL категорий с содержимым на UTM"""
    parent.stepChanged.emit('0|Импорт групп URL категорий раздела "Библиотеки/Категории URL".')

    json_file = "data_ug/Libraries/URLCategories/config_categories_url.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта групп URL категорий!', '2|Нет групп URL категорий для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    error = 0
    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_url_categories()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    url_categories = {x['name']: x['id'] for x in result}

    for item in data:
        content = item.pop('content')
        if item['name'] not in ['Parental Control', 'Productivity', 'Safe categories', 'Threats',
                                'Recommended for morphology checking', 'Recommended for virus check']:
            err, result = parent.utm.add_template_nlist(parent.template_id, item)
            if err:
                parent.stepChanged.emit(f'{err}|{result}')
                if err == 1:
                    parent.stepChanged.emit(f'1|Ошибка! Группа URL категорий "{item["name"]}" не импортирована.')
                    error = 1
                    continue
            else:
                url_category_groups[item['name']] = result
                parent.stepChanged.emit(f'2|Группа URL категорий "{item["name"]}" добавлена.')
                
            for category in content:
                try:
                    category_url = {'category_id': url_categories[category['name']]}
                except KeyError as err:
                    parent.stepChanged.emit(f'4|   Ошибка! URL категория "{category["name"]}" не импортирована. Нет такой категории на UG NGFW.')
                    error = 1
                    continue
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, url_category_groups[item['name']], category_url)
                if err2 == 3:
                    parent.stepChanged.emit(f'3|   Категория "{category["name"]}" уже существует.')
                elif err2 == 1:
                    parent.stepChanged.emit(f'1|   {result2}')
                    error = 1
                else:
                    parent.stepChanged.emit(f'2|   Добавлена категория "{category["name"]}".')
    if error:
        parent.error = 1
    out_message = '5|Группы URL категорий импортированы в раздел "Библиотеки/Категории URL".'
    parent.stepChanged.emit('4|Произошла ошибка при импорте групп URL категорий!' if error else out_message)

def import_application_groups(parent):
    """Импортировать список "Приложения" на UTM"""
    parent.stepChanged.emit('0|Импорт групп приложений в раздел "Библиотеки/Приложения".')

    json_file = "data_ug/Libraries/Applications/config_applications.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта групп приложений!', '2|Нет групп приложений для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_l7_apps(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    l7_app_id = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'applicationgroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.error = 1
        return
    list_applicationgroups = {x['name']: x['id'] for x in result}

    error = 0
    for item in data:
        content = item.pop('content')
        err, result = parent.utm.add_template_nlist(parent.template_id, item)
        if err == 1:
            parent.stepChanged.emit(f'1|{result}')
            parent.stepChanged.emit(f'1|Ошибка! Группа приложений "{item["name"]}" не импортирована.')
            error = 1
            continue
        elif err == 3:
            parent.stepChanged.emit(f'3|Группа приложений "{item["name"]}" уже существует.')
        else:
            list_applicationgroups[item['name']] = result
            parent.stepChanged.emit(f'2|Группа приложений "{item["name"]}" добавлена.')

        for app in content:
            app_name = app['value']
            if parent.utm.version_hight >= 7 and parent.utm.version_midle >= 1:
                try:
                    app['value'] = l7_app_id[app_name]
                except KeyError as err:
                    parent.stepChanged.emit(f'4|   Ошибка! Приложение "{app_name}" не импортировано. Такого приложения нет на UG NGFW.')
                    error = 1
                    continue
                err2, result2 = parent.utm.add_template_nlist_item(parent.template_id, list_applicationgroups[item['name']], app)
            else:
                new_content = []
                try:
                    new_content.append({'value': l7_app_id[app_name]})
                except KeyError as err:
                    parent.stepChanged.emit(f'4|   Ошибка! Приложение "{app_name}" не импортировано. Такого приложения нет на UG NGFW.')
                    error = 1
                    continue
                err2, result2 = parent.utm.add_template_nlist_items(parent.template_id, list_applicationgroups[item['name']], new_content)
 
            if err2 == 1:
                error = 1
                parent.stepChanged.emit(f'1|   {result2}')
            elif err2 == 3:
                parent.stepChanged.emit(f'3|   Приложение "{app_name}" уже существует.')
            else:
                parent.stepChanged.emit(f'2|   Добавлено приложение "{app_name}".')

    if error:
        parent.error = 1
    out_message = '5|Группы приложений импортированы в раздел "Библиотеки/Приложения".'
    parent.stepChanged.emit('4|Произошла ошибка при импорте групп приложений!' if error else out_message)

def import_firewall_rules(parent):
    """Импортировать список правил межсетевого экрана"""
    parent.stepChanged.emit('0|Импорт правил межсетевого экрана в раздел "Политики сети/Межсетевой экран".')

    json_file = "data_ug/NetworkPolicies/Firewall/config_firewall_rules.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта правил межсетевого экрана!', '2|Нет правил межсетевого экрана для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_template_firewall_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    firewall_rules = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_zones_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    zones_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_services_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    services_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'servicegroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    servicegroups_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    ips_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_l7_categories()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    l7categories = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'applicationgroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    applicationgroup = {x['name']: x['id'] for x in result}

    error = 0
    err, ldap_servers = get_ldap_servers(parent)
    if err:
        parent.stepChanged.emit(f'{err}|{ldap_servers}')
        error = 1
        ldap_servers = 0

    for item in data:
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones(parent, item['src_zones'], zones_list, item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], zones_list, item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], ips_list, item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], ips_list, item["name"])
        item['users'] = get_guids_users_and_groups(parent, item['users'], ldap_servers, item['name']) if ldap_servers else []
        for service in item['services']:
            try:
                service[1] = services_list[service[1]] if service[0] == 'service' else servicegroups_list[service[1]]
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найден сервис {service} для правила {item["name"]}.')
        for app in item['apps']:
            try:
                app[1] = l7categories[app[1]] if app[0] == 'ro_group' else applicationgroup[app[1]]
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найдена группа приложений {err} для правила "{item["name"]}". Загрузите группы приложений и повторите попытку.')
        
#        parent.set_time_restrictions(item)
        if item['name'] in firewall_rules:
            parent.stepChanged.emit(f'2|Правило МЭ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_firewall_rule(parent.template_id, firewall_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|Правило "{item["name"]}" не обновлено!\n    {result}')
            else:
                parent.stepChanged.emit(f'2|   Правило МЭ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_firewall_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|Правило "{item["name"]}" не импортировано!\n    {result}')
            else:
                firewall_rules[item['name']] = result
                parent.stepChanged.emit(f'2|   Правило МЭ "{item["name"]}" добавлено.')
    if error:
        parent.error = 1
    out_message = '5|Правила межсетевого экрана импортированы в раздел "Политики сети/Межсетевой экран".'
    parent.stepChanged.emit('4|Произошла ошибка при импорте правил межсетевого экрана!' if error else out_message)

def import_content_rules(parent):
    """Импортировать список правил фильтрации контента"""
    parent.stepChanged.emit('0|Импорт правил фильтрации контента в раздел "Политики безопасности/Фильтрация контента".')

    json_file = "data_ug/SecurityPolicies/ContentFiltering/config_content_rules.json"
    err, data = read_json_file(json_file, '2|Ошибка импорта правил фильтрации контента!', '2|Нет правил фильтрации контента для импорта.')
    if err:
        parent.stepChanged.emit(data)
        parent.error = 1
        return

    err, result = parent.utm.get_template_content_rules(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    content_rules = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_zones_list(parent.template_id)
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил межсетевого экрана прерван!')
        parent.error = 1
        return
    zones_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'network')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    ips_list = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'urlcategorygroup')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    url_category_groups = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_url_categories()
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    url_categories = {x['name']: x['id'] for x in result}

    err, result = parent.utm.get_template_nlists_list(parent.template_id, 'url')
    if err:
        parent.stepChanged.emit(f'1|{result}')
        parent.stepChanged.emit('1|Импорт правил фильтрации контента прерван!')
        parent.error = 1
        return
    url_list = {x['name']: x['id'] for x in result}

    error = 0
    err, ldap_servers = get_ldap_servers(parent)
    if err:
        parent.stepChanged.emit(f'{err}|{ldap_servers}')
        error = 1
        ldap_servers = 0

    for item in data:
        item['position'] = 'last'
        item['position_layer'] = 'pre'
        item['src_zones'] = get_zones(parent, item['src_zones'], zones_list, item["name"])
        item['dst_zones'] = get_zones(parent, item['dst_zones'], zones_list, item["name"])
        item['src_ips'] = get_ips(parent, item['src_ips'], ips_list, item["name"])
        item['dst_ips'] = get_ips(parent, item['dst_ips'], ips_list, item["name"])
        item['users'] = get_guids_users_and_groups(parent, item['users'], ldap_servers, item["name"]) if ldap_servers else []

        for x in item['url_categories']:
            try:
                x[1] = url_category_groups[x[1]] if x[0] == 'list_id' else url_categories[x[1]]
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найдена группа URL-категорий {err} для правила "{item["name"]}". Загрузите ктегории URL и повторите попытку.')

        url_oids = []
        for url_name in item['urls']:
            try:
                url_oids.append(url_list[url_name])
            except KeyError as err:
                error = 1
                parent.stepChanged.emit(f'1|Error! Не найден URL {err} для правила "{item["name"]}".')
        item['urls'] = url_oids
#        parent.set_time_restrictions(item)

        if item['name'] in content_rules:
            parent.stepChanged.emit(f'2|Правило КФ "{item["name"]}" уже существует.')
            item.pop('position', None)
            err, result = parent.utm.update_template_content_rule(parent.template_id, content_rules[item['name']], item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|Правило "{item["name"]}" не обновлено!\n    {result}')
            else:
                parent.stepChanged.emit(f'2|   Правило КФ "{item["name"]}" обновлено.')
        else:
            err, result = parent.utm.add_template_content_rule(parent.template_id, item)
            if err:
                error = 1
                parent.stepChanged.emit(f'1|Правило "{item["name"]}" не импортировано!\n    {result}')
            else:
                content_rules[item['name']] = result
                parent.stepChanged.emit(f'2|   Правило КФ "{item["name"]}" добавлено.')

    if error:
        parent.error = 1
    out_message = '5|Правила контентной фильтрации импортированы в раздел "Политики безопасности/Фильтрация контента".'
    parent.stepChanged.emit('4|Произошла ошибка при импорте правил контентной фильтрации!' if error else out_message)


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
    "TimeSets": pass_function, # import_time_restricted_lists
    "BandwidthPools": pass_function, # import_shaper_list
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
    "NotificationProfiles": pass_function, # import_notification_profiles,
    "NetflowProfiles": pass_function, # import_netflow_profiles,
    "LLDPProfiles": pass_function, # import_lldp_profiles,
    "SSLProfiles": pass_function, # import_ssl_profiles,
    "SSLForwardingProfiles": pass_function, # import_ssl_forward_profiles,
    "HIDObjects": pass_function, # import_hip_objects,
    "HIDProfiles": pass_function, # import_hip_profiles,
    "BfdProfiles": pass_function, # import_bfd_profiles,
    "UserIdAgentSyslogFilters": pass_function, # import_useridagent_syslog_filters,
    'Zones': import_zones,
    'Interfaces': import_vlans,
    'Gateways': import_gateways,
    'AuthServers': pass_function, # import_auth_servers,
    'AuthProfiles': pass_function, # import_auth_profiles,
    'CaptiveProfiles': pass_function, # import_captive_profiles,
    'CaptivePortal': pass_function, # import_captive_portal_rules,
    'Groups': pass_function, # import_local_groups,
    'Users': pass_function, # import_local_users,
    'TerminalServers': pass_function, # import_terminal_servers,
    'MFAProfiles': pass_function, # import_2fa_profiles,
    'UserIDagent': pass_function, # import_userid_agent,
    'BYODPolicies': pass_function, # import_byod_policy,
    'BYODDevices': pass_function,
    'Certificates': pass_function,
    'UserCertificateProfiles': pass_function, # import_users_certificate_profiles,
    'GeneralSettings': import_general_settings,
#    'DeviceManagement': pass_function,
#    'Administrators': pass_function,
    'DNS': import_dns_config,
    'DHCP': pass_function, # import_dhcp_subnets,
    'VRF': pass_function, # import_vrf,
    'WCCP': pass_function, # import_wccp_rules,
    'Routes': pass_function,
    'OSPF': pass_function,
    'BGP': pass_function,
    'Firewall': import_firewall_rules,
    'NATandRouting': pass_function, # import_nat_rules,
    "ICAPServers": pass_function, # import_icap_servers,
    "ReverseProxyServers": pass_function, # import_reverseproxy_servers,
    'LoadBalancing': pass_function, # import_loadbalancing_rules,
    'TrafficShaping': pass_function, # import_shaper_rules,
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

############################# Служебные функции #####################################

def get_ips(parent, rule_ips, utm_ips, rule_name):
    """Получить UID-ы списков IP-адресов. Если список IP-адресов не существует на NGFW, то он пропускается."""
    new_rule_ips = []
    for ips in rule_ips:
        try:
            new_rule_ips.append(['list_id', utm_ips[ips[1]]])
        except KeyError as err:
            error = 1
            parent.stepChanged.emit(f'1|Error! Не найден список IP-адресов {ips} для правила {rule_name}.')
    return new_rule_ips

def get_zones(parent, zones, zones_list, rule_name):
    """Получить UID-ы зон. Если зона не существует на NGFW, то она пропускается."""
    new_zones = []
    for i, zone in enumerate(zones):
        try:
            new_zones.append(zones_list[zone])
        except KeyError as err:
            error = 1
            parent.stepChanged.emit(f'1|Error! Не найдена зона {zone} для правила {rule_name}.')
    return new_zones

def get_guids_users_and_groups(parent, users, ldap_servers, rule_name):
    """
    Получить GUID-ы групп и пользователей по их именам.
    Заменяет имена локальных и доменных пользователей и групп на GUID-ы.
    """
    if not users:
        return []

    new_users = []
    for x in users:
        if x[0] == 'user' and x[1]:
            ldap_domain, _, user_name = x[1].partition("\\")
            if user_name:
                try:
                    ldap_id = ldap_servers[ldap_domain.lower()]
                except KeyError:
                    parent.stepChanged.emit(f'4|   Ошибка! Правило "{rule_name}". Нет LDAP-коннектора для домена "{ldap_domain}"')
                else:
                    err, result = parent.utm.get_usercatalog_ldap_user_guid(ldap_id, user_name)
                    if err:
                        parent.stepChanged.emit(f'1|{result}')
                    elif not result:
                        parent.stepChanged.emit(f'4|   Ошибка! Правило "{rule_name}". Нет пользователя "{user_name}" в домене "{ldap_domain}"!')
                    else:
                        x[1] = result
                        new_users.append(x)

        elif x[0] == 'group' and x[1]:
            ldap_domain, _, group_name = x[1].partition("\\")
            if group_name:
                try:
                    ldap_id = ldap_servers[ldap_domain.lower()]
                except KeyError:
                    parent.stepChanged.emit(f'4|   Ошибка! Правило "{rule_name}". Нет LDAP-коннектора для домена "{ldap_domain}"')
                else:
                    err, result = parent.utm.get_usercatalog_ldap_group_guid(ldap_id, group_name)
                    if err:
                        parent.stepChanged.emit(f'1|{result}')
                    elif not result:
                        parent.stepChanged.emit(f'4|   Ошибка! Правило "{rule_name}". Нет группы "{group_name}" в домене "{ldap_domain}"!')
                    else:
                        x[1] = result
                        new_users.append(x)
        elif x[0] == 'special' and x[1]:
            new_users.append(x)
    return new_users

def get_ldap_servers(parent):
    """
    Получаем список всех активных LDAP-серверов области.
    Выдаём словарь: {"имя_домена": "id_ldap-коннектора", ...}.
    """
    err, result = parent.utm.get_usercatalog_ldap_servers()
    if err:
        return 1, result
    if not result:
        return 4, 'Доменные пользователи не будут импортированы. Нет доступных LDAP-серверов в области.'

    ldap_servers = {}
    for srv in result:
        for domain in srv['domains']:
            ldap_servers[domain.lower()] = srv['id']
    return 0, ldap_servers

def read_json_file(json_file, err_file_not_found, err_data):
    try:
        with open(json_file, "r") as fh:
            data = json.load(fh)
    except FileNotFoundError as err:
        return 1, f'{err_file_not_found} Не найден файл "{json_file}" с сохранённой конфигурацией!'
    except ValueError as err:
        return 1, f'1|Error: JSONDecodeError - {err} "{json_file}".'

    if not data:
        return 1, f'{err_data} Файл "{json_file}" пуст.'
    return 0, data

def input_dialog_nodename():
    """Окно выбора node_name кластера"""
    nodes = ['node_1', 'node_2', 'node_3', 'node_4']
    node_name, ok = QInputDialog.getItem(None, 'Выбор идентификатора узла кластера', 'Выберите идентификатор узла', nodes)
    if ok:
        return node_name
    else:
        return False

