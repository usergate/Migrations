#!/usr/bin/python3
# Версия 2.0
# Общий класс для работы с xml-rpc
import sys
import xmlrpc.client as rpc
from xml.parsers.expat import ExpatError


class UTM:
    def __init__(self, server_ip, login, password):
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4040/rpc'
        self._auth_token = None
        self._server = None
        self.version = None
        self.server_ip = server_ip
        self.node_name = None

    def connect(self):
        """Подключиться к UTM"""
        try:
            self._server = rpc.ServerProxy(self._url, verbose=False)
            if self.get_node_status() == 'work':
                result = self._server.v2.core.login(self._login, self._password, {'origin': 'dev-script'})
                self._auth_token = result.get('auth_token')
                self.node_name =  result.get('node')
                self.version = result.get('version')
            else:
                print('Ошибка: UTM не позволяет установить соединение!')
                sys.exit(1)
        except OSError as err:
            print(f'Ошибка: {err} (Node: {self.server_ip}).')
            sys.exit(1)
        except rpc.ProtocolError as err:
            print(f'Ошибка: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).')
            sys.exit(1)
        except rpc.Fault as err:
            print(f'Ошибка: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).')
            sys.exit(1)
        return 0

    def get_node_status(self):
        """Получить статус узла"""
        result = self._server.v2.core.node.status()
        return result.get('status')

    def logout(self):
        try:
            if self._server is not None and self._auth_token is not None:
                self._server.v2.core.logout(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 104:
                print('Сессия завершилась по таймауту.')

    def ping_session(self):
        """Ping сессии"""
        try:
            result = self._server.v2.core.session.ping(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 104:
                print(f'Сессия завершилась по таймауту.')
            else:
                print(f"\tОшибка utm.ping_session: [{err.faultCode}] — {err.faultString}")

##################################### Settings #########################################
    def set_settings_param(self, param_name, param_value):
        """Изменить параметр"""
        try:
            result = self._server.v2.settings.set.param(self._auth_token, param_name, param_value)
        except rpc.Fault as err:
            return 2, f'Ошибка utm.set_settings_param: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает True

##################################### Библиотека  ######################################
    def get_nlists_list(self, list_type):
        """Получить словарь {name: id} списков URL, applicationgroup, network и т.д."""
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 5000, {})
        except rpc.Fault as err:
            print(f'\033[31m\tОшибка utm.get_nlists_list: [{err.faultCode}] — {err.faultString}\033[0m')
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_nlist(self, named_list):
        """Добавить именованный список"""
        try:
            result = self._server.v2.nlists.add(self._auth_token, named_list)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'Список: "{named_list["name"]}" уже существует'
            else:
                return 2, f'Ошибка utm.add_nlist: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def update_nlist(self, named_list_id, named_list):
        """Обновить параметры именованного списка"""
        try:
            result = self._server.v2.nlists.update(self._auth_token, named_list_id, named_list)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'Список: {named_list["name"]} - нет отличающихся параметров для изменения.'
            else:
                return 2, f'Ошибка utm.update_nlist: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def add_nlist_items(self, named_list_id, items):
        """Добавить список значений в именованный список"""
        try:
            result = self._server.v2.nlists.list.add.items(self._auth_token, named_list_id, items)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 2001:
                return 1, f'Содержимое: {item} не добавлено, так как уже существует.'
            else:
                return 2, f'Ошибка utm.add_nlist_items: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def get_services_list(self):
        """Получить список сервисов раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, {}, [])
        except rpc.Fault as err:
            print(f'\033[31m\tОшибка utm.get_services_list: [{err.faultCode}] — {err.faultString}\033[0m')
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_service(self, service):
        """Добавить список сервисов раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.add(self._auth_token, service)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'Сервис: "{service["name"]}" уже существует.'
            else:
                return 2, f'Ошибка add_service: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID сервиса

################################### Пользователи и устройства #####################################
    def get_users_list(self):
        """Получить список локальных пользователей"""
        try:
            result = self._server.v3.accounts.users.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f'\033[31m\tОшибка get_users_list: [{err.faultCode}] — {err.faultString}\033[0m')
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_user(self, user):
        """Добавить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.add(self._auth_token, user)
        except rpc.Fault as err:
            if err.faultCode == 5002:
                return 1, f'Пользователь "{user["name"]}" уже существует. Проверка параметров...'
            else:
                return 2, f'Ошибка add_user: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает GUID добавленного пользователя

####################################### Интерфейсы  #######################################
    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f'Ошибка utm.get_interfaces_list: [{err.faultCode}] — {err.faultString}')
            sys.exit(1)
        return result

    def update_interface(self, iface_id, iface):
        """Update interface"""
        try:
            result = self._server.v1.netmanager.interface.update(self._auth_token, self.node_name, iface_id, iface)
        except rpc.Fault as err:
            print("\033[33mSkipped!\033[0m")
            if err.faultCode == 1014:
                print(f'\t\033[31mАдаптер {iface["name"]}: Cannot update slave interface.\033[0m')
            elif err.faultCode == 18009:
                print(f'\t\033[31mАдаптер {iface["name"]}: IP address conflict - {iface["ipv4"]}.\033[0m')
            else:
                print(f'\t\033[31mОшибка utm.update_interface: [{err.faultCode}] — {err.faultString}\033[0m')
        else:
            print('\033[32mUpdated!\033[0m\n')

    def add_interface_vlan(self, vlan):
        """Добавить vlan интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.vlan(self._auth_token, self.node_name, vlan['name'], vlan)
        except rpc.Fault as err:
            return 2, f'Ошибка utm.add_interface_vlan: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного интерфейса

##################################### Zones ##################################################
    def get_zones_list(self):
        """Получить список зон {name: id}"""
        try:
            result = self._server.v1.netmanager.zones.list(self._auth_token)
        except rpc.Fault as err:
            print(f'\033[31m\tОшибка get_zones_list: [{err.faultCode}] — {err.faultString}\033[0m')
            sys.exit(1)
        return {x['name']: x['id'] for x in result}

    def add_zone(self, zone):
        """Добавить зону"""
        try:
            result = self._server.v1.netmanager.zone.add(self._auth_token, zone)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'Зона: "{zone["name"]}" уже существует.'
            else:
                return 2, f'Ошибка utm.add_zone: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

################### Политики сети ############################################################
    def get_firewall_rules(self):
        """Получить список {name: id} правил межсетевого экрана"""
        try:
            result = self._server.v1.firewall.rules.list(self._auth_token, 0, 5000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_firewall_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_firewall_rule(self, rule):
        """Добавить новое правило в МЭ"""
        try:
            result = self._server.v1.firewall.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 1, f'\tПравило МЭ "{rule["name"]}" не добавлено — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_firewall_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_firewall_rule(self, rule_id, rule):
        """Обновить правило МЭ"""
        try:
            result = self._server.v1.firewall.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_firewall_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_traffic_rules(self):
        """Получить список правил NAT"""
        try:
            result = self._server.v1.traffic.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_traffic_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_traffic_rule(self, rule):
        """Добавить новое правило NAT"""
        if rule['name'] in self.nat_rules.keys():
            return 1, f'\tПравило "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.traffic.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_traffic_rule: [{err.faultCode}] — {err.faultString}"
        else:
            self.nat_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_traffic_rule(self, rule):
        """Обновить правило NAT"""
        try:
            rule_id = self.nat_rules[rule['name']]
            result = self._server.v1.traffic.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_traffic_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

class UtmError(Exception): pass
