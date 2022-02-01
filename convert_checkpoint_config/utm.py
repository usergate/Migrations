#!/usr/bin/python3
# Версия 1.0
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

##################################### Библиотека  ######################################
    def get_url_category(self):
        """Получить список {name: id} категорий URL"""
        try:
            result = self._server.v2.core.get.categories()
        except rpc.Fault as err:
            print(f"Ошибка get_url_category: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result}

    def get_l7_apps(self):
        """Получить список {name: id} приложений l7"""
        try:
            result = self._server.v2.core.get.l7apps(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            print(f"Ошибка get_l7_apps: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def get_l7_categories(self):
        """Получить список {name: id} категорий приложений l7"""
        try:
            result = self._server.v2.core.get.l7categories(self._auth_token, 0, 10000, '')
        except rpc.Fault as err:
            print(f"Ошибка get_l7_categories: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def get_nlists_list(self, list_type):
        """Получить словарь {name: id} списков URL, applicationgroup, network и т.д."""
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 5000, {})
        except rpc.Fault as err:
            print(f"Ошибка get_nlists_list: [{err.faultCode}] — {err.faultString}")
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
                return 1, f'\tСписок: "{named_list["name"]}" уже существует'
            else:
                return 2, f"\tОшибка utm.add_nlist: [{err.faultCode}] — {err.faultString}"
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
                return 1, f"\tСписок: {named_list['name']} - нет отличающихся параметров для изменения."
            else:
                return 2, f"\tОшибка utm.update_nlist: [{err.faultCode}] — {err.faultString}"
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
                return 1, f"\tСодержимое: {item} не добавлено, так как уже существует."
            else:
                return 2, f'\tОшибка utm.add_nlist_items: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def get_services_list(self):
        """Получить список сервисов раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, {}, [])
        except rpc.Fault as err:
            print(f"Ошибка get_services_list: [{err.faultCode}] — {err.faultString}")
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
                return 1, f"\tСервис: '{service['name']}' уже существует."
            else:
                return 2, f"Ошибка add_service: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID сервиса

################################### Пользователи и устройства #####################################
    def get_groups_list(self):
        """Получить список локальных групп"""
        try:
            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_groups_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_group(self, group):
        """Добавить локальную группу"""
        try:
            result = self._server.v3.accounts.group.add(self._auth_token, group)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tГруппа '{group['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"\tОшибка utm.add_group: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает GUID добавленной группы

    def update_group(self, group):
        """Обновить локальную группу"""
        try:
            result = self._server.v3.accounts.group.update(self._auth_token, group['guid'], group)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_group: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_group_users(self, group_guid):
        """Получить список пользователей в группе"""
        try:
            result = self._server.v3.accounts.group.users.list(self._auth_token, group_guid, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_group_users: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def get_users_list(self):
        """Получить список локальных пользователей"""
        try:
            result = self._server.v3.accounts.users.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка get_users_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_user(self, user):
        """Добавить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.add(self._auth_token, user)
        except rpc.Fault as err:
            if err.faultCode == 5002:
                return 1, f"\tПользователь '{user['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"\tОшибка add_user: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает GUID добавленного пользователя

    def update_user(self, user):
        """Обновить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.update(self._auth_token, user['guid'], user)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_user: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def add_user_in_group(self, group_guid, user_guid):
        """Добавить локального пользователя в локальную группу"""
        try:
            result = self._server.v3.accounts.group.user.add(self._auth_token, group_guid, user_guid)
        except rpc.Fault as err:
            return 2, f"\t\tОшибка utm.add_user: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает true

    def get_ldap_server_id(self, domain):
        """Получить ID сервера авторизации LDAP по имени домена"""
        try:
            result = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.get_ldap_server_id: [{err.faultCode}] — {err.faultString}."
        for item in result:
            if domain in item['domains']:
                return 0, item['id']
        return 2, f"\tНет LDAP-коннектора для домена {domain}."

    def get_ldap_user_guid(self, ldap_domain, user_name):
        """Получить GUID пользователя LDAP по его имени"""
        users = []
        try:
            result = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
            for x in result:
                domains = [y.lower() for y in x['domains']]
                if x['enabled'] and ldap_domain.lower() in domains:
                    users = self._server.v1.ldap.users.list(self._auth_token, x['id'], user_name)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.get_ldap_user_guid: [{err.faultCode}] — {err.faultString}\n\tПроверьте настройки LDAP-коннектора!"
        return 0, users[0]['guid'] if users else 0

    def get_ldap_group_guid(self, ldap_domain, group_name):
        """Получить GUID группы LDAP по её имени"""
        groups = []
        try:
            result = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
            for x in result:
                domains = [y.lower() for y in x['domains']]
                if x['enabled'] and ldap_domain.lower() in domains:
                    groups = self._server.v1.ldap.groups.list(self._auth_token, x['id'], group_name)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.get_ldap_group_guid: [{err.faultCode}] — {err.faultString}\n\tПроверьте настройки LDAP-коннектора!"
        return 0, groups[0]['guid'] if groups else 0

####################################### Интерфейсы  #######################################
    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка utm.get_interfaces_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def update_interface(self, iface_id, iface):
        """Update interface"""
        try:
            if iface['kind'] == 'vpn':
                result = self._server.v1.netmanager.interface.update(self._auth_token, 'cluster', iface_id, iface)
            else:
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
            print('\033[32mUpdated!\033[0m')

    def add_interface_vlan(self, vlan):
        """Добавить vlan интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.vlan(self._auth_token, self.node_name, vlan['name'], vlan)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_interface_vlan: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного интерфейса

######################################## Маршруты  ########################################
    def get_routers_list(self):
        """Получить список маршрутов"""
        try:
            result = self._server.v1.netmanager.virtualrouters.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка utm.get_routers_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def add_routers_rule(self, rule):
        """Добавить статический маршрут"""
        try:
            result = self._server.v1.netmanager.virtualrouter.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 1015:
                return 2, f'\tВ виртуальном маршрутизаторе "{rule["name"]}" указан несуществующий порт: {rule["interfaces"]}.'
            elif err.faultCode == 1016:
                return 2, f'\tВ виртуальном маршрутизаторе "{rule["name"]}" указан порт использующийся в другом маршрутизаторе: {rule["interfaces"]}.'
            else:
                return 2, f"\tОшибка utm.add_routers_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_routers_rule(self, rule_id, rule):
        """Изменить статический маршрут"""
        try:
            result = self._server.v1.netmanager.virtualrouter.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            if err.faultCode == 1020:
                return 2, f'\tВ виртуальном маршрутизаторе "{rule["name"]}" указан порт использующийся в другом маршрутизаторе: {rule["interfaces"]} [{err.faultString}]'
            return 2, f"\tОшибка utm.update_routers_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

##################################### Network #####################################
    def get_zones_list(self):
        """Получить список зон {name: id}"""
        try:
            result = self._server.v1.netmanager.zones.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_zones_list: [{err.faultCode}] — {err.faultString}")
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
                return 1, f"\tЗона: {zone['name']} уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка utm.add_zone: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def update_zone(self, zone_id, zone):
        """Обновить параметры зоны"""
        try:
            result = self._server.v1.netmanager.zone.update(self._auth_token, zone_id, zone)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tЗона: {zone['name']} - нет отличающихся параметров для изменения."
            else:
                return 2, f"Ошибка utm.update_zone: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_gateway(self, gateway):
        """Добавить новый шлюз"""
        try:
            result = self._server.v1.netmanager.gateway.add(self._auth_token, self.node_name, gateway)
        except rpc.Fault as err:
            if err.faultCode == 1019:
                return 2, f'\tШлюз "{gateway["name"]}" не импортирован! Duplicate IP.'
            else:
                return 2, f"\tОшибка utm.add_gateway: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_gateway(self, gateway_id, gateway):
        """Обновить шлюз"""
        try:
            result = self._server.v1.netmanager.gateway.update(self._auth_token, self.node_name, gateway_id, gateway)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_gateway: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

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

    def get_content_rules(self):
        """Получить список правил фильтрации контента"""
        try:
            result = self._server.v1.content.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_content_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return {x['name']: x['id'] for x in result['items']}

    def add_content_rule(self, rule):
        """Добавить новое правило фильтрации контента"""
        try:
            result = self._server.v1.content.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_content_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_content_rule(self, rule_id, rule):
        """Обновить сценарий"""
        try:
            result = self._server.v1.content.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_content_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_reverseproxy_servers(self):
        """Получить список серверов reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_reverseproxy_servers: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_reverseproxy_servers(self, profile):
        """Добавить новый сервер reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_reverseproxy_servers: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_reverseproxy_servers(self, profile_id, profile):
        """Обновить сервер reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_reverseproxy_servers: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_reverseproxy_rules(self):
        """Получить список правил reverse-прокси"""
        try:
            if self.version.startswith('5'):
                result = self._server.v1.reverseproxy.rules.list(self._auth_token, {})
                return len(result), result
            else:
                result = self._server.v1.reverseproxy.rules.list(self._auth_token, 0, 100, {})
                return len(result['items']), result['items']
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_reverseproxy_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)

    def add_reverseproxy_rule(self, rule):
        """Добавить новое правило reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_reverseproxy_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_reverseproxy_rule(self, rule_id, rule):
        """Обновить правило reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_reverseproxy_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

class UtmError(Exception): pass
