#!/usr/bin/python3
# Версия 1.6
# Общий класс для работы с xml-rpc Management Center
#
# Коды возврата:
# 0 - Успешно
# 1 - Ошибка выполнения
# 2, 3 и далее - Информационные сообщения
#-----------------------------------------------------------------------------------------------------------
import sys
import xmlrpc.client as rpc
from xml.parsers.expat import ExpatError


class McXmlRpc:
    def __init__(self, server_ip, login, password):
        self.server_ip = server_ip
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4041/rpc'
        self._auth_token = None
        self._server = None
        self._logan_auth_token = None
        self._logan_session_mc = None
        self._real_admin_id = None
        self.node_name = None
        self.version = None
        self.version_hight = None
        self.version_midle = None
        self.version_low = None
        self.version_other = None

    def connect(self):
        """Подключиться к UTM"""
        try:
            self._server = rpc.ServerProxy(self._url, verbose=False, allow_none=True)
        except OSError as err:
            return 1, f'Error mclib.connect: {err} (Node: {self.server_ip}).'
        except rpc.ProtocolError as err:
            return 1, f'Error mclib.connect: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).'
        except rpc.Fault as err:
            return 1, f'Error mclib.connect: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).'
        return self.login()

    def login(self):
        try:
            err, status = self.get_node_status()
            if status == 'work':
                result = self._server.v1.core.login(self._login, self._password, {'origin': 'dev-script'})
            else:
                return 1, f'Error mclib.login: MC не позволяет установить соединение! Status: "{status}".'
        except OSError as err:
            return 1, f'Error mclib.login: {err} (Node: {self.server_ip}).'
        except rpc.ProtocolError as err:
            return 1, f'Error mclib.login: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).'
        except rpc.Fault as err:
            return 1, f'Error mclib.login: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).'
        else:
            self._auth_token = result.get('auth_token')
            self._logan_auth_token = result.get('logan_auth_token')
            self._logan_session_mc = result.get('logan_session_mc')
            self._real_admin_id = result.get('real_admin_id')
            self.node_name =  result.get('node', None)
            err, result = self.get_product_info()
            if err:
                return 1, result
            self.version = result.get('version')
            tmp = self.version.split(".")
            self.version_hight = int(tmp[0])
            self.version_midle = int(tmp[1])
            self.version_low = int(tmp[2])
            self.version_other = tmp[3]
            return 0, True

    def get_node_status(self):
        """Получить статус узла"""
        result = self._server.v1.core.node.status()
        return 0, result.get('status')

    def logout(self):
        if self._server and self._auth_token:
            if not self.ping_session()[0]:
                self._server.v1.core.logout(self._auth_token)
        return 0, True

    def ping_session(self):
        """Ping сессии"""
        try:
            result = self._server.v1.core.session.ping(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 4:
                return 2, f'Сессия завершилась по таймауту.'
            else:
                return 1, f'Ошибка mclib.ping_session: [{err.faultCode}] — {err.faultString}'
        return 0, result # Возвращает True

    def get_product_info(self):
        """Получить версию продукта и его название"""
        try:
            result = self._server.v1.core.product.info(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 25:
                return 0, {'name': 'cc_core', 'version': '7.0.1.XXX'}
            else:
                return 1, f'Error mclib.get_product_info: [{err.faultCode}] — {err.faultString}'
        return 0, result # 

############## Device API module, выполняются только под администраторами МС (Admin/system)##################
    def get_realms_list(self):
        """Получить список областей"""
        try:
            result = self._server.v1.core.realms.list(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получения списка областей [Error mclib.get_realms_list: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_realms_list: [{err.faultCode}] — {err.faultString}'
        return 0, result

######## NGFW Template API module, выполняются только под администраторами областей (realm_admin/SF)#########
    def get_device_templates(self):
        """Получить список шаблонов устройств области"""
        try:
            result = self._server.v1.ccdevices.templates.list(self._auth_token, 0, 1000, {}, [])
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получения списка шаблонов [Error mclib.get_device_templates: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_device_templates: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список словарей.

    def fetch_device_template(self, template_id):
        """Получить шаблон области по id"""
        try:
            result = self._server.v1.ccdevices.template.fetch(self._auth_token, template_id)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получения списка шаблонов [Error mclib.fetch_device_template: {err.faultString}].'
            else:
                return 1, f'Error mclib.fetch_device_template: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает словарь.

    def add_device_template(self, template):
        """Создать новый шаблон устройства в области. Принимает структуру: {'name': ИМЯ_ШАБЛОНА, 'description': ОПИСАНИЕ}"""
        try:
            result = self._server.v1.ccdevices.template.add(self._auth_token, template)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на добавление шаблона устройства [Error mclib.add_device_template: {err.faultString}].'
            elif err.faultCode == 9:
                return 2, f'Шаблон с таким именем уже существует [Error mclib.add_device_template: {err.faultString}].'
            else:
                return 1, f'Error mclib.add_device_template: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID созданного шаблона.

######## Settings ###########################################################################################
    def set_template_settings(self, template_id, param):
        """Set NGFW general setting value"""
        try:
            result = self._server.v1.ccgeneralsettings.setting.set(self._auth_token, template_id, param)
        except rpc.Fault as err:
            return 1, f'Error mclib.set_template_settings: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает True

    def get_template_certificates_list(self, template_id):
        """Получить список сертификатов шаблона"""
        try:
            result = self._server.v1.cccertificates.certificates.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_certificates_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']  # Возвращает список

######## Настройки шлюзов шаблона #############################################################################
    def get_template_gateways_list(self, template_id):
        """Получить список шлюзов шаблона"""
        try:
            result = self._server.v1.ccnetmanager.gateways.list(self._auth_token, template_id, 0, 100,  {}, [])
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 1, f'Нет прав на получение списка шлюзов шаблона [Error mclib.get_template_gateways_list: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_template_gateways_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список шлюзов

    def add_template_gateway(self, template_id, gateway):
        """Добавить новый шлюз в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.gateway.add(self._auth_token, template_id, gateway)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 1, f'Нет прав на получение списка шлюзов шаблона [Error utm.add_template_gateway: {err.faultString}].'
            else:
                return 1, f'Error mclib.add_template_gateway: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного шлюза

    def update_template_gateway(self, template_id, gateway_id, gateway):
        """Обновить шлюз в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.gateway.update(self._auth_token, template_id, gateway_id, gateway)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 1, f'Нет прав на update шлюза в шаблоне [Error utm.update_template_gateway: {err.faultString}].'
            elif err.faultCode == 7:
                return 4, f'Не найден шлюз "{gateway["name"]}" для обновления в шаблоне [Error utm.update_template_gateway: {err.faultString}].'
            else:
                return 1, f'Error mclib.update_template_gateway: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def delete_template_gateway(self, template_id, gateway_id):
        """Удалить шлюз в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.gateway.delete(self._auth_token, template_id, gateway_id)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 1, f'Нет прав на удаление шлюза в шаблоне [Error utm.delete_template_gateway: {err.faultString}].'
            elif err.faultCode == 7:
                return 4, f'Не найден шлюз для удаления в шаблоне [Error utm.delete_template_gateway: {err.faultString}].'
            else:
                return 1, f'Error mclib.delete_template_gateway: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

##################################### DNS ######################################
    def get_template_dns_servers(self, template_id):
        """Получить список системных DNS-серверов шаблона"""
        try:
            result = self._server.v1.ccdns.custom.dnses.list(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_dns_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список структур: [{'dns': 'ip_address', 'id': 'id'}, ...]

    def add_template_dns_server(self, template_id, dns_server):
        """Добавить системный DNS-server в шаблон"""
        try:
            result = self._server.v1.ccdns.custom.dns.add(self._auth_token, template_id, dns_server)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'DNS server {dns_server["dns"]} уже существует.'
            else:
                return 1, f'Error mclib.add_template_dns_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID созданного объекта.

    def get_template_dns_rules(self, template_id):
        """Получить список правил DNS шаблона"""
        try:
            result = self._server.v1.ccdns.rules.list(self._auth_token, template_id, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_dns_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список NgfwDnsRuleInfo

    def add_template_dns_rule(self, template_id, dns_rule):
        """Добавить правило DNS в шаблон"""
        try:
            result = self._server.v1.ccdns.rule.add(self._auth_token, template_id, dns_rule)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Правило DNS {dns_rule["name"]} уже существует.'
            else:
                return 1, f'Error mclib.add_template_dns_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID созданного объекта.

    def get_template_dns_static_records(self, template_id):
        """Получить список статических записей DNS шаблона"""
        try:
            result = self._server.v1.ccdns.static.records.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_dns_static_records: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список NgfwStaticDnsRecordInfo

    def add_template_dns_static_record(self, template_id, dns_record):
        """Добавить статическую запись DNS в шаблон"""
        try:
            result = self._server.v1.ccdns.static.record.add(self._auth_token, template_id, dns_record)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Статическая запись DNS "{dns_record["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_dns_static_record: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID созданного объекта.

########################## VPF  #############################################################################
    def get_template_vrf_list(self, template_id):
        """Получить список VRFs шаблона со всей конфигурацией"""
        try:
            result = self._server.v1.ccnetmanager.virtualrouters.list(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_routers_list: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает список NgfwVirtualRouterInfo

    def add_template_vrf(self, template_id, vrf_info):
        """Добавить виртуальный маршрутизатор в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.virtualrouter.add(self._auth_token, template_id, vrf_info)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_vrf: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного VRF

    def update_template_vrf(self, template_id, vrf_id, vrf_info):
        """Изменить настройки виртуального маршрутизатора в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.virtualrouter.update(self._auth_token, template_id, vrf_id, vrf_info)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_vrf: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

########################## Zone #############################################################################
    def get_template_zones_list(self, template_id):
        """Получить список зон шаблона"""
        try:
            result = self._server.v1.ccnetmanager.zones.list(self._auth_token, template_id, 0, 200, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_zones_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список зон.

    def add_template_zone(self, template_id, zone):
        """Добавить зону в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.zone.add(self._auth_token, template_id, zone)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Зона {zone["name"]} уже существует.'
            else:
                return 1, f'Error mclib.add_template_zone: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID созданной зоны

    def update_template_zone(self, template_id, zone_id, zone):
        """Обновить параметры зоны в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.zone.update(self._auth_token, template_id, zone_id, zone)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 7:
                return 4, f'Зона {zone["name"]} не найдена в шаблоне!'
            elif err.faultCode == 9:
                return 3, f'Зона {zone["name"]} - нет отличающихся параметров для изменения.'
            else:
                return 1, f'Error mclib.update_template_zone: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

########################## Interfaces #######################################################################
    def get_template_interfaces_list(self, template_id, node_name=''):
        """Получить список сетевых интерфейсов шаблона"""
        try:
            result = self._server.v1.ccnetmanager.interfaces.list(self._auth_token, template_id, 0, 1000, {'node_name': node_name})
            return 0, result['items']    # Возвращает список интерфейсов.
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_interfaces_list: [{err.faultCode}] — {err.faultString}'

    def add_template_interface(self, template_id, iface):
        """Добавить vlan интерфейс в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.interface.add(self._auth_token, template_id, iface)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_interface: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID созданного интерфейса.

##################################### DHCP ######################################
    def get_dhcp_list(self, template_id):
        """Получить список подсетей dhcp для шаблона"""
        try:
            result = self._server.v1.ccnetmanager.dhcp.subnets.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f"Error mclib.get_dhcp_list: [{err.faultCode}] — {err.faultString}"
        return 0, result['items']    # Возвращает list of all DHCP subnets on that node

    def add_dhcp_subnet(self, template_id, subnet):
        """Добавить DHCP subnet в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.dhcp.subnet.add(self._auth_token, template_id,  subnet)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:  # 1017:
                return 3, f'DHCP subnet "{subnet["name"]}" уже существует.'
            else:
                return 1, f"Error mclib.add_dhcp_subnet: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result    # Возвращает ID созданной subnet

########################## Library ##########################################################################
    def get_template_services_list(self, template_id):
        """Получить список сервисов раздела Библиотеки шаблона"""
        try:
            if self.version_hight >= 7 and self.version_midle >= 1:
                result = self._server.v1.ccnetwork.services.list(self._auth_token, template_id, 0, 50000, {}, [])
            else:
                result = self._server.v1.ccnetwork.services.list(self._auth_token, template_id, 0, 50000, {}, [{}])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_services_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает лист сервисов (список словарей).

    def add_template_service(self, template_id, service):
        """Добавить список сервисов раздела Библиотеки в шаблон"""
        try:
            result = self._server.v1.ccnetwork.service.add(self._auth_token, template_id, service)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Сервис "{service["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_service: [{err.faultCode}] — {err.faultString} [Сервис "{service["name"]}"]'
        return 0, result     # Возвращает ID сервиса

    def update_template_service(self, template_id, service_id, service):
        """Обновить отдельный сервис раздела Библиотеки в шаблоне"""
        try:
            result = self._server.v1.ccnetwork.service.update(self._auth_token, template_id, service_id, service)
        except rpc.Fault as err:
            if err.faultCode == 7:
                return 4, f'Не удалось обновить сервис "{service["name"]}". Данный сервис не найден.'
            else:
                return 1, f'Error mclib.update_template_service: [{err.faultCode}] — {err.faultString} [Сервис "{service["name"]}"]'
        return 0, result     # Возвращает True

    def get_template_nlists_list(self, template_id, list_type):
        """Получить список именованных списков по их типу из Библиотеки в шаблоне"""
        array = []
        try:
            result = self._server.v1.ccnlists.lists.list(self._auth_token, template_id, list_type, 0, 100000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_nlists_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает лист списков (список словарей).

    def add_template_nlist(self, template_id, named_list):
        """Добавить именованный список в шаблон"""
        try:
            result = self._server.v1.ccnlists.list.add(self._auth_token, template_id, named_list)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Список "{named_list["name"]}" уже существует'
            else:
                return 1, f'Error mclib.add_template_nlist: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID списка

    def update_template_nlist(self, template_id, named_list_id, named_list):
        """Обновить параметры именованного списка в шаблоне"""
        try:
            result = self._server.v1.ccnlists.list.update(self._auth_token, template_id, named_list_id, named_list)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Список "{named_list["name"]}" - нет отличающихся параметров для изменения.'
            else:
                return 1, f'Error mclib.update_template_nlist: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def add_template_nlist_item(self, template_id, named_list_id, item):
        """Добавить 1 значение в именованный список шаблона"""
        try:
            result = self._server.v1.ccnlists.item.add(self._auth_token, template_id, named_list_id, item)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode in {9, 22001}:
                return 3, f'Содержимое {item} не добавлено, так как уже существует.'
            elif err.faultCode == 11:
                return 1, f'Error: содержимое {item} не добавлено — {err.faultString}.'
            else:
                return 1, f'Error mclib.add_template_nlist_item: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID созданного объекта

    def add_template_nlist_items(self, template_id, named_list_id, items):
        """Добавить список значений в именованный список шаблона"""
        try:
            result = self._server.v1.ccnlists.items.add(self._auth_token, template_id, named_list_id, items)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode in {9, 22001}:
                return 3, f'Содержимое {items} не добавлено, так как уже существует.'
            else:
                return 1, f'Error mclib.add_template_nlist_items: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает int (кол-во добавленных объектов).

    def get_template_shapers_list(self, template_id):
        """Получить список полос пропускания шаблона"""
        try:
            result = self._server.v1.ccshaper.pool.list(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_template_shapers_list: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def add_template_shaper(self, template_id, shaper):
        """Получить список полос пропускания шаблона"""
        try:
            result = self._server.v1.ccshaper.pool.add(self._auth_token, template_id, shaper)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Полоса пропускания "{shaper["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_shaper: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID созданного объекта

    def update_template_shaper(self, template_id, shaper_id, shaper):
        """Получить список полос пропускания шаблона"""
        try:
            result = self._server.v1.ccshaper.pool.update(self._auth_token, template_id, shaper_id, shaper)
        except rpc.Fault as err:
            return 1, f"Error mclib.update_template_shaper: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_template_notification_profiles_list(self, template_id):
        """Получить список профилей оповещения шаблона"""
        try:
            result = self._server.v1.ccnotification.notification.profiles.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_template_notification_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список словарей

    def add_template_notification_profile(self, template_id, profile):
        """Добавить профиль оповещения в шаблон"""
        try:
            result = self._server.v1.ccnotification.notification.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Профиль оповещения "{profile["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_template_notification_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля
        
    def update_template_notification_profile(self, template_id, profile_id, profile):
        """Обновить профиль оповещения в шаблоне"""
        try:
            result = self._server.v1.ccnotification.notification.profile.update(self._auth_token, template_id, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_template_notification_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

########################## Политики сети ####################################################################
    def get_template_firewall_rules(self, template_id):
        """Получить список правил межсетевого экрана шаблона"""
        try:
            result = self._server.v1.ccfirewall.rules.list(self._auth_token, template_id, 0, 20000, {})
        except rpc.Fault as err:
            return 1, f"Error mclib.get_template_firewall_rules: [{err.faultCode}] — {err.faultString}"
        return 0, result['items']

    def add_template_firewall_rule(self, template_id, rule):
        """Добавить новое правило в МЭ в шаблон"""
        try:
            result = self._server.v1.ccfirewall.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f"Error mclib.add_template_firewall_rule: [{err.faultCode}] — {err.faultString}"
        return 0, result     # Возвращает ID добавленного правила

    def update_template_firewall_rule(self, template_id, rule_id, rule):
        """Обновить правило МЭ в шаблоне. Принимает структуру правила и его ID."""
        try:
            result = self._server.v1.ccfirewall.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"Error mclib.update_template_firewall_rule: [{err.faultCode}] — {err.faultString}"
        return 0, result     # Возвращает True

    def get_template_traffic_rules(self, template_id):
        """Получить список правил NAT шаблона"""
        try:
            result = self._server.v1.cctraffic.rules.list(self._auth_token, template_id, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_traffic_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_traffic_rule(self, template_id, rule):
        """Добавить новое правило NAT в шаблон"""
        try:
            result = self._server.v1.cctraffic.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_traffic_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_template_traffic_rule(self, template_id, rule_id, rule):
        """Обновить правило NAT в шаблоне"""
        try:
            result = self._server.v1.cctraffic.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_traffic_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_shaper_rules(self, template_id):
        """Получить список правил пропускной способности"""
        try:
            result = self._server.v1.ccshaper.rules.list(self._auth_token, template_id, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_shaper_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_shaper_rule(self, template_id, rule):
        """Добавить новое правило пропускной способности"""
        try:
            result = self._server.v1.ccshaper.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_shaper_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_shaper_rule(self, template_id, rule_id, rule):
        """Обновить правило пропускной способности"""
        try:
            result = self._server.v1.ccshaper.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_shaper_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

########################## Политики безопасности ############################################################
    def get_template_content_rules(self, template_id):
        """Получить список правил фильтрации контента шаблона"""
        try:
            result = self._server.v1.cccontent.rules.list(self._auth_token, template_id, 0, 20000, {})
        except rpc.Fault as err:
            return 1, f"Error mclib.get_template_content_rules: [{err.faultCode}] — {err.faultString}"
        return 0, result['items']

    def add_template_content_rule(self, template_id, rule):
        """Добавить новое правило фильтрации контента в шаблон"""
        try:
            result = self._server.v1.cccontent.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f"Error mclib.add_template_content_rule: [{err.faultCode}] — {err.faultString}"
        return 0, result     # Возвращает ID добавленного правила

    def update_template_content_rule(self, template_id, rule_id, rule):
        """Обновить правило фильтрации контента в шаблоне"""
        try:
            result = self._server.v1.cccontent.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"Error mclib.update_template_content_rule: [{err.faultCode}] — {err.faultString}"
        return 0, result     # Возвращает True

    def get_template_scenarios_rules(self, template_id):
        """Получить список сценариев шаблона"""
        try:
            result = self._server.v1.ccscenarios.rules.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_scenarios_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_scenarios_rule(self, template_id, rule):
        """Добавить новый сценарий в шаблон"""
        try:
            result = self._server.v1.ccscenarios.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_scenarios_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_scenarios_rule(self, template_id, rule_id, rule):
        """Обновить сценарий в шаблоне"""
        try:
            result = self._server.v1.ccscenarios.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_scenarios_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

########################## Пользователи #####################################################################
    def get_usercatalog_ldap_servers(self):
        """Получить список активных LDAP серверов области находящихся в каталогах пользователей."""
        try:
            if self.version_hight >= 7 and self.version_midle >= 1:
                result = self._server.v1.usercatalogs.servers.list(self._auth_token, 0, 500, {'enabled': True}, [])
                return 0, result['items']
            else:
                result = self._server.v1.usercatalogs.servers.list(self._auth_token, {'enabled': True})
                return 0, result
        except rpc.Fault as err:
            return 1, f"Error mclib.get_usercatalog_ldap_servers: [{err.faultCode}] — {err.faultString}"

    def get_usercatalog_ldap_user_guid(self, ldap_id, user_name):
        """Получить GUID пользователя LDAP по его имени"""
        try:
            if self.version_hight >= 7 and self.version_midle >= 1:
                users = self._server.v1.usercatalogs.ldap.users.list(self._auth_token, ldap_id, user_name)
            else:
                users = self._server.v1.usercatalogs.realm.ldap.users.list(self._auth_token, ldap_id, user_name)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_usercatalog_ldap_user_guid: [{err.faultCode}] — {err.faultString}"
        return 0, users[0]['guid'] if users else 0  # Возвращает или guid или 0

    def get_usercatalog_ldap_group_guid(self, ldap_id, group_name):
        """Получить GUID группы LDAP по её имени"""
        try:
            if self.version_hight >= 7 and self.version_midle >= 1:
                groups = self._server.v1.usercatalogs.ldap.groups.list(self._auth_token, ldap_id, group_name)
            else:
                groups = self._server.v1.usercatalogs.realm.ldap.groups.list(self._auth_token, ldap_id, group_name)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_usercatalog_ldap_group_guid: [{err.faultCode}] — {err.faultString}"
        return 0, groups[0]['guid'] if groups else 0  # Возвращает или guid или 0

    def get_template_groups_list(self, template_id):
        """Получить список локальных групп в шаблоне"""
        try:
            result = self._server.v1.ccaccounts.groups.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_groups_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_group(self, template_id, group):
        """Добавить локальную группу в шаблон"""
        try:
            result = self._server.v1.ccaccounts.group.add(self._auth_token, template_id, group)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Группа "{group["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_group: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает GUID добавленной группы

    def update_template_group(self, template_id, guid, group):
        """Обновить локальную группу в шаблоне"""
        try:
            result = self._server.v1.ccaccounts.group.update(self._auth_token, template_id, guid, group)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_group: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_group_users(self, template_id, group_guid):
        """Получить список пользователей в группе шаблона"""
        try:
            result = self._server.v1.ccaccounts.group.users.list(self._auth_token, template_id, group_guid, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_group_users: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def get_template_users_list(self, template_id):
        """Получить список локальных пользователей в шаблоне"""
        try:
            result = self._server.v1.ccaccounts.users.list(self._auth_token, template_id, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error get_template_users_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_user(self, template_id, user):
        """Добавить локального пользователя"""
        try:
            result = self._server.v1.ccaccounts.user.add(self._auth_token, template_id, user)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Пользователь "{user["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_user: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного пользователя

    def update_template_user(self, template_id, user_UID, user):
        """Обновить локального пользователя шаблона"""
        try:
            result = self._server.v1.ccaccounts.user.update(self._auth_token, template_id, user_UID, user)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_user: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def add_user_in_template_group(self, template_id, group_guid, user_guid):
        """Добавить локального пользователя в локальную группу шаблона"""
        try:
            result = self._server.v1.ccaccounts.group.user.add(self._auth_token, template_id, group_guid, user_guid)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_user_in_template_group: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает true

    def get_template_auth_servers(self, template_id, servers_type=''):
        """
        Получить список активных серверов авторизации шаблона.
        Если servers_type не указан, выводятся все сервера аутентификации.
        """
        try:
            result = self._server.v1.ccauth.auth.servers.list(self._auth_token, template_id, 0, 500, {'type': servers_type}, [])
            return 0, result['items']
        except rpc.Fault as err:
            return 1, f"Error mclib.get_template_auth_servers: [{err.faultCode}] — {err.faultString}"

    def add_template_auth_server(self, template_id, server):
        """Добавить сервер авторизации в шаблон."""
        try:
            result = self._server.v1.ccauth.auth.server.add(self._auth_token, template_id, server)
            return 0, result
        except rpc.Fault as err:
            return 1, f"Error mclib.add_template_auth_server: [{err.faultCode}] — {err.faultString}"

####################################### Служебные методы ######################################################################
    def get_ip_protocol_list(self):
        """Получить список поддерживаемых IP протоколов"""
        try:
            result = self._server.v1.core.ip.protocol.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_ip_protocol_list: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, {x['name'] for x in result}  # Возвращает set {protocol_name, ...}

    def get_url_categories(self):
        """Получить список категорий URL"""
        try:
            result = self._server.v1.core.url.categories.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_url_categories: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result  # Возвращает список [{id: name}, ...]

    def get_l7_apps(self, template_id):
        """Получить список приложений l7"""
        try:
            if self.version_hight >= 7 and self.version_midle >= 1:
                result = self._server.v1.ccl7.signatures.list(self._auth_token, template_id, 0, 500000, {}, [])
                return 0, [{'id': x['signature_id'], 'name': x['name']} for x in result['items']]
            else:
                result = self._server.v1.core.get.l7apps(self._auth_token, 0, 500000, {}, [])
                return 0, [{'id': x['id'], 'name': x['name']} for x in result['items']]
        except rpc.Fault as err:
            return 1, f"Error mclib.get_l7_apps: [{err.faultCode}] — {err.faultString}"

    def get_l7_categories(self):
        """
        Получить список категорий l7.
        В версиях до 7.1 возвращает список: [{'id': category_id, 'name': category_name, 'app_list': [id_app_1, id_app_2, ...]}, ...]
        В версиях начиная с 7.1 возвращает список: [{'id': category_id, 'name': category_name}, ...]
        """
        try:
            if self.version_hight >= 7 and self.version_midle >= 1:
                result = self._server.v1.ccl7.get.categories(self._auth_token)
            else:
                result = self._server.v1.core.get.l7categories(self._auth_token, 0, 10000, '')
        except rpc.Fault as err:
            return 1, f"Error mclib.get_l7_categories: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result['items']
#####################################################################################################

class UtmError(Exception): pass

