#!/usr/bin/python3
# Версия 2.3 09.09.2024
# Общий класс для работы с xml-rpc Management Center
#
# Коды возврата:
# 0 - Успешно
# 1 - Ошибка выполнения
# 2, 3 и далее - Информационные сообщения
#-----------------------------------------------------------------------------------------------------------
import sys
import requests
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
            self.version_low = int(''.join(n for n in tmp[2] if n.isdecimal()))
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
                return 2, f'Нет прав на получение списка областей [Error mclib.get_realms_list: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_realms_list: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def get_realm_upload_session(self, upload_file):
        """Получить """
        try:
            result = self._server.v1.storage.init.upload.session(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на импорт файла {upload_file} [Error mclib.get_realms_upload_session: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_realms_upload_session: [{err.faultCode}] — {err.faultString}'
        upload_url = f'http://{self.server_ip}:4041{result["upload_url"]}'
        req = requests.post(upload_url, files={'data': open(upload_file, 'rb')})
        return 0, req.json()
############## Realm API module (API для области) ###########################################################
    def get_usercatalog_servers_status(self):
        """Получить статус всех серверов авторизации LDAP области"""
        try:
            result = self._server.v1.usercatalogs.check.all.servers.status(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получение списка серверов авторизации [Error mclib.get_usercatalog_servers_status: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_usercatalog_servers_status: [{err.faultCode}] — {err.faultString}'
        return 0, result

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

######## NGFW Template API module, выполняются только под администраторами областей (realm_admin/SF)#########
    def get_device_templates(self):
        """Получить список шаблонов устройств области"""
        try:
            result = self._server.v1.ccdevices.templates.list(self._auth_token, 0, 1000, {}, [])
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получение списка шаблонов [Error mclib.get_device_templates: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_device_templates: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список словарей.

    def fetch_device_template(self, template_id):
        """Получить шаблон области по id"""
        try:
            result = self._server.v1.ccdevices.template.fetch(self._auth_token, template_id)
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получение списка шаблонов [Error mclib.fetch_device_template: {err.faultString}].'
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
    def get_template_general_settings(self, template_id):
        """Get NGFW general setting value"""
        try:
            result = self._server.v1.ccgeneralsettings.settings.list(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_general_settings: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список

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

    def add_template_certificate(self, template_id, cert_info, cert_data, private_key=None):
        """Импортировать сертификат в шаблон"""
        try:
            cert_info['cert_data'] = rpc.Binary(cert_data)
            if private_key:
                cert_info['key_data'] = rpc.Binary(private_key) 
            f = getattr(self._server, 'v1.cccertificates.certificate.import')
            result = f(self._auth_token, template_id, cert_info)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Сертификат "{cert_info["name"]}" уже существует.'
            return 1, f'Error mclib.add_template_certificate: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает ID добавленого сертификата

    def new_template_certificate(self, template_id, cert_info):
        """Создать новый сертификат в шаблоне"""
        try:
            result = self._server.v1.cccertificates.certificate.generate.ca(self._auth_token, template_id, cert_info)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Сертификат "{cert_info["name"]}" уже существует.'
            return 1, f'Error mclib.new_template_certificate: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает ID добавленого сертификата

    def update_template_certificate(self, template_id, cert_id, cert_info, cert_data, private_key=None):
        """Создать новый сертификат в шаблоне"""
        try:
            cert_info['cert_data'] = rpc.Binary(cert_data)
            if private_key:
                cert_info['key_data'] = rpc.Binary(private_key) 
            result = self._server.v1.cccertificates.certificate.update(self._auth_token, template_id, cert_id, cert_info)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_certificate: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает True

    def get_template_client_certificate_profiles(self, template_id):
        """Получить список профилей пользовательских сертификатов шаблона"""
        try:
            result = self._server.v1.cccertificates.client.profiles.list(self._auth_token, template_id, 0, 500, {}, [])
            return 0, result['items']
        except rpc.Fault as err:
            return 1, f'Error utm.get_template_client_certificate_profiles: [{err.faultCode}] — {err.faultString}'

    def add_template_client_certificate_profile(self, template_id, profile):
        """Создать профиль сертификата пользователя в шаблоне"""
        try:
            result = self._server.v1.cccertificates.client.profile.add(self._auth_token, template_id, profile)
            return 0, result    # Возвращает ID созданного профиля
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Профиль "{profile["name"]} уже существует.'
            else:
                return 1, f'Error utm.add_template_client_certificate_profile: [{err.faultCode}] — {err.faultString}'

    def get_proxyportal_config(self):
        """Получить настройки веб-портала"""
        try:
            result = self._server.v1.proxyportal.config.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_proxyportal_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def set_proxyportal_config(self, params):
        """Изменить настройки веб-портала"""
        try:
            result = self._server.v1.proxyportal.config.set(self._auth_token, params)
        except rpc.Fault as err:
            return 1, f"Error utm.set_proxyportal_config: [{err.faultCode}] — {err.faultString}"
        return 0, result    # Возвращает True

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

################################ Gateways ################################################################
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

    def get_template_gateway_failover(self, template_id):
        """Получить настройки проверки сети шлюзов шаблона"""
        try:
            result = self._server.v1.ccnetmanager.failover.config.fetch(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_template_gateway_failover: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def update_template_gateway_failover(self, template_id, params):
        """Изменить настройки проверки сети шлюзов в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.failover.config.update(self._auth_token, template_id, params)
        except rpc.Fault as err:
            return 1, f"Error mclib.update_template_gateway_failover: [{err.faultCode}] — {err.faultString}"
        return 0, result    # Возвращает True

##################################### DHCP ######################################
    def get_template_dhcp_list(self, template_id):
        """Получить список подсетей dhcp для шаблона"""
        try:
            result = self._server.v1.ccnetmanager.dhcp.subnets.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f"Error mclib.get_template_dhcp_list: [{err.faultCode}] — {err.faultString}"
        return 0, result['items']    # Возвращает list of all DHCP subnets on that node

    def add_template_dhcp_subnet(self, template_id, subnet):
        """Добавить DHCP subnet в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.dhcp.subnet.add(self._auth_token, template_id,  subnet)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:  # 1017:
                return 3, f'DHCP subnet "{subnet["name"]}" уже существует.'
            else:
                return 1, f"Error mclib.add_template_dhcp_subnet: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result    # Возвращает ID созданной subnet

################################## DNS ##################################################################
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

    def get_template_dns_settings(self, template_id):
        """Получить список настроек DNS-прокси шаблона"""
        try:
            result = self._server.v1.ccdns.settings.list(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_dns_settings: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает список

    def update_template_dns_setting(self, template_id, key, value):
        """Изменить параметр настроек DNS-прокси шаблона"""
        try:
            result = self._server.v1.ccdns.setting.update.param(self._auth_token, template_id, key, value)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_dns_setting: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

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

######################################## WCCP  ########################################
    def get_template_wccp_rules(self, template_id):
        """Получить список правил wccp шаблона"""
        try:
            result = self._server.v1.ccwccp.rules.list(self._auth_token, template_id)
        except rpc.Fault as err:
            if err.faultCode == 102:
                return 2, f'Ошибка: нет прав на чтение конфигурации WCCP. Конфигурация WWCP не выгружена.'
            else:
                return 1, f'Error utm.get_template_wccp_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает список записей

    def add_template_wccp_rule(self, template_id, rule):
        """Добавить правило wccp в шаблон"""
        try:
            result = self._server.v1.ccwccp.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_template_wccp_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_template_wccp_rule(self, template_id, rule_id, rule):
        """Изменить правило wccp в шаблоне"""
        try:
            result = self._server.v1.ccwccp.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_template_wccp_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

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
            if err.faultCode in {9, 22001}:
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
            if err.faultCode in {9, 22001}:
                return 3, f'Список "{named_list["name"]}" - нет отличающихся параметров для изменения.'
            else:
                return 1, f'Error mclib.update_template_nlist: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_nlist_items(self, template_id, named_list_id):
        """Получить содержимое именованного списка Библиотеки в шаблоне"""
        array = []
        try:
            result = self._server.v1.ccnlists.items.list(self._auth_token, template_id, named_list_id, 0, 100000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_nlists_items: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает лист списков (список словарей).

    def add_template_nlist_item(self, template_id, named_list_id, item):
        """Добавить 1 значение в именованный список шаблона"""
        try:
            result = self._server.v1.ccnlists.item.add(self._auth_token, template_id, named_list_id, item)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 22001:
                return 3, f'Содержимое {item} не добавлено, так как уже существует.'
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
            if err.faultCode == 22001:
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

    def get_template_responsepages_list(self, template_id):
        """Получить список шаблонов страниц Библиотеки шаблона"""
        try:
            result = self._server.v1.ccresponsepages.templates.list(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_responsepages_list: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def add_template_responsepage(self, template_id, responsepage):
        """Добавить новый шаблон в раздел "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.ccresponsepages.template.add(self._auth_token, template_id, responsepage)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 3, f'Шаблон страницы "{responsepage["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_responsepage: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID шаблона

    def update_template_responsepage(self, template_id, responsepage_id, responsepage):
        """Обновить шаблон в разделе "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.ccresponsepages.template.update(self._auth_token, template_id, responsepage_id, responsepage)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 2, f'Не удалось обновить шаблон страницы "{responsepage["name"]}". Данная страница не найдена.'
            else:
                return 1, f'Error mclib.update_template_responsepage: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_responsepage_data(self, template_id, responsepage_id):
        """Получить HTML страницы шаблона раздела Библиотеки"""
        try:
            result = self._server.v1.ccresponsepages.template.data.fetch(self._auth_token, template_id, responsepage_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_responsepage_data: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_template_responsepage_data(self, template_id, responsepage_id, storage_file_uid):
        """Импортировать страницу HTML шаблона раздела Библиотеки"""
        try:
            result = self._server.v1.ccresponsepages.template.data.update(self._auth_token, template_id, responsepage_id, storage_file_uid)
        except rpc.Fault as err:
            return 1, f'Error mclib.set_template_responsepage_data: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_template_custom_url_list(self, template_id):
        """Получить список изменённых категорий URL раздела Библиотеки"""
        try:
            result = self._server.v1.cccontent.override.domains.list(self._auth_token, template_id, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_custom_url_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_custom_url(self, template_id, data):
        """Добавить изменённую категорию URL"""
        try:
            result = self._server.v1.cccontent.override.domain.add(self._auth_token, template_id, data)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Категория URL: "{data["name"]}" уже существует'
            else:
                return 1, f'Error mclib.add_template_custom_url: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def update_template_custom_url(self, template_id, data_id, data):
        """Обновить изменённую категорию URL"""
        try:
            result = self._server.v1.cccontent.override.domain.update(self._auth_token, template_id, data_id, data)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Категория URL: "{data["name"]}" - нет отличающихся параметров для изменения.'
            else:
                return 1, f'Error mclib.update_template_custom_url: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def get_template_app_signatures(self, template_id, query={}):
        """Получить список пользовательских приложений l7 шаблона"""
        try:
            result = self._server.v1.ccl7.signatures.list(self._auth_token, template_id, 0, 50000, query, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_app_signatures: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_app_signature(self, template_id, apps_info):
        """Добавить новое пользовательское приложение l7 в шаблон"""
        try:
            result = self._server.v1.ccl7.signature.add(self._auth_token, template_id, apps_info)
        except rpc.Fault as err:
            return 1, f"Error mclib.add_template_app_signature: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленной сигнатуры

    def update_template_app_signature(self, template_id, apps_id, apps_info):
        """Обновить пользовательское приложение l7 в шаблоне"""
        try:
            result = self._server.v1.ccl7.signature.update(self._auth_token, template_id, apps_id, apps_info)
        except rpc.Fault as err:
            return 1, f"Error mclib.update_template_app_signature: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_template_l7_profiles_list(self, template_id):
        """Получить список профилей приложений шаблона"""
        try:
            result = self._server.v1.ccl7.profiles.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_l7_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает list

    def add_template_l7_profile(self, template_id, profile):
        """Добавить профиль приложений в шаблон"""
        try:
            result = self._server.v1.ccl7.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_l7_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID созданного профиля

    def update_template_l7_profile(self, template_id, profile_id, profile):
        """Обновить профиль приложений в шаблоне"""
        try:
            result = self._server.v1.ccl7.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_l7_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

    def get_template_notification_profiles_list(self, template_id):
        """Получить список профилей оповещения шаблона"""
        try:
            result = self._server.v1.ccnotification.notification.profiles.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_notification_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список словарей

    def add_template_notification_profile(self, template_id, profile):
        """Добавить профиль оповещения в шаблон"""
        try:
            result = self._server.v1.ccnotification.notification.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Профиль оповещения "{profile["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_notification_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля
        
    def update_template_notification_profile(self, template_id, profile_id, profile):
        """Обновить профиль оповещения в шаблоне"""
        try:
            result = self._server.v1.ccnotification.notification.profile.update(self._auth_token, template_id, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_notification_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_idps_signatures_list(self, template_id, query={}):
        """Получить список сигнатур IDPS шаблона"""
        try:
            result = self._server.v2.ccidps.signatures.list(self._auth_token, template_id, 0, 50000, query, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_idps_signatures_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает list сигнатур

    def add_template_idps_signature(self, template_id, signature):
        """Добавить сигнатуру IDPS в шаблон"""
        try:
            result = self._server.v2.ccidps.signature.add(self._auth_token, template_id, signature)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_idps_signature: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID сигнатуры

    def update_template_idps_signature(self, template_id, signature_id, signature):
        """Обновить сигнатуру IDPS в шаблоне."""
        try:
            result = self._server.v2.ccidps.signature.update(self._auth_token, template_id, signature_id, signature)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_idps_signature: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

    def get_template_idps_signature_fetch(self, template_id, signature_id):
        """Получить сигнатуру СОВ по ID из шаблона"""
        try:
            result = self._server.v2.ccidps.signature_fetch(self._auth_token, template_id, signature_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_idps_signature_fetch: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает словарь

    def get_template_idps_profiles_list(self, template_id):
        """Получить список профилей СОВ шаблона"""
        try:
            result = self._server.v2.ccidps.profiles.list(self._auth_token, template_id, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_idps_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает list

    def add_template_idps_profile(self, template_id, profile):
        """Добавить профиль СОВ в шаблон"""
        try:
            result = self._server.v2.ccidps.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_idps_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID созданного профиля СОВ

    def update_template_idps_profile(self, template_id, profile_id, profile):
        """Обновить профиль СОВ в шаблоне"""
        try:
            result = self._server.v2.ccidps.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_idps_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

    def get_template_netflow_profiles_list(self, template_id):
        """Получить список профилей netflow из Библиотеки шаблона"""
        try:
            result = self._server.v1.ccnetmanager.netflow.profiles.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_netflow_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_netflow_profile(self, template_id, profile):
        """Добавить профиль netflow в Библиотеку шаблона"""
        try:
            result = self._server.v1.ccnetmanager.netflow.profile.add(self._auth_token, template_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_netflow_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_template_netflow_profile(self, template_id, profile_id, profile):
        """Обновить профиль netflow в Библиотеке шаблона"""
        try:
            result = self._server.v1.ccnetmanager.netflow.profile.update(self._auth_token, template_id, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_netflow_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_lldp_profiles_list(self, template_id):
        """Получить список профилей LLDP раздела Библиотеки шаблона."""
        try:
            result = self._server.v1.ccnetmanager.lldp.profiles.list(self._auth_token, template_id, 0, 1000, {}, '')
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_lldp_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список словарей

    def add_template_lldp_profile(self, template_id, profile):
        """Добавить профиль LLDP в Библиотеку шаблона"""
        try:
            result = self._server.v1.ccnetmanager.lldp.profile.add(self._auth_token, template_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_lldp_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_template_lldp_profile(self, template_id, profile_id, profile):
        """Обновить профиль LLDP в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.lldp.profile.update(self._auth_token, template_id, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_lldp_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_ssl_profiles_list(self, template_id):
        """Получить список профилей SSL шаблона"""
        try:
            result = self._server.v1.cccontent.ssl.profiles.list(self._auth_token, template_id, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_ssl_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_ssl_profile(self, template_id, profile):
        """Добавить профиль SSL в шаблон"""
        try:
            result = self._server.v1.cccontent.ssl.profile.add(self._auth_token, template_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 2, f'Профиль SSL: "{profile["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_ssl_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_template_ssl_profile(self, template_id, profile_id, profile):
        """Обновить профиль SSL в шаблоне"""
        try:
            result = self._server.v1.cccontent.ssl.profile.update(self._auth_token, template_id, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_ssl_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_ssl_forward_profiles(self, template_id):
        """Получить список профилей пересылки SSL шаблона"""
        try:
            result = self._server.v1.cccontent.ssl.forward.profiles.list(self._auth_token, template_id, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_ssl_forward_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_ssl_forward_profile(self, template_id, profile):
        """Добавить профиль пересылки SSL в шаблон"""
        try:
            result = self._server.v1.cccontent.ssl.forward.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_ssl_forward_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_template_ssl_forward_profile(self, template_id, profile_id, profile):
        """Обновить профиль пересылки SSL в шаблоне"""
        try:
            result = self._server.v1.cccontent.ssl.forward.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_ssl_forward_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def get_template_hip_objects_list(self, template_id):
        """Получить список объектов HIP шаблона"""
        try:
            result = self._server.v1.cchip.objects.list(self._auth_token, template_id, 0, 5000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_hip_objects_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_hip_object(self, template_id, hip_object):
        """Добавить объект HIP в шаблон"""
        try:
            result = self._server.v1.cchip.object.add(self._auth_token, template_id, hip_object)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_hip_object: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного объекта

    def update_template_hip_object(self, template_id, hip_object_id, hip_object):
        """Обновить объект HIP в шаблоне"""
        try:
            result = self._server.v1.cchip.object.update(self._auth_token, template_id, hip_object_id, hip_object)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_hip_object: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_hip_profiles_list(self, template_id):
        """Получить список профилей HIP шаблона"""
        try:
            result = self._server.v1.cchip.profiles.list(self._auth_token, template_id, 0, 5000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_hip_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_hip_profile(self, template_id, profile):
        """Добавить профиль HIP в шаблон"""
        try:
            result = self._server.v1.cchip.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_hip_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_template_hip_profile(self, template_id, profile_id, profile):
        """Обновить профиль HIP в шаблоне"""
        try:
            result = self._server.v1.cchip.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_hip_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_bfd_profiles_list(self, template_id):
        """Получить список профилей BFD шаблона"""
        try:
            result = self._server.v1.ccnetmanager.bfd.profiles.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_bfd_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_bfd_profile(self, template_id, profile):
        """Добавить профиль BFD в шаблон"""
        try:
            result = self._server.v1.ccnetmanager.bfd.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_bfd_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_template_bfd_profile(self, template_id, profile_id, profile):
        """Обновить профиль BFD в шаблоне"""
        try:
            result = self._server.v1.ccnetmanager.bfd.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_bfd_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_useridagent_filters_list(self, template_id):
        """Получить Syslog фильтры UserID агента шаблона"""
        try:
            result = self._server.v1.ссuseridagent.filters.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_useridagent_filters_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_useridagent_filter(self, template_id, filter_info):
        """Добавить Syslog фильтр UserID агента в шаблон"""
        try:
            result = self._server.v1.ссuseridagent.filter.add(self._auth_token, template_id, filter_info)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_useridagent_filter: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного фильтра

    def update_template_useridagent_filter(self, template_id, filter_id, filter_info):
        """Обновить Syslog фильтр UserID агента в шаблоне"""
        try:
            result = self._server.v1.ссuseridagent.filter.update(self._auth_token, template_id, filter_id, filter_info)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_useridagent_filter: [{err.faultCode}] — {err.faultString}'
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
            return 1, f'Error mclib.add_template_scenarios_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_scenarios_rule(self, template_id, rule_id, rule):
        """Обновить сценарий в шаблоне"""
        try:
            result = self._server.v1.ccscenarios.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_scenarios_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

########################## Пользователи #####################################################################
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
        return 0, result     # Возвращает ID добавленного пользователя

    def update_template_user(self, template_id, user_UID, user):
        """Обновить локального пользователя шаблона"""
        try:
            result = self._server.v1.ccaccounts.user.update(self._auth_token, template_id, user_UID, user)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_user: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def add_user_in_template_group(self, template_id, group_guid, user_guid):
        """Добавить локального пользователя в локальную группу шаблона"""
        try:
            result = self._server.v1.ccaccounts.group.user.add(self._auth_token, template_id, group_guid, user_guid)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_user_in_template_group: [{err.faultCode}] — {err.faultString}'
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

    def get_template_auth_profiles(self, template_id):
        """Получить список профилей аутентификации в шаблоне"""
        try:
            result = self._server.v1.ccauth.user.auth.profiles.list(self._auth_token, template_id, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_auth_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_auth_profile(self, template_id, profile):
        """Добавить профиль аутентификации в шаблон"""
        try:
            result = self._server.v1.ccauth.user.auth.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_auth_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

    def update_template_auth_profile(self, template_id, profile_id, profile):
        """Обновить профиль аутентификации в шаблоне"""
        try:
            result = self._server.v1.ccauth.user.auth.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_auth_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_template_captive_profiles(self, template_id):
        """Получить список Captive-профилей шаблона"""
        try:
            result = self._server.v1.cccaptiveportal.profiles.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_captive_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_captive_profile(self, template_id, profile):
        """Добавить новый Captive-профиль в шаблон"""
        try:
            result = self._server.v1.cccaptiveportal.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 1, f'Error: Профиль авторизации "{profile["name"]}" не добавлен — {err.faultString}.'
            elif err.faultCode == 111:
                return 1, f'Error: Недопустимые символы в названии captive-профиля "{profile["name"]}".'
            else:
                return 1, f'Error mclib.add_template_captive_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_template_captive_profile(self, template_id, profile_id, profile):
        """Обновить Captive-профиль в шаблоне"""
        try:
            result = self._server.v1.cccaptiveportal.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_captive_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_captive_portal_rules(self, template_id):
        """Получить список правил Captive-портала шаблона"""
        try:
            result = self._server.v1.cccaptiveportal.rules.list(self._auth_token, template_id, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_captive_portal_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_captive_portal_rule(self, template_id, rule):
        """Добавить новое правило Captive-портала в шаблон"""
        try:
            result = self._server.v1.cccaptiveportal.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 1, f'Error: Правило Captive-портала "{rule["name"]}" не добавлено — {err.faultString}.'
            elif err.faultCode == 111:
                return 1, f'Error: Недопустимые символы в названии правила captive-портала "{rule["name"]}".'
            else:
                return 1, f'Error mclib.add_template_captive_portal_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_captive_portal_rule(self, template_id, rule_id, rule):
        """Обновить правило Captive-портала в шаблоне"""
        try:
            result = self._server.v1.cccaptiveportal.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_captive_portal_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_2fa_profiles(self, template_id):
        """Получить список профилей MFA шаблона"""
        try:
            result = self._server.v1.ccauth.cc2fa.profiles.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_2fa_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_2fa_profile(self, template_id, profile):
        """Добавить новый профиль MFA в шаблон"""
        try:
            result = self._server.v1.ccauth.cc2fa.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_2fa_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def get_template_terminal_servers(self, template_id):
        """Получить список терминальных серверов шаблона"""
        try:
            result = self._server.v1.ccauth.terminal.agent.list(self._auth_token, template_id, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_terminal_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список

    def add_template_terminal_server(self, template_id, server):
        """Добавить новый терминальнй сервер в шаблон"""
        try:
            result = self._server.v1.ccauth.terminal.agent.add(self._auth_token, template_id, server)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_terminal_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

    def update_template_terminal_server(self, template_id, server_id, server):
        """Обновить терминальнй серверв шаблоне"""
        try:
            result = self._server.v1.ccauth.terminal.agent.update(self._auth_token, template_id, server_id, server)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_terminal_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_template_useridagent_servers(self, template_id):
        """Получить список UserID агентов шаблона"""
        try:
            result = self._server.v1.ccuseridagent.servers.list(self._auth_token, template_id, 0, 50000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_useridagent_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список

    def add_template_useridagent_server(self, template_id, server):
        """Добавить новый агент UserID в шаблон"""
        try:
            result = self._server.v1.ccuseridagent.server.add(self._auth_token, template_id, server)
        except rpc.Fault as err:
            if err.faultCode == 9:
                return 3, f'Агент UserID "{server["name"]}" уже существует.'
            else:
                return 1, f'Error mclib.add_template_useridagent_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

    def update_template_useridagent_server(self, template_id, server_id, server):
        """Обновить агент UserID в шаблоне"""
        try:
            result = self._server.v1.ccuseridagent.server.update(self._auth_token, template_id, server_id, server)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_useridagent_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_template_useridagent_config(self, template_id):
        """Получить список параметров UserID шаблона"""
        try:
            result = self._server.v1.useridagent.get.agent.config(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_useridagent_config: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает dict

    def set_template_useridagent_config(self, template_id, config_info):
        """Установить параметры UserID агента шаблона"""
        try:
            result = self._server.v1.ccuseridagent.set.agent.config(self._auth_token, template_id, config_info)
        except rpc.Fault as err:
            return 1, f'Error mclib.set_template_useridagent_config: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

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

    def get_template_loadbalancing_rules(self, template_id, query={}):
        """
        Получить список правил балансировки нагрузки шаблона.
        query: {'query': 'type = reverse'} (Тип принимает значения: 'ipvs', 'icap', 'reverse')
        """
        try:
            result = self._server.v1.ccloadbalancing.rules.list(self._auth_token, template_id, 0, 100, query)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_loadbalancing_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_loadbalancing_rule(self, template_id, rule):
        """Добавить новое правило балансировки нагрузки в шаблон"""
        try:
            result = self._server.v1.ccloadbalancing.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_loadbalancing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_template_loadbalancing_rule(self, template_id, rule_id, rule):
        """Обновить правило балансировки нагрузки в шаблоне"""
        try:
            result = self._server.v1.ccloadbalancing.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_loadbalancing_rule: [{err.faultCode}] — {err.faultString}'
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

    def get_template_safebrowsing_rules(self, template_id):
        """Получить список правил веб-безопасности шаблона"""
        try:
            result = self._server.v1.cccontent.safe.browsing.rules.list(self._auth_token, template_id, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_template_safebrowsing_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_safebrowsing_rule(self, template_id, rule):
        """Добавить новое правило веб-безопасности в шаблон"""
        try:
            result = self._server.v1.cccontent.safe.browsing.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_safebrowsing_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_safebrowsing_rule(self, template_id, rule_id, rule):
        """Обновить правило веб-безопасности в шаблоне"""
        try:
            result = self._server.v1.cccontent.safe.browsing.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_safebrowsing_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_tunnel_inspection_rules(self, template_id):
        """Получить список правил инспектирования туннелей шаблона"""
        try:
            result = self._server.v1.ccfirewall.tunnel.inspection.rules.list(self._auth_token, template_id, 0, 5000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_tunnel_inspection_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_tunnel_inspection_rule(self, template_id, rule):
        """Добавить новое правило инспектирования туннелей в шаблон"""
        try:
            result = self._server.v1.ccfirewall.tunnel.inspection.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_tunnel_inspection_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_tunnel_inspection_rule(self, template_id, rule_id, rule):
        """Обновить правило инспектирования туннелей в шаблоне"""
        try:
            result = self._server.v1.ccfirewall.tunnel.inspection.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_tunnel_inspection_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_ssldecrypt_rules(self, template_id):
        """Получить список правил инспектирования SSL шаблона"""
        try:
            result = self._server.v1.cccontent.ssl.decryption.rules.list(self._auth_token, template_id, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_ssldecrypt_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_ssldecrypt_rule(self, template_id, rule):
        """Добавить новое правило инспектирования SSL в шаблон"""
        try:
            result = self._server.v1.cccontent.ssl.decryption.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_ssldecrypt_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_ssldecrypt_rule(self, template_id, rule_id, rule):
        """Обновить правило инспектирования SSL в шаблоне"""
        try:
            result = self._server.v1.cccontent.ssl.decryption.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_ssldecrypt_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_sshdecrypt_rules(self, template_id):
        """Получить список правил инспектирования SSH шаблона"""
        try:
            result = self._server.v1.cccontent.ssh.decryption.rules.list(self._auth_token, template_id, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_sshdecrypt_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_sshdecrypt_rule(self, template_id, rule):
        """Добавить новое правило инспектирования SSH в шаблон"""
        try:
            result = self._server.v1.cccontent.ssh.decryption.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_sshdecrypt_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_sshdecrypt_rule(self, template_id, rule_id, rule):
        """Обновить правило инспектирования SSH в шаблоне"""
        try:
            result = self._server.v1.cccontent.ssh.decryption.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_sshdecrypt_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_mailsecurity_rules(self, template_id):
        """Получить список правил защиты почтового трафика шаблона"""
        try:
            result = self._server.v1.ccmailsecurity.rules.list(self._auth_token, template_id, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_mailsecurity_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_mailsecurity_rule(self, template_id, rule):
        """Добавить новое правило защиты почтового трафика в шаблон"""
        try:
            result = self._server.v1.ccmailsecurity.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_mailsecurity_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_template_mailsecurity_rule(self, template_id, rule_id, rule):
        """Обновить правило защиты почтового трафика в шаблоне"""
        try:
            result = self._server.v1.ccmailsecurity.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_mailsecurity_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_mailsecurity_antispam(self, template_id):
        """Получить конфигурацию dnsbl и batv защиты почтового трафика шаблона"""
        try:
            result = self._server.v1.ccmailsecurity.antispam.fetch(self._auth_token, template_id)
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_mailsecurity_antispam: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_template_mailsecurity_antispam(self, template_id, config):
        """Установить конфигурацию антиспама для почтового трафика в шаблоне"""
        try:
            result = self._server.v1.ccmailsecurity.antispam.update(self._auth_token, template_id, config)
        except rpc.Fault as err:
            return 1, f'Error mclib.set_template_mailsecurity_antispam: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_icap_servers(self, template_id):
        """Получить список серверов ICAP шаблона"""
        try:
            result = self._server.v1.ccicap.profiles.list(self._auth_token, template_id, 0, 100, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_icap_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список настроек ICAP серверов

    def add_template_icap_server(self, template_id, server):
        """Добавить новый ICAP сервер в шаблон"""
        try:
            result = self._server.v1.ccicap.profile.add(self._auth_token, template_id, server)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_icap_server: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_icap_server(self, template_id, server_id, server):
        """Обновить ICAP сервер в шаблоне"""
        try:
            result = self._server.v1.ccicap.profile.update(self._auth_token, template_id, server_id, server)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_icap_server: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_icap_rules(self, template_id):
        """Получить список правил ICAP шаблона"""
        try:
            result = self._server.v1.ccicap.rules.list(self._auth_token, template_id, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_icap_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_icap_rule(self, template_id, rule):
        """Добавить новое ICAP-правило в шаблон"""
        try:
            result = self._server.v1.ccicap.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_icap_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_icap_rule(self, template_id, rule_id, rule):
        """Обновить ICAP-правило в шаблоне"""
        try:
            result = self._server.v1.ccicap.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_icap_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_dos_profiles(self, template_id):
        """Получить список профилей DoS шаблона"""
        try:
            result = self._server.v1.ccdos.profiles.list(self._auth_token, template_id, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_dos_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_dos_profile(self, template_id, profile):
        """Добавить новый профиль DoS в шаблон"""
        try:
            result = self._server.v1.ccdos.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_dos_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_dos_profile(self, template_id, profile_id, profile):
        """Обновить профиль DoS в шаблоне"""
        try:
            result = self._server.v1.ccdos.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_dos_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_dos_rules(self, template_id):
        """Получить список правил защиты DoS шаблона"""
        try:
            result = self._server.v1.ccdos.rules.list(self._auth_token, template_id, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_dos_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_dos_rule(self, template_id, rule):
        """Добавить новое правило защиты DoS в шаблон"""
        try:
            result = self._server.v1.ccdos.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_dos_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_dos_rule(self, template_id, rule_id, rule):
        """Обновить правило защиты DoS в шаблоне"""
        try:
            result = self._server.v1.ccdos.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_dos_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

############################# Глобальный портал #####################################################################
    def get_template_proxyportal_rules(self, template_id):
        """Получить список ресурсов URL веб-портала шаблона"""
        try:
            result = self._server.v1.ccproxyportal.bookmarks.list(self._auth_token, template_id, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_proxyportal_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_proxyportal_rule(self, template_id, rule):
        """Добавить новый URL-ресурс веб-портала в шаблон"""
        try:
            result = self._server.v1.ccproxyportal.bookmark.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_proxyportal_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_proxyportal_rule(self, template_id, rule_id, rule):
        """Обновить URL-ресурс веб-портала в шаблоне"""
        try:
            result = self._server.v1.ccproxyportal.bookmark.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_proxyportal_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_reverseproxy_servers(self, template_id):
        """Получить список серверов reverse-прокси шаблона"""
        try:
            result = self._server.v1.ccreverseproxy.profiles.list(self._auth_token, template_id, 0, 100000, {}, [])
            return 0, result['items']   # Возвращает список настроек серверов reverse-прокси
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_reverseproxy_servers: [{err.faultCode}] — {err.faultString}'
 
    def add_template_reverseproxy_server(self, template_id, profile):
        """Добавить новый сервер reverse-прокси в шаблон"""
        try:
            result = self._server.v1.ccreverseproxy.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_reverseproxy_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_reverseproxy_server(self, template_id, profile_id, profile):
        """Обновить сервер reverse-прокси в шаблоне"""
        try:
            result = self._server.v1.ccreverseproxy.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_reverseproxy_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_reverseproxy_rules(self, template_id):
        """Получить список правил reverse-прокси шаблона"""
        try:
            result = self._server.v1.ccreverseproxy.rules.list(self._auth_token, template_id, 0, 100000, {})
            return 0, result['items']
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_reverseproxy_rules: [{err.faultCode}] — {err.faultString}'

    def add_template_reverseproxy_rule(self, template_id, rule):
        """Добавить новое правило reverse-прокси в шаблон"""
        try:
            result = self._server.v1.ccreverseproxy.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_reverseproxy_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_reverseproxy_rule(self, template_id, rule_id, rule):
        """Обновить правило reverse-прокси в шаблоне"""
        try:
            result = self._server.v1.ccreverseproxy.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_reverseproxy_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

################################### WAF #############################################################################
    def get_template_waf_profiles(self, template_id):
        """Получить список профилей WAF шаблона"""
        try:
            result = self._server.v1.ccwaf.profiles.list(self._auth_token, template_id, 0, 100000, {}, [])
        except rpc.Fault as err:
            if err.faultCode == 5:
                return 2, f'Нет прав на получение профилей WAF шаблона [Error mclib.get_realms_list: {err.faultString}].'
            else:
                return 1, f'Error mclib.get_template_waf_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

################################### VPN #############################################################################
    def get_template_vpn_client_security_profiles(self, template_id):
        """Получить клиентские профили безопасности VPN шаблона"""
        try:
            result = self._server.v1.ccvpn.client.security.profiles.list(self._auth_token, template_id, 0, 100000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_vpn_client_security_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_vpn_client_security_profile(self, template_id, profile):
        """Добавить клиентский профиль безопасности VPN в шаблон"""
        try:
            result = self._server.v1.ccvpn.client.security.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add__templatevpn_client_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_vpn_client_security_profile(self, template_id, profile_id, profile):
        """Обновить клиентский профиль безопасности VPN в шаблоне"""
        try:
            result = self._server.v1.ccvpn.client.security.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_vpn_client_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_vpn_server_security_profiles(self, template_id):
        """Получить серверные профили безопасности VPN шаблона"""
        try:
            result = self._server.v1.ccvpn.server.security.profiles.list(self._auth_token, template_id, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_vpn_server_security_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_vpn_server_security_profile(self, template_id, profile):
        """Добавить серверный профиль безопасности VPN в шаблон"""
        try:
            result = self._server.v1.ccvpn.server.security.profile.add(self._auth_token, template_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_vpn_server_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_vpn_server_security_profile(self, template_id, profile_id, profile):
        """Обновить серверный профиль безопасности VPN в шаблоне"""
        try:
            result = self._server.v1.ccvpn.server.security.profile.update(self._auth_token, template_id, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_vpn_server_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_vpn_networks(self, template_id):
        """Получить список сетей VPN шаблона"""
        try:
            result = self._server.v1.ccvpn.tunnels.list(self._auth_token, template_id, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_vpn_networks: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_vpn_network(self, template_id, network):
        """Добавить новую сеть VPN в шаблон"""
        try:
            result = self._server.v1.ccvpn.tunnel.add(self._auth_token, template_id, network)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_vpn_network: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_vpn_network(self, template_id, network_id, network):
        """Обновить сеть VPN в шаблоне"""
        try:
            result = self._server.v1.ccvpn.tunnel.update(self._auth_token, template_id, network_id, network)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_vpn_network: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_vpn_server_rules(self, template_id):
        """Получить список серверных правил VPN шаблона"""
        try:
            result = self._server.v1.ccvpn.server.rules.list(self._auth_token, template_id, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_vpn_server_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_vpn_server_rule(self, template_id, rule):
        """Добавить новое серверное правило VPN в шаблон"""
        try:
            result = self._server.v1.ccvpn.server.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_vpn_server_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_vpn_server_rule(self, template_id, rule_id, rule):
        """Обновить серверное правило VPN в шаблоне"""
        try:
            result = self._server.v1.ccvpn.server.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_vpn_server_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_template_vpn_client_rules(self, template_id):
        """Получить список клиентских правил VPN шаблона"""
        try:
            result = self._server.v1.ccvpn.client.rules.list(self._auth_token, template_id, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error mclib.get_template_vpn_client_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_template_vpn_client_rule(self, template_id, rule):
        """Добавить новое клиентское правило VPN в шаблон"""
        try:
            result = self._server.v1.ccvpn.client.rule.add(self._auth_token, template_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.add_template_vpn_client_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_template_vpn_client_rule(self, template_id, rule_id, rule):
        """Обновить клиентское правило VPN в шаблоне"""
        try:
            result = self._server.v1.ccvpn.client.rule.update(self._auth_token, template_id, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error mclib.update_template_vpn_client_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

############################# Служебные методы ######################################################################
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
        """Получить список приложений l7 шаблона"""
        try:
            result = self._server.v1.ccl7.signatures.list(self._auth_token, template_id, 0, 500000, {}, [])
            return 0, [{'id': x['signature_id'], 'name': x['name']} for x in result['items']]
        except rpc.Fault as err:
            return 1, f"Error mclib.get_l7_apps: [{err.faultCode}] — {err.faultString}"

    def get_l7_categories(self):
        """
        Получить список категорий l7.
        В версиях до 7.1 возвращает список: [{'id': category_id, 'name': category_name, 'app_list': [id_app_1, id_app_2, ...]}, ...]
        В версиях начиная с 7.1 возвращает список: [{'id': category_id, 'name': category_name}, ...]
        """
        try:
            result = self._server.v1.ccl7.get.categories(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error mclib.get_l7_categories: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result['items']
#####################################################################################################

class UtmError(Exception): pass

