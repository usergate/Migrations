#!/usr/bin/python3
# Версия 3.18 07.10.2024
# Общий класс для работы с xml-rpc
#
# Коды возврата:
# 0 - Успешно
# 1 - Ошибка выполнения
# 2, 3 и далее - Информационные сообщения
#-----------------------------------------------------------------------------------------------------------
import sys
import xmlrpc.client as rpc
from xml.parsers.expat import ExpatError


class UtmXmlRpc:
    def __init__(self, server_ip, login, password):
        self.server_ip = server_ip
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4040/rpc'
        self._auth_token = None
        self._server = None
        self.node_name = None
        self.version = None
        self.version_hight = None
        self.version_midle = None
        self.version_low = None
        self.version_other = None
        self.float_version = None
        self.waf_license = False

        rpc.MAXINT = 2**64 - 1

    def connect(self):
        """Подключиться к UTM"""
        try:
            self._server = rpc.ServerProxy(self._url, verbose=False, allow_none=True)
        except OSError as err:
            return 1, f'Ошибка utm.connect: {err} (Node: {self.server_ip}).'
        except rpc.ProtocolError as err:
            return 1, f'Ошибка utm.connect: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).'
        except rpc.Fault as err:
            return 1, f'Ошибка utm.connect: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).'
        return self.login()

    def login(self):
        try:
            err, status = self.get_node_status()
            if status == 'work':
                result = self._server.v2.core.login(self._login, self._password, {'origin': 'dev-script'})
            else:
                return 1, f'Ошибка utm.login: UTM не позволяет установить соединение! Status: "{status}".'
        except OSError as err:
            return 1, f'Ошибка utm.login: {err} (Node: {self.server_ip}).'
        except rpc.ProtocolError as err:
            return 1, f'Ошибка utm.login: [{err.errcode}] {err.errmsg} (Node: {self.server_ip}).'
        except rpc.Fault as err:
            return 1, f'Ошибка utm.login: [{err.faultCode}] {err.faultString} (Node: {self.server_ip}).'
        else:
            self._auth_token = result.get('auth_token')
            self.node_name =  result.get('node')
            self.version = result.get('version')
            tmp = self.version.split(".")
            self.version_hight = int(tmp[0])
            self.version_midle = int(tmp[1])
            self.version_low = int(''.join(n for n in tmp[2] if n.isdecimal()))
            self.version_other = tmp[3]
            self.float_version = float(f'{tmp[0]}.{tmp[1]}')
            self.waf_license = False    # При новом логине сбрасываем значение
            try:
                result = self._server.v2.core.license.info(self._auth_token)
                for item in result['modules']:
                    if item['name'] == 'waf': self.waf_license = True
            except rpc.Fault as err:
                return 1, f"Error utm.login: Не удалось получить список лицезированных модулей. [{err.faultCode}] — {err.faultString}"
            return 0, True

    def get_node_status(self):
        """Получить статус узла"""
        result = self._server.v2.core.node.status()
        return 0, result.get('status')

    def logout(self):
        if self._server and self._auth_token:
            if not self.ping_session()[0]:
                self._server.v2.core.logout(self._auth_token)
        return 0, True

    def ping_session(self):
        """Ping сессии"""
        try:
            result = self._server.v2.core.session.ping(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 104:
                return 2, f'Сессия завершилась по таймауту.'
            else:
                return 1, f"Ошибка utm.ping_session: [{err.faultCode}] — {err.faultString}"
        except OSError as err:
            return 1, f'Ошибка utm.login: {err} (Node: {self.server_ip}).'
        return 0, result # Возвращает True

################################### Settings ####################################
    def get_settings_parameter(self, param):
        """
        Получить один параметр.
        """
        try:
            result = self._server.v2.settings.get.param(self._auth_token, param)
        except rpc.Fault as err:
            return 1, f"Error utm.get_settings_parameter: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_settings_params(self, params):
        """
        Получить несколько параметров за 1 запрос.
        params - list of params
        Возвращает dict
        """
        try:
            result = self._server.v2.settings.get.params(self._auth_token, params)
        except rpc.Fault as err:
            return 1, f"Error utm.get_settings_params: [{err.faultCode}] — {err.faultString}"
        return 0, result    # Возвращает список словарей [{name: value}, ...]

    def set_settings_param(self, param_name, param_value):
        """Изменить параметр"""
        try:
            result = self._server.v2.settings.set.param(self._auth_token, param_name, param_value)
        except rpc.Fault as err:
            return 1, f"Error utm.set_settings_param: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает True

    def get_webui_auth_mode(self):
        """Получить режим аутентификации веб-консоли"""
        try:
            result = self._server.v2.settings.webui.auth.mode.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_webui_auth_mode: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_proxy_port(self):
        """Получить порт прокси"""
        try:
            result = self._server.v2.settings.proxy.port.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_proxy_port: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает номер порта

    def set_proxy_port(self, port):
        """Изменить порт прокси"""
        try:
            result = self._server.v2.settings.proxy.port.set(self._auth_token, port)
        except rpc.Fault as err:
            return 1, f"Error utm.set_proxy_port: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает True

    def get_ntp_config(self):
        """Получить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_ntp_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def add_ntp_config(self, ntp):
        """Обновить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.set(self._auth_token, ntp)
        except rpc.Fault as err:
            return 1, f"Error utm.add_ntp_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_upstream_proxy_settings(self):
        """Получить настройки вышестоящего прокси"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v2.settings.upstream.proxy.config.get(self._auth_token)
                return 0, result
            else:
                return 1, 'Error utm.get_upstream_proxy_settings: This method is only available for version 7.1 and higher.'
        except rpc.Fault as err:
            return 1, f"Error utm.get_upstream_proxy_settings: [{err.faultCode}] — {err.faultString}"

    def set_upstream_proxy_settings(self, settings):
        """Обновить настройки вышестоящего прокси"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v2.settings.upstream.proxy.config.set(self._auth_token, settings)
                return 0, result    # Возвращает True
            else:
                return 1, 'Error utm.set_upstream_proxy_settings: This method is only available for version 7.1 and higher.'
        except rpc.Fault as err:
            return 1, f"Error utm.set_upstream_proxy_settings: [{err.faultCode}] — {err.faultString}"

    def get_statistics_status(self):
        """
        Получить настройки Log Analyzer.
        """
        try:
            result = self._server.v1.statistics.status(self._auth_token)
            result2 = self._server.v2.settings.stat.server.config.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_statistics_status: [{err.faultCode}] — {err.faultString}"
        result.update(result2)
        return 0, result

    def get_mc_config(self):
        """Получить парамтры Management Center"""
        try:
            result = self._server.v2.settings.ccclient.config.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_mc_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

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

    def get_admin_profiles_list(self):
        """Получить список профилей администраторов"""
        try:
            if self.float_version >= 7.0:
                result = self._server.v2.core.administrator.profiles.list(self._auth_token, 0, 1000, {}, [])
                return 0, result['items']
            else:
                result = self._server.v2.core.administrator.profiles.list(self._auth_token)
                return 0, result
        except rpc.Fault as err:
            return 1, f"Error utm.get_admin_profiles_list: [{err.faultCode}] — {err.faultString}"

    def add_admin_profile(self, profile):
        """Добавить новый профиль администраторов"""
        try:
            result = self._server.v2.core.administrator.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            if err.faultCode == 111:
                return 2, f"Профиль '{profile['name']}' не добавлен, так как русские буквы в имени профиля запрещены."
            else:
                return 1, f"Error utm.add_admin_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_admin_profile(self, profile_id, profile):
        """Обновить профиль администраторов"""
        try:
            result = self._server.v2.core.administrator.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f"Error utm.update_admin_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_admin_config(self):
        """Получить список настроек пароля администраторов"""
        try:
            result = self._server.v2.core.administrator.config.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_admin_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def set_admin_config(self, params):
        """Изменить настройки пароля администраторов"""
        try:
            result = self._server.v2.core.administrator.config.set(self._auth_token, params)
        except rpc.Fault as err:
            return 1, f"Error utm.set_admin_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_admin_list(self):
        """Получить список администраторов"""
        try:
            if self.float_version >= 7.0:
                result = self._server.v2.core.administrator.list(self._auth_token, 0, 1000, {}, [])
                return 0, result['items']
            else:
                result = self._server.v2.core.administrator.list(self._auth_token, {})
                return 0, result
        except rpc.Fault as err:
            return 1, f"Error utm.get_admin_list: [{err.faultCode}] — {err.faultString}"

    def add_admin(self, admin):
        """Добавить нового администратора"""
        try:
            result = self._server.v2.core.administrator.add(self._auth_token, admin)
        except rpc.Fault as err:
            if err.faultCode == 111:
                return 2, f"Администратор '{admin['login']}' не добавлен, так как не найден профиль или имя профиля в русском регистре."
            else:
                return 1, f"Error utm.add_admin: [{err.faultCode}] — {err.faultString}: {admin['login']}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_admin(self, admin_id, admin):
        """Обновить администратора"""
        try:
            result = self._server.v2.core.administrator.update(self._auth_token, admin_id, admin)
        except rpc.Fault as err:
            if err.faultCode == 111:
                return 2, f"Ошибка обновления '{admin['login']}'. Не найден профиль администратора или имя профиля в русском регистре."
            else:
                return 1, f"Error utm.update_admin: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_certificates_list(self):
        """Получить список сертификатов"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v2.settings.certificates.list(self._auth_token, 0, 100, {})
                return 0, result['items']
            else:
                result = self._server.v2.settings.certificates.list(self._auth_token)
                return 0, result
        except rpc.Fault as err:
            return 1, f"Error utm.get_certificates_list: [{err.faultCode}] — {err.faultString}"

    def get_certificate_details(self, cert_id):
        """Получить детальную информацию по сертификату"""
        try:
            result = self._server.v2.settings.certificate.details(self._auth_token, cert_id)
        except rpc.Fault as err:
            return 1, f"Error utm.get_certificate_details: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_certificate_data(self, cert_id):
        """Выгрузить сертификат в DER формате"""
        try:
            result = self._server.v2.settings.certificate.getData(self._auth_token, cert_id)
        except rpc.Fault as err:
            return 1, f"Error utm.get_certificate_data: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_certificate_chain_data(self, cert_id):
        """Выгрузить сертификат и всю цепочку сертификатов в PEM формате"""
        try:
            result = self._server.v2.settings.certificate.getCertWithChainData(self._auth_token, cert_id)
        except rpc.Fault as err:
            return 1, f"Error utm.get_certificate_chain_data: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def add_certificate(self, cert):
        """Добавить новый сертификат"""
        try:
            result = self._server.v2.setting.certificate.add(self._auth_token, cert)
        except rpc.Fault as err:
            return 1, f'Error utm.add_certificate: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def get_snmp_engine(self):
        """Выгрузить SNMP Engine ID"""
        if self.version_hight == 5:
            return 1, 'Error utm.get_snmp_engine: В версии 5 snmp engine не поддерживается.'
        else:
            try:
                if self.float_version >= 7.1:
                    result = self._server.v1.snmp.engine.id.get(self._auth_token, self.node_name)
                else:
                    result = self._server.v1.snmp.engine.id.get(self._auth_token)
            except rpc.Fault as err:
                return 1, f'Error utm.get_snmp_engine: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_snmp_engine(self, engine):
        """Установить SNMP Engine ID"""
        if self.version_hight == 5:
            return 1, 'Error utm.get_snmp_engine: В версии 5 snmp engine не поддерживается.'
        else:
            try:
                if self.float_version >= 7.1:
                    result = self._server.v1.snmp.engine.id.set(self._auth_token, self.node_name, engine)
                else:
                    result = self._server.v1.snmp.engine.id.set(self._auth_token, engine)
            except rpc.Fault as err:
                return 1, f'Error utm.set_snmp_engine: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_client_certificate_profiles(self):
        """Получить список профилей пользовательских сертификатов"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.certificates.client.profiles.list(self._auth_token, 0, 500, {}, [])
                return 0, result['items']
            else:
                return 1, 'Error utm.get_client_certificate_profiles: This method is only available for version 7.1 and higher.'
        except rpc.Fault as err:
            return 1, f'Error utm.get_client_certificate_profiles: [{err.faultCode}] — {err.faultString}'

    def add_client_certificate_profile(self, profile):
        """Создать профиль сертификата пользователя"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.certificates.client.profile.add(self._auth_token, profile)
                return 0, result    # Возвращает ID созданного профиля
            else:
                return 1, 'Error utm.add_client_certificate_profile: This method is only available for version 7.1 and higher.'
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Профиль "{profile["name"]} уже существует.'
            else:
                return 1, f'Error utm.add_client_certificate_profile: [{err.faultCode}] — {err.faultString}'

##################################### Network #####################################
    def get_zones_list(self):
        """Получить список зон"""
        try:
            result = self._server.v1.netmanager.zones.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error utm.get_zones_list: [{err.faultCode}] — {err.faultString}"
        return 0, result    # Возвращает список зон.

    def add_zone(self, zone):
        """Добавить зону"""
        try:
            result = self._server.v1.netmanager.zone.add(self._auth_token, zone)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f"Зона {zone['name']} уже существует."
            elif err.faultCode == 111:
                return 1, f"Error: Зона '{zone['name']}' не добавлена [{err.faultString}]"
            else:
                return 1, f"Error utm.add_zone: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result    # Возвращает ID добавленной зоны

    def update_zone(self, zone_id, zone):
        """Обновить параметры зоны"""
        try:
            result = self._server.v1.netmanager.zone.update(self._auth_token, zone_id, zone)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f"Зона: {zone['name']} - нет отличающихся параметров для изменения."
            else:
                return 1, f"Error utm.update_zone: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result    # Возвращает True

    def get_gateways_list(self):
        """Получить список шлюзов"""
        try:
            result = self._server.v1.netmanager.gateways.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            return 1, f"Error utm.get_gateways_list: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def add_gateway(self, gateway):
        """Добавить новый шлюз"""
        try:
            result = self._server.v1.netmanager.gateway.add(self._auth_token, self.node_name, gateway)
        except rpc.Fault as err:
            if err.faultCode == 1019:
                return 2, f'Error: Шлюз "{gateway["name"]}" не импортирован! Duplicate IP.'
            else:
                return 1, f"Error utm.add_gateway: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_gateway(self, gateway_id, gateway):
        """Обновить шлюз"""
        try:
            result = self._server.v1.netmanager.gateway.update(self._auth_token, self.node_name, gateway_id, gateway)
        except rpc.Fault as err:
            return 1, f"Error utm.update_gateway: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_gateway_failover(self):
        """Получить настройки проверки сети шлюзов"""
        try:
            result = self._server.v1.netmanager.failover.config.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f"Error get_gateway_failover: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def set_gateway_failover(self, params):
        """Изменить настройки проверки сети шлюзов"""
        try:
            result = self._server.v1.netmanager.failover.config.set(self._auth_token, params)
        except rpc.Fault as err:
            return 1, f"Error utm.set_gateway_failover: [{err.faultCode}] — {err.faultString}"
        return 0, result    # Возвращает True

################################## Interfaces ###################################
    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, 0, 1000, {})
                return 0, result['items']
            else:
                result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
                return 0, result
        except rpc.Fault as err:
            return 1, f"Error utm.get_interfaces_list: [{err.faultCode}] — {err.faultString}"

    def update_interface(self, iface_id, iface):
        """Update interface"""
        try:
            if iface['kind'] == 'vpn':
                result = self._server.v1.netmanager.interface.update(self._auth_token, 'cluster', iface_id, iface)
            else:
                result = self._server.v1.netmanager.interface.update(self._auth_token, self.node_name, iface_id, iface)
        except rpc.Fault as err:
            if err.faultCode == 1014:
                return 2, f'Error update interface "{iface["name"]}": Cannot update slave interface.'
            elif err.faultCode == 18009:
                return 2, f'Error update interface "{iface["name"]}": IP address conflict - {iface["ipv4"]}.'
            else:
                return 1, f'Error utm.update_interface: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def add_interface_bond(self, bond):
        """Добавить bond интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.bond(self._auth_token, self.node_name, bond['name'], bond)
        except rpc.Fault as err:
            return 1, f"Error utm.add_interface_bond: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает имя добавленного интерфейса

    def add_interface_bridge(self, bridge):
        """Добавить bridge интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.bridge(self._auth_token, self.node_name, bridge['name'], bridge)
        except rpc.Fault as err:
            return 1, f"Error utm.add_interface_bridge: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает имя добавленного интерфейса

    def add_interface_vlan(self, vlan):
        """Добавить vlan интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.vlan(self._auth_token, self.node_name, vlan['name'], vlan)
        except rpc.Fault as err:
            return 1, f"Error utm.add_interface_vlan: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает имя добавленного интерфейса

    def add_interface_pppoe(self, ppp):
        """Добавить PPPoE интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.pppoe(self._auth_token, self.node_name, ppp['name'], ppp)
        except rpc.Fault as err:
            return 1, f"Return utm.add_interface_pppoe: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает имя добавленного интерфейса

    def add_interface_tunnel(self, tunnel):
        """Добавить TUNNEL интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.tunnel(self._auth_token, self.node_name, tunnel['name'], tunnel)
        except rpc.Fault as err:
            if err.faultCode == 1205:
                return 2, f'Интерфейс с таким IP-адресом {tunnel["ipv4"]} уже существует [{err.faultString}].'
            else:
                return 1, f"Error utm.add_interface_tunnel: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает имя добавленного интерфейса

    def add_interface_vpn(self, vpn):
        """Добавить VPN интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.vpn(self._auth_token, 'cluster', vpn['name'], vpn)
        except rpc.Fault as err:
            if err.faultCode == 18004:
                return 2, f'Интерфейс {vpn["name"]} пропущен так как содержит IP принадлежащий подсети другого интерфейса VPN!.'
            else:
                return 1, f'Error utm.add_interface_vpn: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает имя добавленного интерфейса

##################################### DHCP ######################################
    def get_dhcp_list(self):
        """Получить список подсетей для dhcp"""
        try:
            result = self._server.v1.netmanager.dhcp.subnets.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            return 1, f"Error utm.get_dhcp_list: [{err.faultCode}] — {err.faultString}"
        return 0, result    # Возвращает list of all DHCP subnets on that node

    def add_dhcp_subnet(self, subnet):
        """Добавить DHCP subnet"""
        try:
            result = self._server.v1.netmanager.dhcp.subnet.add(self._auth_token, self.node_name, subnet)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 1017:
                return 2, f'DHCP subnet "{subnet["name"]}" уже существует.'
            else:
                return 1, f"Error utm.add_dhcp_subnet: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result    # Возвращает ID созданной subnet

##################################### DNS ######################################
    def get_dns_servers(self):
        """Получить список системных DNS-серверов"""
        try:
            dns_servers = self._server.v2.settings.custom.dnses.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_dns_servers: [{err.faultCode}] — {err.faultString}'
        return 0, dns_servers   # Возвращает список серверов dns

    def get_dns_rules(self):
        """Получить список правил DNS"""
        try:
            dns_rules = self._server.v1.dns.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_dns_rules: [{err.faultCode}] — {err.faultString}'
        return 0, dns_rules['items']    # Возвращает список правил

    def get_dns_static_records(self):
        """Получить список статических записей DNS"""
        try:
            static_records = self._server.v1.dns.static.records.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_dns_static_records: [{err.faultCode}] — {err.faultString}'
        return 0, static_records['items']   # Возвращает список статических запией

    def add_dns_server(self, dns_server):
        """Добавить DNS server"""
        try:
            result = self._server.v2.settings.custom.dns.add(self._auth_token, dns_server)
        except rpc.Fault as err:
            if err.faultCode == 18004:
                return 2, f'DNS server "{dns_server["dns"]}" уже существует.'
            else:
                return 1, f'Error utm.add_dns_server: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result    # Возвращает ID добавленноё записи

    def add_dns_rule(self, dns_rule):
        """Добавить правило DNS"""
        try:
            result = self._server.v1.dns.rule.add(self._auth_token, dns_rule)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Правило DNS "{dns_rule["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_dns_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result    # Возвращает ID добавленноё записи

    def add_dns_static_record(self, dns_record):
        """Добавить статическую запись DNS"""
        try:
            result = self._server.v1.dns.static.record.add(self._auth_token, dns_record)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Статическая запись DNS "{dns_record["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_dns_static_record: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result    # Возвращает ID добавленноё записи
######################################## WCCP  ########################################
    def get_wccp_list(self):
        """Получить список правил wccp"""
        try:
            result = self._server.v1.wccp.rules.list(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 102:
                return 2, f'Ошибка: нет прав на чтение конфигурации WCCP. Конфигурация WWCP не выгружена.'
            else:
                return 1, f'Error utm.get_wccp_list: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает список записей

    def add_wccp_rule(self, rule):
        """Добавить правило wccp"""
        try:
            result = self._server.v1.wccp.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_wccp_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_wccp_rule(self, rule_id, rule):
        """Изменить правило wccp"""
        try:
            result = self._server.v1.wccp.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_wccp_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

######################################## Маршруты  ########################################
    def get_routes_list(self):
        """Получить список VRFs со всей конфигурацией"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.netmanager.route.list(self._auth_token, self.node_name, {})
            else:
                result = self._server.v1.netmanager.virtualrouters.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_routers_list: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает список записей

    def get_vrf_by_id(self, vrf_id):
        """Получить список VRFs со всей конфигурацией"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.netmanager.route.fetch(self._auth_token, self.node_name, vrf_id)
            else:
                result = self._server.v1.netmanager.virtualrouter.fetch(self._auth_token, vrf_id)
        except rpc.Fault as err:
            return 1, f'Error utm.get_vrf_by_id: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает vfr

    def add_vrf(self, vrf_info):
        """Добавить виртуальный маршрутизатор"""
        try:
            result = self._server.v1.netmanager.virtualrouter.add(self._auth_token, vrf_info)
        except rpc.Fault as err:
            if err.faultCode == 1015:
                return 2, f'Error: В виртуальном маршрутизаторе "{vrf_info["name"]}" указан несуществующий порт: {vrf_info["interfaces"]}.'
            elif err.faultCode == 1016:
                return 2, f'Error: В виртуальном маршрутизаторе "{vrf_info["name"]}" указан порт использующийся в другом маршрутизаторе: {vrf_info["interfaces"]}.'
            else:
                return 1, f'Error utm.add_vrf: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного VRF

    def update_vrf(self, vrf_id, vrf_info):
        """Изменить настройки виртуального маршрутизатора"""
        try:
            result = self._server.v1.netmanager.virtualrouter.update(self._auth_token, vrf_id, vrf_info)
        except rpc.Fault as err:
            if err.faultCode == 1020:
                return 2, f'Error: В виртуальном маршрутизаторе "{rule["name"]}" указан порт использующийся в другом маршрутизаторе: {rule["interfaces"]} [{err.faultString}]'
            return 1, f'Error utm.update_vrf: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def get_bfd_profiles(self):
        """Получить список BFD профилей для BGP"""
        try:
            result = self._server.v1.netmanager.bfd.profiles.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_bfd_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список профилей

    def get_ospf_config(self):
        """Получить конфигурацию OSPF (только для v.5)"""
        try:
            data = self._server.v1.netmanager.ospf.router.fetch(self._auth_token, self.node_name)
            ifaces = self._server.v1.netmanager.ospf.interfaces.list(self._auth_token, self.node_name)
            areas = self._server.v1.netmanager.ospf.areas.list(self._auth_token, self.node_name)
        except rpc.Fault as err:
            return 1, f'Error utm.get_ospf_config: [{err.faultCode}] — {err.faultString}', False, False
        return 0, data, ifaces, areas

    def get_bgp_config(self):
        """Получить конфигурацию BGP (только для v.5)"""
        try:
            data = self._server.v1.netmanager.bgp.router.fetch(self._auth_token, self.node_name)
            neigh = self._server.v1.netmanager.bgp.neighbors.list(self._auth_token, self.node_name)
            rmaps = self._server.v1.netmanager.bgp.routemaps.list(self._auth_token, self.node_name)
            filters = self._server.v1.netmanager.bgp.filters.list(self._auth_token, self.node_name)
        except rpc.Fault as err:
            return 1, f'Error utm.get_bgp_config: [{err.faultCode}] — {err.faultString}', False, False, False
        return 0, data, neigh, rmaps, filters

##################################### Библиотека  ######################################
    def get_custom_url_list(self):
        """Получить список изменённых категорий URL раздела Библиотеки"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.content.override.domains.list(self._auth_token, 0, 10000, {})
            else:
                result = self._server.v1.content.override.domains.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error get_custom_url_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_custom_url(self, data):
        """Добавить изменённую категорию URL"""
        try:
            result = self._server.v1.content.override.domain.add(self._auth_token, data)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Категория URL: "{data["name"]}" уже существует'
            else:
                return 1, f'Error utm.add_custom_url: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def update_custom_url(self, data_id, data):
        """Обновить изменённую категорию URL"""
        try:
            result = self._server.v1.content.override.domain.update(self._auth_token, data_id, data)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Категория URL: "{data["name"]}" - нет отличающихся параметров для изменения.'
            else:
                return 1, f'Error utm.update_custom_url: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def get_nlists_list(self, list_type):
        """Получить список именованных списков по их типу из Библиотеки"""
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_nlists_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает лист списков (список словарей).

    def get_nlist_list(self, list_type):
        """Получить список пользовательских именованных списков c их содержимым."""
        array = []
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_nlist_list: [{err.faultCode}] — {err.faultString}'

        for item in result['items']:
            if item['editable']:
                item['name'] = item['name'].strip()
                content = {}
                try:
                    if (list_type == 'ipspolicy' and self.version_hight == 5) \
                             or (self.float_version == 6.1 and self.version_low >= 8):
#                             or (self.float_version == 6.1 and self.version_low > 8):
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 100000, {}, [])
                    elif self.version_hight >= 7:
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 100000, {}, [])
                    else:
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 100000, '', [])
                except rpc.Fault as err:
                    return 2, f'Error: Содержимое списка "{item["name"]}" не экспортировано. Ошибка загрузки списка!'
                except ExpatError:
                    return 2, f'Error: Содержимое списка "{item["name"]}" не экспортировано. Список corrupted!'
                except UnboundLocalError:
                    return 1, f'Error: Содержимое списка "{item["name"]}" не экспортировано. Ошибка программы!'

                if list_type == 'timerestrictiongroup' and self.version_hight == 5:
                    item['content'] = [x['value'] for x in content['items']]
                elif list_type == 'httpcwl':
                    array = {'id': item['id'], 'content': content['items']}
                    break
                else:
                    item['content'] = content['items']
                array.append(item)
        return 0, array

    def add_nlist(self, named_list):
        """Добавить именованный список"""
        try:
            result = self._server.v2.nlists.add(self._auth_token, named_list)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Список "{named_list["name"]}" уже существует'
            else:
                return 1, f'Error utm.add_nlist: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result    # Возвращает ID списка

    def update_nlist(self, named_list_id, named_list):
        """Обновить параметры именованного списка"""
        try:
            result = self._server.v2.nlists.update(self._auth_token, named_list_id, named_list)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Список "{named_list["name"]}" - нет отличающихся параметров для изменения.'
            else:
                return 1, f'Error utm.update_nlist: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def add_nlist_item(self, named_list_id, item):
        """Добавить 1 значение в именованный список"""
        try:
            result = self._server.v2.nlists.list.add(self._auth_token, named_list_id, item)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 2001:
                return 2, f"Содержимое: {item} не добавлено, так как уже существует [{err}]."
            else:
                return 1, f"Error utm.add_nlist_item: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_nlist_items(self, named_list_id, items):
        """Добавить список значений в именованный список"""
        try:
            result = self._server.v2.nlists.list.add.items(self._auth_token, named_list_id, items)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 2001:
                return 2, f"Содержимое: {items} не добавлено, так как уже существует."
            elif err.faultCode == 2003:
                return 2, f"Содержимое: {items} не добавлено, так как обновляется через URL."
            else:
                return 1, f'Error utm.add_nlist_items: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result    # Возвращает число успешно добавленных записей

    def get_services_list(self):
        """Получить список сервисов раздела Библиотеки"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 50000, '', [])
            else:
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 50000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_services_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает лист сервисов (список словарей).

    def add_service(self, service):
        """Добавить список сервисов раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.add(self._auth_token, service)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Сервис "{service["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_service: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID сервиса

    def update_service(self, service_id, service):
        """Обновить отдельный сервис раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.update(self._auth_token, service_id, service)
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 2, f'Не удалось обновить сервис "{service["name"]}" c id: {service_id}. Данный сервис не найден.'
            else:
                return 1, f'Error utm.update_service: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_shaper_list(self):
        """Получить список полос пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Ошибка utm.get_shaper_list: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def add_shaper(self, shaper):
        """Добавить полосу пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.add(self._auth_token, shaper)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Полоса пропускания "{shaper["name"]}" уже существует.'
            elif err.faultCode == 406:
                return 2, f'Полоса пропускания "{shaper["name"]}" не добавлена! Превышено максимальное количество записей.'
            else:
                return 1, f'Error utm.add_shaper: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID шейпера

    def update_shaper(self, shaper_id, shaper):
        """Обновить полосу пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.update(self._auth_token, shaper_id, shaper)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 2, f'Не удалось обновить полосу пропускания "{shaper["name"]}" c id: {shaper_id}. Данная полоса пропускания не найдена.'
            else:
                return 1, f'Error utm.update_shaper: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_scada_list(self):
        """Получить список профилей АСУ ТП раздела Библиотеки"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, '', [])
            else:
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_scada_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_scada(self, scada):
        """Добавить профиль АСУ ТП раздела Библиотеки"""
        try:
            result = self._server.v1.scada.profile.add(self._auth_token, scada)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Профиль АСУ ТП "{scada["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_scada: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID шейпера

    def update_scada(self, scada_id, scada):
        """Обновить профиль АСУ ТП раздела Библиотеки"""
        try:
            result = self._server.v1.scada.profile.update(self._auth_token, scada_id, scada)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_scada: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_templates_list(self):
        """Получить список шаблонов страниц раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.templates.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_templates_list: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def add_template(self, template):
        """Добавить новый шаблон в раздел "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.add(self._auth_token, template)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Шаблон страницы "{template["name"]}" уже существует.'
            elif err.faultCode == 111:
                return 2, f'Шаблон "{template["name"]}" не добавлен. Эта ошибка исправлена в версии 7.0.2.'
            else:
                return 1, f'Error utm.add_template: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID шаблона

    def update_template(self, template_id, template):
        """Обновить шаблон в разделе "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.update(self._auth_token, template_id, template)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 2, f'Не удалось обновить шаблон страницы. Данная страница не найдена.'
            else:
                return 1, f'Error utm.update_template: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_template_data(self, template_type, template_id):
        """Получить HTML страницы шаблона раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.public.data.fetch(template_type, template_id)
        except rpc.Fault as err:
            return 1, f'Error utm.get_template_data: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_template_data(self, template_id, data):
        """Импортировать страницу HTML шаблона раздела Библиотеки"""
        try:
            data64 = rpc.Binary(data)
            result = self._server.v1.libraries.response.page.template.data.update(self._auth_token, template_id, data64)
        except rpc.Fault as err:
            return 1, f'Error utm.set_template_data: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_notification_profiles_list(self):
        """Получить список профилей оповещения"""
        try:
            result = self._server.v1.notification.profiles.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_notification_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает список словарей

    def add_notification_profile(self, profile):
        """Добавить профиль оповещения"""
        try:
            result = self._server.v1.notification.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_notification_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля
        
    def update_notification_profile(self, profile_id, profile):
        """Обновить профиль оповещения"""
        try:
            result = self._server.v1.notification.profile.update(self._auth_token, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_notification_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_idps_signatures_list(self, query={}):
        """Получить список сигнатур IDPS. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.signatures.list(self._auth_token, 0, 50000, query, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_idps_signatures_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает list сигнатур

    def add_idps_signature(self, signature):
        """Добавить сигнатуру IDPS. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.signature.add(self._auth_token, signature)
        except rpc.Fault as err:
            return 1, f'Error utm.add_idps_signature: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID сигнатуры

    def update_idps_signature(self, signature_id, signature):
        """Обновить сигнатуру IDPS. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.signature.update(self._auth_token, signature_id, signature)
        except rpc.Fault as err:
            return 1, f'Error utm.update_idps_signature: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

    def get_idps_signature_fetch(self, signature_id):
        """Получить сигнатуру СОВ по ID. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.signature_fetch(self._auth_token, signature_id)
        except rpc.Fault as err:
            return 1, f'Error utm.get_idps_signature_fetch: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает словарь

    def get_idps_profiles_list(self):
        """Получить список профилей СОВ. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.profiles.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_idps_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает list

    def add_idps_profile(self, profile):
        """Добавить профиль СОВ. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_idps_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID созданного профиля СОВ

    def update_idps_profile(self, profile_id, profile):
        """Обновить профиль СОВ. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.idps.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_idps_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

    def get_netflow_profiles_list(self):
        """Получить список профилей netflow раздела Библиотеки"""
        try:
            result = self._server.v1.netmanager.netflow.profiles.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_notification_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_netflow_profile(self, profile):
        """Добавить профиль netflow в Библиотеку"""
        try:
            result = self._server.v1.netmanager.netflow.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.add_netflow_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_netflow_profile(self, profile_id, profile):
        """Обновить профиль netflow раздела Библиотеки"""
        try:
            result = self._server.v1.netmanager.netflow.profile.update(self._auth_token, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_netflow_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_lldp_profiles_list(self):
        """Получить список профилей LLDP раздела Библиотеки. Только для версии 7.0 и выше"""
        try:
            result = self._server.v1.netmanager.lldp.profiles.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_lldp_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список словарей

    def add_lldp_profile(self, profile):
        """Добавить профиль LLDP в Библиотеку. Только для версии 7.0 и выше"""
        try:
            result = self._server.v1.netmanager.lldp.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Профиль lldp "{profile["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_lldp_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_lldp_profile(self, profile_id, profile):
        """Обновить профиль LLDP. Только для версии 7.0 и выше"""
        try:
            result = self._server.v1.netmanager.lldp.profile.update(self._auth_token, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_lldp_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_ssl_profiles_list(self):
        """Получить список профилей SSL"""
        try:
            result = self._server.v1.content.ssl.profiles.list(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            return 1, f'Error get_ssl_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_ssl_profile(self, profile):
        """Добавить профиль SSL"""
        try:
            result = self._server.v1.content.ssl.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Профиль SSL: "{profile["name"]}" уже существует.'
            else:
                return 1, f'Error utm.add_ssl_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_ssl_profile(self, profile_id, profile):
        """Обновить профиль SSL"""
        try:
            result = self._server.v1.content.ssl.profile.update(self._auth_token, profile_id, profile)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_ssl_profile: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_ssl_forward_profiles(self):
        """Получить список профилей пересылки SSL. Только для версии 7.0 и выше"""
        try:
            result = self._server.v1.content.ssl.forward.profiles.list(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            return 1, f'Error get_ssl_forward_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_ssl_forward_profile(self, profile):
        """Добавить профиль пересылки SSL. Только для версии 7.0 и выше"""
        try:
            result = self._server.v1.content.ssl.forward.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error add_ssl_forward_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_ssl_forward_profile(self, profile_id, profile):
        """Обновить профиль пересылки SSL. Только для версии 7.0 и выше"""
        try:
            result = self._server.v1.content.ssl.forward.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error update_ssl_forward_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def get_hip_objects_list(self):
        """Получить список объектов HIP"""
        try:
            result = self._server.v1.hip.objects.list(self._auth_token, 0, 5000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error get_hip_objects_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_hip_object(self, hip_object):
        """Добавить объект HIP"""
        try:
            result = self._server.v1.hip.object.add(self._auth_token, hip_object)
        except rpc.Fault as err:
            return 1, f'Error add_hip_object: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного объекта

    def update_hip_object(self, hip_object_id, hip_object):
        """Обновить объект HIP"""
        try:
            result = self._server.v1.hip.object.update(self._auth_token, hip_object_id, hip_object)
        except rpc.Fault as err:
            return 1, f'Error update_hip_object: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_hip_profiles_list(self):
        """Получить список профилей HIP"""
        try:
            result = self._server.v1.hip.profiles.list(self._auth_token, 0, 5000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error get_hip_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_hip_profile(self, profile):
        """Добавить профиль HIP"""
        try:
            result = self._server.v1.hip.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error add_hip_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_hip_profile(self, profile_id, profile):
        """Обновить профиль HIP"""
        try:
            result = self._server.v1.hip.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error update_hip_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_bfd_profiles_list(self):
        """Получить список профилей BFD"""
        try:
            result = self._server.v1.netmanager.bfd.profiles.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            return 1, f'Error get_bfd_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_bfd_profile(self, profile):
        """Добавить профиль BFD"""
        try:
            result = self._server.v1.netmanager.bfd.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error add_bfd_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_bfd_profile(self, profile_id, profile):
        """Обновить профиль BFD"""
        try:
            result = self._server.v1.netmanager.bfd.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error update_bfd_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_useridagent_filters_list(self):
        """Получить Syslog фильтры UserID агента"""
        try:
            result = self._server.v1.useridagent.filters.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error get_useridagent_filters_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_useridagent_filter(self, filter_info):
        """Добавить Syslog фильтр UserID агента"""
        try:
            result = self._server.v1.useridagent.filter.add(self._auth_token, filter_info)
        except rpc.Fault as err:
            return 1, f'Error add_useridagent_filter: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного фильтра

    def update_useridagent_filter(self, filter_id, filter_info):
        """Обновить Syslog фильтр UserID агента"""
        try:
            result = self._server.v1.useridagent.filter.update(self._auth_token, filter_id, filter_info)
        except rpc.Fault as err:
            return 1, f'Error update_useridagent_filter: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

################################### Пользователи и устройства #####################################
    def get_groups_list(self):
        """Получить список локальных групп"""
        try:
            if self.version_hight == 5:
                result = self._server.v3.accounts.groups.list(self._auth_token, 0, 10000, {})
            else:
                result = self._server.v3.accounts.groups.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_groups_list: [{err.faultCode}] — {err.faultString}'

        if self.float_version < 7.1:
            try:
                for group in result['items']:
                    group['id'] = group.pop('guid')
            except KeyError as err:
                return 1, f'Error utm.get_groups_list: нет GUID в группе локальных пользователей {group["name"]} [{err}]'
        return 0, result['items']

    def add_group(self, group):
        """Добавить локальную группу"""
        try:
            result = self._server.v3.accounts.group.add(self._auth_token, group)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 2, f'Группа "{group["name"]}" уже существует.'
            elif err.faultCode == 111:
                return 1, f'Недопустимые символы в названии группы: "{group["name"]}"! {err.faultString}'
            else:
                return 1, f'Error utm.add_group: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает GUID добавленной группы

    def update_group(self, guid, group):
        """Обновить локальную группу"""
        try:
            result = self._server.v3.accounts.group.update(self._auth_token, guid, group)
        except TypeError as err:
            return 1, err
        except rpc.Fault as err:
            return 1, f'Error utm.update_group: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_group_users(self, group_guid):
        """Получить список пользователей в группе"""
        try:
            result = self._server.v3.accounts.group.users.list(self._auth_token, group_guid, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_group_users: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def get_users_list(self):
        """Получить список локальных пользователей"""
        try:
            result = self._server.v3.accounts.users.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error get_users_list: [{err.faultCode}] — {err.faultString}'
        if self.float_version < 7.1:
            try:
                for user in result['items']:
                    user['id'] = user.pop('guid')
            except KeyError as err:
                return 1, f'Error utm.get_users_list: нет GUID у пользователя {user["name"]} [{err}]'
        return 0, result['items']

    def add_user(self, user):
        """Добавить локального пользователя"""
        try:
            result = self._server.v3.accounts.user.add(self._auth_token, user)
        except rpc.Fault as err:
            if err.faultCode == 5002:
                return 2, f'Пользователь "{user["name"]}" уже существует.'
            else:
                return 1, f'Error add_user: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного пользователя

    def update_user(self, user):
        """Обновить локального пользователя"""
        guid = user['id'] if self.float_version >= 7.1 else user['guid']
        try:
            result = self._server.v3.accounts.user.update(self._auth_token, guid, user)
        except rpc.Fault as err:
            return 1, f'Error utm.update_user: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def add_user_in_group(self, group_guid, user_guid):
        """Добавить локального пользователя в локальную группу"""
        try:
            result = self._server.v3.accounts.group.user.add(self._auth_token, group_guid, user_guid)
        except rpc.Fault as err:
            return 1, f'Error utm.add_user_in_group: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает true

    def get_auth_servers(self):
        """Получить список серверов авторизации"""
        try:
            ldap = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
            radius = self._server.v1.auth.radius.servers.list(self._auth_token, {})
            tacacs = self._server.v1.auth.tacacs.plus.server.list(self._auth_token, {})
            ntlm = self._server.v1.auth.ntlm.server.list(self._auth_token, {})
            saml = self._server.v1.auth.saml.idp.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_auth_servers: [{err.faultCode}] — {err.faultString}', False, False, False, False
        return 0, ldap, radius, tacacs, ntlm, saml

    def get_ldap_servers(self):
        """Получить список серверов авторизации LDAP"""
        try:
            result = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_ldap_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список словарей

    def get_radius_servers(self):
        """Получить список серверов авторизации RADIUS"""
        try:
            result = self._server.v1.auth.radius.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_radius_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список словарей

    def get_tacacs_servers(self):
        """Получить список серверов авторизации TACACS+"""
        try:
            result = self._server.v1.auth.tacacs.plus.server.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_tacacs_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список словарей

    def get_ntlm_servers(self):
        """Получить список серверов авторизации NTLM"""
        try:
            result = self._server.v1.auth.ntlm.server.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_ntlm_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список словарей

    def get_saml_servers(self):
        """Получить список серверов авторизации SAML"""
        try:
            result = self._server.v1.auth.saml.idp.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_saml_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список словарей

    def get_ldap_server_id(self, domain):
        """Получить ID сервера авторизации LDAP по имени домена"""
        try:
            result = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_ldap_server_id: [{err.faultCode}] — {err.faultString}.'
        for item in result:
            if domain in item['domains']:
                return 0, item['id']
        return 2, f'Нет LDAP-коннектора для домена {domain}.'

    def add_auth_server(self, server_type, server):
        """Добавить auth сервер"""
        try:
            if server_type == 'ldap':
                result = self._server.v1.auth.ldap.server.add(self._auth_token, server)
            elif server_type == 'ntlm':
                result = self._server.v1.auth.ntlm.server.add(self._auth_token, server)
            elif server_type == 'radius':
                result = self._server.v1.auth.radius.server.add(self._auth_token, server)
            elif server_type == 'tacacs':
                result = self._server.v1.auth.tacacs.plus.server.add(self._auth_token, server)
            elif server_type == 'saml':
                result = self._server.v1.auth.saml.idp.server.add(self._auth_token, server)
        except rpc.Fault as err:
            if err.faultCode == 111:
                return 1, f'Недопустимые символы в названии auth-сервера!'
            else:
                return 1, f'Error utm.add_auth_server: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного сервера авторизации

    def get_2fa_profiles(self):
        """Получить список профилей MFA"""
        try:
            f = getattr(self._server, 'v1.2fa.profiles.list')
            result = f(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            return 1, f'Error utm.get_2fa_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_2fa_profile(self, profile):
        """Добавить новый профиль MFA"""
        try:
            f = getattr(self._server, 'v1.2fa.profile.add')
            result = f(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_2fa_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def get_auth_profiles(self):
        """Получить список профилей авторизации"""
        try:
            result = self._server.v1.auth.user.auth.profiles.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_auth_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает список словарей

    def add_auth_profile(self, profile):
        """Добавить новый профиль авторизации"""
        try:
            result = self._server.v1.auth.user.auth.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            if err.faultCode == 111:
                return 1, f'Недопустимые символы в названии auth-профиля "{profile["name"]}".'
            else:
                return 1, f'Error utm.add_auth_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_auth_profile(self, profile_id, profile):
        """Обновить профиль авторизации"""
        try:
            result = self._server.v1.auth.user.auth.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_auth_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_captive_profiles(self):
        """Получить список Captive-профилей"""
        try:
            result = self._server.v1.captiveportal.profiles.list(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            return 1, f'Error utm.get_captive_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_captive_profile(self, profile):
        """Добавить новый Captive-профиль"""
        try:
            result = self._server.v1.captiveportal.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 1, f'Профиль авторизации "{profile["name"]}" не добавлен — {err.faultString}.'
            elif err.faultCode == 111:
                return 1, f'Недопустимые символы в названии captive-профиля "{profile["name"]}".'
            else:
                return 1, f'Error utm.add_captive_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_captive_profile(self, profile_id, profile):
        """Обновить Captive-профиль"""
        try:
            result = self._server.v1.captiveportal.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_captive_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_captive_portal_rules(self):
        """Получить список правил Captive-портала"""
        try:
            result = self._server.v1.captiveportal.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_captive_portal_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_captive_portal_rules(self, rule):
        """Добавить новое правило Captive-портала"""
        try:
            result = self._server.v1.captiveportal.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 1, f'Правило Captive-портала "{rule["name"]}" не добавлено — {err.faultString}.'
            elif err.faultCode == 111:
                return 1, f'Недопустимые символы в названии правила captive-портала "{rule["name"]}".'
            else:
                return 1, f'Error utm.add_captive_portal_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_captive_portal_rule(self, rule_id, rule):
        """Обновить правило Captive-портала"""
        try:
            result = self._server.v1.captiveportal.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_captive_portal_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_terminal_servers(self):
        """Получить список терминальных серверов"""
        try:
            result = self._server.v1.auth.terminal.agent.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_terminal_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает список

    def add_terminal_server(self, server):
        """Добавить новый терминальнй сервер"""
        try:
            result = self._server.v1.auth.terminal.agent.add(self._auth_token, server)
        except rpc.Fault as err:
            return 1, f'Error utm.add_terminal_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

    def update_terminal_server(self, server_id, server):
        """Обновить терминальнй сервер"""
        try:
            result = self._server.v1.auth.terminal.agent.update(self._auth_token, server_id, server)
        except rpc.Fault as err:
            return 1, f'Error utm.update_terminal_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_byod_policy(self):
        """Получить список политик BYOD. Только для версий 5 и 6."""
        try:
            result = self._server.v1.byod.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_byod_policy: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_byod_policy(self, rule):
        """Добавить новое правило в Политики BYOD. Только для версий 5 и 6."""
        try:
            result = self._server.v1.byod.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 1, f'Правило BYOD "{rule["name"]}" не добавлено — {err.faultString}.'
            else:
                return 1, f'Error utm.add_byod_policy: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_byod_policy(self, rule_id, rule):
        """Обновить правило Политики BYOD. Только для версий 5 и 6."""
        try:
            result = self._server.v1.byod.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_byod_policy: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

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
            return 1, f'Error utm.get_ldap_user_guid: [{err.faultCode}] — {err.faultString}'
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
            return 1, f'Error utm.get_ldap_group_guid: [{err.faultCode}] — {err.faultString}'
        return 0, groups[0]['guid'] if groups else 0

    def get_ldap_user_name(self, user_guid):
        """Получить имя пользователя LDAP по его GUID"""
        user = []
        try:
            result = self._server.v1.ldap.user.fetch(self._auth_token, user_guid)
        except rpc.Fault as err:
            if err.faultCode == 1:
                return 2, f'Не возможно получить имя доменного пользователя. Проверьте что версия NGFW 5.0.6.4973 (6.1.7) или выше.'
            elif err.faultCode == 404:
                return 2, f'Не возможно получить имя доменного пользователя. Возможно не доступен контроллер домена.'
            else:
                return 1, f'Error utm.get_ldap_user_name: [{err.faultCode}] — {err.faultString}'
        name = result['name']
        i = name.find('(')
        return 0, name[i+1:len(name)-1]

    def get_ldap_group_name(self, group_guid):
        """Получить имя группы LDAP по её GUID"""
        user = []
        if self.float_version >= 7.1:
            group_guid = group_guid.split(':')[1]
        try:
            result = self._server.v1.ldap.group.fetch(self._auth_token, group_guid)
        except rpc.Fault as err:
            if err.faultCode == 1:
                return 2, f'Не возможно получить имя доменной группы. Проверьте что версия UTM 5.0.6.4973 (6.1.7) или выше.'
            elif err.faultCode == 404:
                return 2, f'Не возможно получить имя доменной группы. Возможно не доступен контроллер домена.'
            else:
                return 1, f'Error utm.get_ldap_group_name: [{err.faultCode}] — {err.faultString}'
        data = [x.split('=') for x in result['name'].split(',')]
        for y in data:
            if y[0] == 'CN':
                return 0, f"{result['guid'].split(':')[0]}\\{y[1]}"

    def get_useridagent_servers(self):
        """Получить список UserID серверов"""
        try:
            result = self._server.v1.useridagent.servers.list(self._auth_token, 0, 50000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_useridagent_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список

    def add_useridagent_server(self, server):
        """Добавить новый UserID сервер"""
        try:
            result = self._server.v1.useridagent.server.add(self._auth_token, server)
        except rpc.Fault as err:
            return 1, f'Error utm.add_useridagent_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

    def update_useridagent_server(self, server_id, server):
        """Обновить UserID сервер"""
        try:
            result = self._server.v1.useridagent.server.update(self._auth_token, server_id, server)
        except rpc.Fault as err:
            return 1, f'Error utm.update_useridagent_server: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_useridagent_filters(self):
        """Получить список UserID фильтров"""
        try:
            result = self._server.v1.useridagent.filters.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_useridagent_filters: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']    # Возвращает список

    def add_useridagent_filter(self, filter_info):
        """Добавить новый UserID фильтр"""
        try:
            result = self._server.v1.useridagent.filter.add(self._auth_token, filter_info)
        except rpc.Fault as err:
            return 1, f'Error utm.add_useridagent_filter: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

    def update_useridagent_filter(self, filter_id, filter_info):
        """Обновить UserID фильтр"""
        try:
            result = self._server.v1.useridagent.filter.update(self._auth_token, filter_id, filter_info)
        except rpc.Fault as err:
            return 1, f'Error utm.update_useridagent_filter: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает True

    def get_useridagent_config(self):
        """Получить список UserID фильтров"""
        try:
            result = self._server.v1.useridagent.get.agent.config(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_useridagent_config: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает dict

    def set_useridagent_config(self, config_info):
        """Добавить новый UserID фильтр"""
        try:
            result = self._server.v1.useridagent.set.agent.config(self._auth_token, config_info)
        except rpc.Fault as err:
            return 1, f'Error utm.set_useridagent_config: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает ID

################### Политики сети ############################################################
    def get_firewall_rules(self):
        """Получить список правил межсетевого экрана"""
        try:
            result = self._server.v1.firewall.rules.list(self._auth_token, 0, 20000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_firewall_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_firewall_rule(self, rule):
        """Добавить новое правило в МЭ"""
        try:
            result = self._server.v1.firewall.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_firewall_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_firewall_rule(self, rule_id, rule):
        """Обновить правило МЭ. Принимает структуру правила и его ID."""
        try:
            result = self._server.v1.firewall.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_firewall_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_traffic_rules(self):
        """Получить список правил NAT"""
        try:
            result = self._server.v1.traffic.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_traffic_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_traffic_rule(self, rule):
        """Добавить новое правило NAT"""
        try:
            result = self._server.v1.traffic.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_traffic_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_traffic_rule(self, rule_id, rule):
        """Обновить правило NAT"""
        try:
            result = self._server.v1.traffic.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_traffic_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_loadbalancing_rules(self):
        """Получить список правил балансировки нагрузки"""
        try:
            tcpudp = self._server.v1.virtualserver.rules.list(self._auth_token)
            icap = self._server.v1.icap.loadbalancing.rules.list(self._auth_token)
            reverse = self._server.v1.reverseproxy.loadbalancing.rules.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'error utm.get_loadbalancing_rules: [{err.faultCode}] — {err.faultString}', 0, 0
        return 0, tcpudp, icap, reverse

    def add_virtualserver_rule(self, rule):
        """Добавить новое правило балансировки нагрузки TCP/UDP"""
        try:
            result = self._server.v1.virtualserver.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_virtualserver_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_virtualserver_rule(self, rule_id, rule):
        """Обновить правило балансировки нагрузки TCP/UDP"""
        try:
            result = self._server.v1.virtualserver.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_virtualserver_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def add_icap_loadbalancing_rule(self, rule):
        """Добавить новое правило балансировки нагрузки ICAP"""
        try:
            result = self._server.v1.icap.loadbalancing.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_icap_loadbalancing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_icap_loadbalancing_rule(self, rule_id, rule):
        """Обновить правило балансировки нагрузки ICAP"""
        try:
            result = self._server.v1.icap.loadbalancing.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_icap_loadbalancing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def add_reverse_loadbalancing_rule(self, rule):
        """Добавить новое правило балансировки нагрузки reverse-proxy"""
        try:
            result = self._server.v1.reverseproxy.loadbalancing.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_reverse_loadbalancing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_reverse_loadbalancing_rule(self, rule_id, rule):
        """Обновить правило балансировки нагрузки reverse-proxy"""
        try:
            result = self._server.v1.reverseproxy.loadbalancing.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_reverse_loadbalancing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_shaper_rules(self):
        """Получить список правил пропускной способности"""
        try:
            result = self._server.v1.shaper.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_shaper_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_shaper_rule(self, rule):
        """Добавить новое правило пропускной способности"""
        try:
            result = self._server.v1.shaper.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_shaper_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_shaper_rule(self, rule_id, rule):
        """Обновить правило пропускной способности"""
        try:
            result = self._server.v1.shaper.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_shaper_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_content_rules(self):
        """Получить список правил фильтрации контента"""
        try:
            result = self._server.v1.content.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_content_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_content_rule(self, rule):
        """Добавить новое правило фильтрации контента"""
        try:
            result = self._server.v1.content.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_content_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_content_rule(self, rule_id, rule):
        """Обновить правило фильтрации контента"""
        try:
            result = self._server.v1.content.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_content_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_safebrowsing_rules(self):
        """Получить список правил веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_safebrowsing_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_safebrowsing_rule(self, rule):
        """Добавить новое правило веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_safebrowsing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_safebrowsing_rule(self, rule_id, rule):
        """Обновить правило веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_safebrowsing_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_tunnel_inspection_rules(self):
        """Получить список правил инспектирования туннелей. Для версии 7.0 и выше."""
        try:
            result = self._server.v1.firewall.tunnel.inspection.rules.list(self._auth_token, 0, 5000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_tunnel_inspection_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_tunnel_inspection_rule(self, rule):
        """Добавить новое правило инспектирования туннелей. Для версии 7.0 и выше."""
        try:
            result = self._server.v1.firewall.tunnel.inspection.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_tunnel_inspection_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_tunnel_inspection_rule(self, rule_id, rule):
        """Обновить правило инспектирования туннелей. Для версии 7.0 и выше."""
        try:
            result = self._server.v1.firewall.tunnel.inspection.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_tunnel_inspection_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_ssldecrypt_rules(self):
        """Получить список правил инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_ssldecrypt_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_ssldecrypt_rule(self, rule):
        """Добавить новое правило инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_ssldecrypt_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_ssldecrypt_rule(self, rule_id, rule):
        """Обновить правило инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_ssldecrypt_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_sshdecrypt_rules(self):
        """Получить список правил инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_sshdecrypt_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_sshdecrypt_rule(self, rule):
        """Добавить новое правило инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_sshdecrypt_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_sshdecrypt_rule(self, rule_id, rule):
        """Обновить правило инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_sshdecrypt_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_idps_rules(self):
        """Получить список правил СОВ"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.idps.rules.list(self._auth_token, {})
                return 0, result
            else:
                result = self._server.v1.idps.rules.list(self._auth_token, 0, 100000, {})
                return 0, result['items']
        except rpc.Fault as err:
            return 1, f'Error utm.get_idps_rules: [{err.faultCode}] — {err.faultString}'
    
    def add_idps_rule(self, rule):
        """Добавить новое правило СОВ"""
        try:
            result = self._server.v1.idps.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_idps_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_idps_rule(self, rule_id, rule):
        """Обновить правило СОВ"""
        try:
            result = self._server.v1.idps.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_idps_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_scada_rules(self):
        """Получить список правил АСУ ТП"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.scada.rules.list(self._auth_token, {})
                return 0, result
            else:
                result = self._server.v1.scada.rules.list(self._auth_token, 0, 100000, {})
                return 0, result['items']
        except rpc.Fault as err:
            return 1, f'Error utm.get_scada_rules: [{err.faultCode}] — {err.faultString}'

    def add_scada_rule(self, rule):
        """Добавить новое правило АСУ ТП"""
        try:
            result = self._server.v1.scada.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_scada_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_scada_rule(self, rule_id, rule):
        """Обновить правило АСУ ТП"""
        try:
            result = self._server.v1.scada.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_scada_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_scenarios_rules(self):
        """Получить список сценариев"""
        try:
            result = self._server.v1.scenarios.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_scenarios_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_scenarios_rule(self, rule):
        """Добавить новый сценарий в Сценарии"""
        try:
            result = self._server.v1.scenarios.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_scenarios_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_scenarios_rule(self, rule_id, rule):
        """Обновить сценарий"""
        try:
            result = self._server.v1.scenarios.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_scenarios_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_mailsecurity_rules(self):
        """Получить список правил защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_mailsecurity_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_mailsecurity_rule(self, rule):
        """Добавить новое правило защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_mailsecurity_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_mailsecurity_rule(self, rule_id, rule):
        """Обновить правило защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_mailsecurity_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_mailsecurity_dnsbl(self):
        """Получить список dnsbl и batv защиты почтового трафика"""
        try:
            dnsbl = self._server.v1.mailsecurity.dnsbl.config.get(self._auth_token)
            batv = self._server.v1.mailsecurity.batv.config.get(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_mailsecurity_dnsbl: [{err.faultCode}] — {err.faultString}'
        return 0, dnsbl, batv

    def set_mailsecurity_dnsbl(self, rule):
        """Установить конфигурацию DNSBL защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.dnsbl.config.set(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.set_mailsecurity_dnsbl: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def set_mailsecurity_batv(self, rule):
        """Установить конфигурацию BATV защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.batv.config.set(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.set_mailsecurity_batv: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def get_icap_servers(self):
        """Получить список серверов ICAP"""
        try:
            result = self._server.v1.icap.profiles.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_icap_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result    # Возвращает список настроек ICAP серверов

    def add_icap_server(self, server):
        """Добавить новый ICAP сервер"""
        try:
            result = self._server.v1.icap.profile.add(self._auth_token, server)
        except rpc.Fault as err:
            return 1, f'Error utm.add_icap_server: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_icap_server(self, server_id, server):
        """Обновить ICAP сервер"""
        try:
            result = self._server.v1.icap.profile.update(self._auth_token, server_id, server)
        except rpc.Fault as err:
            return 1, f'Error utm.update_icap_server: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_icap_rules(self):
        """Получить список правил ICAP"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.icap.rules.list(self._auth_token, {})
            else:
                result = self._server.v1.icap.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_icap_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result if self.version_hight == 5 else result['items']

    def add_icap_rule(self, rule):
        """Добавить новое ICAP-правило"""
        try:
            result = self._server.v1.icap.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_icap_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_icap_rule(self, rule_id, rule):
        """Обновить ICAP-правило"""
        try:
            result = self._server.v1.icap.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_icap_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_dos_profiles(self):
        """Получить список профилей DoS"""
        try:
            result = self._server.v1.dos.profiles.list(self._auth_token, 0, 10000, '')
        except rpc.Fault as err:
            return 1, f'Error utm.get_dos_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_dos_profile(self, profile):
        """Добавить новый профиль DoS"""
        try:
            result = self._server.v1.dos.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_dos_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_dos_profile(self, profile_id, profile):
        """Обновить профиль DoS"""
        try:
            result = self._server.v1.dos.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_dos_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_dos_rules(self):
        """Получить список правил защиты DoS"""
        try:
            result = self._server.v1.dos.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_dos_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_dos_rule(self, rule):
        """Добавить новое правило защиты DoS"""
        try:
            result = self._server.v1.dos.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_dos_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_dos_rule(self, rule_id, rule):
        """Обновить правило защиты DoS"""
        try:
            result = self._server.v1.dos.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_dos_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_proxyportal_rules(self):
        """Получить список ресурсов URL веб-портала"""
        try:
            result = self._server.v1.proxyportal.bookmarks.list(self._auth_token, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_proxyportal_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def add_proxyportal_rule(self, rule):
        """Добавить новый URL-ресурс веб-портала"""
        try:
            result = self._server.v1.proxyportal.bookmark.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_proxyportal_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_proxyportal_rule(self, rule_id, rule):
        """Обновить URL-ресурс веб-портала"""
        try:
            result = self._server.v1.proxyportal.bookmark.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_proxyportal_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_reverseproxy_servers(self):
        """Получить список серверов reverse-прокси"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.reverseproxy.profiles.list(self._auth_token, 0, 100000, {}, [])
                return 0, result['items']   # Возвращает список настроек серверов reverse-прокси
            else:
                result = self._server.v1.reverseproxy.profiles.list(self._auth_token)
                return 0, result   # Возвращает список настроек серверов reverse-прокси
        except rpc.Fault as err:
            return 1, f'Error utm.get_reverseproxy_servers: [{err.faultCode}] — {err.faultString}'
 
    def add_reverseproxy_server(self, profile):
        """Добавить новый сервер reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_reverseproxy_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_reverseproxy_server(self, profile_id, profile):
        """Обновить сервер reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_reverseproxy_servers: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_reverseproxy_rules(self):
        """Получить список правил reverse-прокси"""
        try:
            if self.version_hight == 5:
                result = self._server.v1.reverseproxy.rules.list(self._auth_token, {})
                return 0, result
            else:
                result = self._server.v1.reverseproxy.rules.list(self._auth_token, 0, 100000, {})
                return 0, result['items']
        except rpc.Fault as err:
            return 1, f'Error utm.get_reverseproxy_rules: [{err.faultCode}] — {err.faultString}'

    def add_reverseproxy_rule(self, rule):
        """Добавить новое правило reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_reverseproxy_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_reverseproxy_rule(self, rule_id, rule):
        """Обновить правило reverse-прокси"""
        try:
            result = self._server.v1.reverseproxy.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_reverseproxy_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_vpn_security_profiles(self):
        """Получить список профилей безопасности VPN"""
        try:
            result = self._server.v1.vpn.security.profiles.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_vpn_security_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def add_vpn_security_profile(self, profile):
        """Добавить новый профиль безопасности VPN"""
        try:
            result = self._server.v1.vpn.security.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_vpn_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_vpn_security_profile(self, profile_id, profile):
        """Обновить профиль безопасности VPN"""
        try:
            result = self._server.v1.vpn.security.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_vpn_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_vpn_client_security_profiles(self):
        """Получить клиентские профили безопасности VPN. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.vpn.client.security.profiles.list(self._auth_token, 0, 100000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_vpn_client_security_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_vpn_client_security_profile(self, profile):
        """Добавить клиентский профиль безопасности VPN. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.vpn.client.security.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_vpn_client_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_vpn_client_security_profile(self, profile_id, profile):
        """Обновить клиентский профиль безопасности VPN. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.vpn.client.security.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_vpn_client_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_vpn_server_security_profiles(self):
        """Получить серверные профили безопасности VPN. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.vpn.server.security.profiles.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_vpn_server_security_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_vpn_server_security_profile(self, profile):
        """Добавить серверный профиль безопасности VPN. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.vpn.server.security.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_vpn_server_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_vpn_server_security_profile(self, profile_id, profile):
        """Обновить серверный профиль безопасности VPN. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.vpn.server.security.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_vpn_server_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_vpn_networks(self):
        """Получить список сетей VPN"""
        try:
            result = self._server.v1.vpn.tunnels.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_vpn_networks: [{err.faultCode}] — {err.faultString}'
        if isinstance(result, list):
            return 0, result
        else:
            return 0, result['items']

    def add_vpn_network(self, network):
        """Добавить новую сеть VPN"""
        try:
            result = self._server.v1.vpn.tunnel.add(self._auth_token, network)
        except rpc.Fault as err:
            return 1, f'Error utm.add_vpn_network: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_vpn_network(self, network_id, network):
        """Обновить сеть VPN"""
        try:
            result = self._server.v1.vpn.tunnel.update(self._auth_token, network_id, network)
        except rpc.Fault as err:
            return 1, f'Error utm.update_vpn_network: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_vpn_server_rules(self):
        """Получить список серверных правил VPN"""
        try:
            result = self._server.v1.vpn.server.rules.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_vpn_server_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result if self.version_hight == 5 else result['items']

    def add_vpn_server_rule(self, rule):
        """Добавить новое серверное правило VPN"""
        try:
            result = self._server.v1.vpn.server.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_vpn_server_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_vpn_server_rule(self, rule_id, rule):
        """Обновить серверное правило VPN"""
        try:
            result = self._server.v1.vpn.server.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_vpn_server_rule: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает True

    def get_vpn_client_rules(self):
        """Получить список клиентских правил VPN"""
        try:
            result = self._server.v1.vpn.client.rules.list(self._auth_token)
        except rpc.Fault as err:
            return 1, f'Error utm.get_vpn_client_rules: [{err.faultCode}] — {err.faultString}'
        if isinstance(result, list):
            return 0, result
        else:
            return 0, result['items']

    def add_vpn_client_rule(self, rule):
        """Добавить новое клиентское правило VPN"""
        try:
            if self.version_hight > 6:
                result = self._server.v1.vpn.client.rule.add(self._auth_token, rule)
            else:
                result = self._server.v1.vpn.client.rule.add(self._auth_token, self.node_name, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_vpn_client_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_vpn_client_rule(self, rule_id, rule):
        """Обновить клиентское правило VPN"""
        try:
            if self.version_hight > 6:
                result = self._server.v1.vpn.client.rule.update(self._auth_token, rule_id, rule)
            else:
                result = self._server.v1.vpn.client.rule.update(self._auth_token, self.node_name, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_vpn_client_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

########################################### Оповещения ###########################################
    def get_snmp_sysname(self):
        """Получить SNMP имя системы. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.sys.name.get(self._auth_token, self.node_name)
        except rpc.Fault as err:
            return 1, f'Error utm.get_snmp_sysname: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_snmp_sysname(self, name):
        """Установить SNMP имя системы. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.sys.name.set(self._auth_token, self.node_name, name)
        except rpc.Fault as err:
            return 1, f'Error utm.set_snmp_sysname: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def get_snmp_syslocation(self):
        """Получить SNMP локацию системы. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.sys.location.get(self._auth_token, self.node_name)
        except rpc.Fault as err:
            return 1, f'Error utm.get_snmp_syslocation: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_snmp_syslocation(self, location):
        """Установить SNMP локацию системы. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.sys.location.set(self._auth_token, self.node_name, location)
        except rpc.Fault as err:
            return 1, f'Error utm.set_snmp_syslocation: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def get_snmp_sysdescription(self):
        """Получить SNMP описание системы. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.sys.description.get(self._auth_token, self.node_name)
        except rpc.Fault as err:
            return 1, f'Error utm.get_snmp_sysdescription: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def set_snmp_sysdescription(self, description):
        """Установить SNMP описание системы. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.sys.description.set(self._auth_token, self.node_name, description)
        except rpc.Fault as err:
            return 1, f'Error utm.set_snmp_sysdescription: [{err.faultCode}] — {err.faultString}'
        return 0, result

    def get_snmp_security_profiles(self):
        """Получить профили безопасности SNMP. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.security.profiles.list(self._auth_token, 0, 10000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_snmp_security_profiles: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_snmp_security_profile(self, profile):
        """Добавить профиль безопасности SNMP. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.security.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_snmp_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного профиля

    def update_snmp_security_profile(self, profile_id, profile):
        """Обновить профиль безопасности SNMP. Для версии 7.1 и выше."""
        try:
            result = self._server.v1.snmp.security.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_snmp_security_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_snmp_rules(self):
        """Получить список правил SNMP"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.snmp.rules.list(self._auth_token, 0, 100000, {})
                return 0, result['items']
            else:
                result = self._server.v1.snmp.rules.list(self._auth_token)
                return 0, result
        except rpc.Fault as err:
            return 1, f'Error utm.get_snmp_rules: [{err.faultCode}] — {err.faultString}'

    def add_snmp_rule(self, rule):
        """Добавить новое правило SNMP"""
        try:
            result = self._server.v1.snmp.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_snmp_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_snmp_rule(self, rule_id, rule):
        """Обновить правило SNMP"""
        try:
            result = self._server.v1.snmp.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_snmp_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

    def get_notification_alert_rules(self):
        """Получить список правил оповещений"""
        try:
            result = self._server.v1.notification.alert.rules.list(self._auth_token, 0, 100000, {})
        except rpc.Fault as err:
            return 1, f'Error utm.get_notification_alert_rules: [{err.faultCode}] — {err.faultString}'
        return 0, result if self.version_hight < 7 else result['items']

    def add_notification_alert_rule(self, rule):
        """Добавить новое правило оповещений"""
        try:
            result = self._server.v1.notification.alert.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.add_notification_alert_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает ID добавленного правила

    def update_notification_alert_rule(self, rule_id, rule):
        """Обновить правило оповещений"""
        try:
            result = self._server.v1.notification.alert.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f'Error utm.update_notification_alert_rule: [{err.faultCode}] — {err.faultString}'
        return 0, result     # Возвращает True

################################## WAF для версии 7.1 и выше #######################################
    def get_waf_technology_list(self):
        """Получить список технологий WAF"""
        try:
            result = self._server.v1.waf.system.rules.technologies.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_waf_technology_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список словарей: {'id': <int>; 'name': <str>}

    def get_waf_system_layers_list(self):
        """Получить список системных слоёв WAF"""
        try:
            result = self._server.v1.waf.system.layers.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_waf_system_layers_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def get_waf_custom_layers_list(self):
        """Получить список персональных слоёв WAF"""
        try:
            result = self._server.v1.waf.custom.layers.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_waf_custom_layers_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']

    def add_waf_custom_layer(self, layer):
        """Добавить персональный слой WAF"""
        try:
            result = self._server.v1.waf.custom.layer.add(self._auth_token, layer)
        except rpc.Fault as err:
            return 1, f'Error utm.add_waf_custom_layer: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID

    def update_waf_custom_layer(self, layer_id, layer):
        """Обновить персональный слой WAF"""
        try:
            result = self._server.v1.waf.custom.layer.update(self._auth_token, layer_id, layer)
        except rpc.Fault as err:
            return 1, f'Error utm.update_waf_custom_layer: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

    def get_waf_profiles_list(self):
        """Получить список профилей WAF"""
        try:
            result = self._server.v1.waf.profiles.list(self._auth_token, 0, 10000, {}, [])
        except rpc.Fault as err:
            if err.faultCode == 102:
                return 2, 'Нет лицензии на модуль WAF или нет разрешения для API WAF в профиле администратора.'
            else:
                return 1, f'Error utm.get_waf_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает список словарей

    def add_waf_profile(self, profile):
        """Добавить профиль WAF"""
        try:
            result = self._server.v1.waf.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_waf_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID

    def update_waf_profile(self, profile_id, profile):
        """Добавить профиль WAF"""
        try:
            result = self._server.v1.waf.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_waf_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

################################### L7 для версии 7.1 и выше #######################################
    def get_version71_apps(self, query={}):
        """Получить список пользовательских приложений l7 для версии 7.1 и выше"""
        if self.float_version >= 7.1:
            try:
                result = self._server.v1.l7.signatures.list(self._auth_token, 0, 50000, query, [])
            except rpc.Fault as err:
                return 1, f'Error utm.get_version71_apps: [{err.faultCode}] — {err.faultString}'
            return 0, result['items']
        else:
            return 1, 'Не корректная версия NGFW. Должна быть 7.1 или выше.'

    def add_version71_app(self, apps_info):
        """Добавить новое пользовательское приложение l7 для версии 7.1 и выше"""
        try:
            result = self._server.v1.l7.signature.add(self._auth_token, apps_info)
        except rpc.Fault as err:
            return 1, f"Error utm.add_version71_app: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленной сигнатуры

    def update_version71_app(self, apps_id, apps_info):
        """Обновить пользовательское приложение l7 для версии 7.1 и выше"""
        try:
            result = self._server.v1.l7.signature.update(self._auth_token, apps_id, apps_info)
        except rpc.Fault as err:
            return 1, f"Error utm.update_version71_app: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_l7_profiles_list(self):
        """Получить список профилей приложений. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.l7.profiles.list(self._auth_token, 0, 100000, {}, [])
        except rpc.Fault as err:
            return 1, f'Error utm.get_l7_profiles_list: [{err.faultCode}] — {err.faultString}'
        return 0, result['items']   # Возвращает list

    def add_l7_profile(self, profile):
        """Добавить профиль приложений. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.l7.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.add_l7_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает ID созданного профиля

    def update_l7_profile(self, profile_id, profile):
        """Обновить профиль приложений. Только для версии 7.1 и выше."""
        try:
            result = self._server.v1.l7.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f'Error utm.update_l7_profile: [{err.faultCode}] — {err.faultString}'
        return 0, result   # Возвращает True

####################################### Служебные методы ###########################################
    def get_ip_protocol_list(self):
        """Получить список поддерживаемых IP протоколов"""
        try:
            result = self._server.v2.core.ip.protocol.list()
        except rpc.Fault as err:
            return 1, f'Error utm.get_ip_protocol_list: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, {x['name'] for x in result}  # Возвращает set {protocol_name, ...}

    def get_url_categories(self):
        """Получить список категорий URL"""
        try:
            result = self._server.v2.core.get.categories()
        except rpc.Fault as err:
            return 1, f'Error utm.get_url_categories: [{err.faultCode}] — {err.faultString}'
        return 0, result  # Возвращает список [{id: name}, ...]

    def get_l7_apps(self):
        """Получить список приложений l7"""
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.l7.signatures.list(self._auth_token, 0, 500000, {}, [])
                return 0, {x['id']: x['name'] for x in result['items']}
            elif self.version_hight == 6 or self.float_version == 7.0:
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 500000, {}, [])
                return 0, {x['id']: x['name'] for x in result['items']}
            elif self.version_hight == 5:
                result = self._server.v2.core.get.l7apps(self._auth_token, 0, 500000, '')
                return 0, {x['app_id']: x['name'] for x in result['items']}
        except rpc.Fault as err:
            return 1, f'Error utm.get_l7_apps: [{err.faultCode}] — {err.faultString}'

    def get_l7_categories(self):
        """
        Получить список категорий l7.
        В версиях до 7.1 возвращает список: [{'id': category_id, 'name': category_name, 'app_list': [id_app_1, id_app_2, ...]}, ...]
        В версиях начиная с 7.1 возвращает список: [{'id': category_id, 'name': category_name}, ...]
        """
        try:
            if self.float_version >= 7.1:
                result = self._server.v1.l7.get.categories(self._auth_token)
            else:
                result = self._server.v2.core.get.l7categories(self._auth_token, 0, 10000, '')
        except rpc.Fault as err:
            return 1, f"Error utm.get_l7_categories: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result['items']

#####################################################################################################

class UtmError(Exception): pass

