#!/usr/bin/python3
# Версия 2.15
# Общий класс для работы с xml-rpc
import sys
import xmlrpc.client as rpc
from xml.parsers.expat import ExpatError


class UtmXmlRpc:
    def __init__(self, server_ip, login, password):
        self._login = login
        self._password = password
        self._url = f'http://{server_ip}:4040/rpc'
        self._auth_token = None
        self._server = None
        self.version = None
        self.server_ip = server_ip
        self.node_name = None

    def _connect(self):
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

################################### Settings ####################################
    def get_ntp_config(self):
        """Получить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_ntp_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_ntp_config(self, ntp):
        """Обновить конфигурацию NTP"""
        try:
            result = self._server.v2.settings.time.set(self._auth_token, ntp)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_ntp_config: [{err.faultCode}] — {err.faultString}"
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
            print(f"\tОшибка utm.get_settings_params: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def set_settings_param(self, param_name, param_value):
        """Изменить параметр"""
        try:
            result = self._server.v2.settings.set.param(self._auth_token, param_name, param_value)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_settings_param: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает True

    def get_proxy_port(self):
        """Получить порт прокси"""
        try:
            result = self._server.v2.settings.proxy.port.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_proxy_port: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result  # Возвращает номер порта

    def set_proxy_port(self, port):
        """Изменить порт прокси"""
        try:
            result = self._server.v2.settings.proxy.port.set(self._auth_token, port)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_proxy_port: [{err.faultCode}] — {err.faultString}"
        return 0, result  # Возвращает True

    def get_proxyportal_config(self):
        """Получить настройки веб-портала"""
        try:
            result = self._server.v1.proxyportal.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_proxyportal_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

    def set_proxyportal_config(self, params):
        """Изменить настройки веб-портала"""
        try:
            result = self._server.v1.proxyportal.config.set(self._auth_token, params)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_proxyportal_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_admin_profiles_list(self):
        """Получить список профилей администраторов"""
        try:
            result = self._server.v2.core.administrator.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_admin_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_admin_profile(self, profile):
        """Добавить новый профиль администраторов"""
        try:
            result = self._server.v2.core.administrator.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_admin_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_admin_profile(self, profile_id, profile):
        """Обновить профиль администраторов"""
        try:
            result = self._server.v2.core.administrator.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_admin_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_admin_config(self):
        """Получить список настроек пароля администраторов"""
        try:
            result = self._server.v2.core.administrator.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_admin_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def set_admin_config(self, params):
        """Изменить настройки пароля администраторов"""
        try:
            result = self._server.v2.core.administrator.config.set(self._auth_token, params)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_admin_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

    def get_admin_list(self):
        """Получить список администраторов"""
        try:
            result = self._server.v2.core.administrator.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_admin_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_admin(self, admin):
        """Добавить нового администратора"""
        try:
            result = self._server.v2.core.administrator.add(self._auth_token, admin)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_admin: [{err.faultCode}] — {err.faultString}: {admin['login']}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_admin(self, admin_id, admin):
        """Обновить администратора"""
        try:
            result = self._server.v2.core.administrator.update(self._auth_token, admin_id, admin)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_admin: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_certificates_list(self):
        """Получить список сертификатов"""
        try:
            result = self._server.v2.settings.certificates.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_certificates_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

    def get_certificate_details(self, cert_id):
        """Получить детальную информацию по сертификату"""
        try:
            result = self._server.v2.settings.certificate.details(self._auth_token, cert_id)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_certificate_details: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_certificate_data(self, cert_id):
        """Выгрузить сертификат в DER формате"""
        try:
            result = self._server.v2.settings.certificate.getData(self._auth_token, cert_id)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_certificate_data: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def get_certificate_chain_data(self, cert_id):
        """Выгрузить сертификат в DER формате"""
        try:
            result = self._server.v2.settings.certificate.getCertWithChainData(self._auth_token, cert_id)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_certificate_chain_data: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def add_certificate(self, cert):
        """Добавить новый сертификат"""
        try:
            result = self._server.v2.setting.certificate.add(self._auth_token, cert)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_certificate: [{err.faultCode}] — {err.faultString}: {admin['login']}"
        else:
            return 0, result     # Возвращает ID добавленного правила

##################################### Network #####################################
    def get_zones_list(self):
        """Получить список зон"""
        try:
            result = self._server.v1.netmanager.zones.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка utm.get_zones_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

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

    def get_gateways_list(self):
        """Получить список шлюзов"""
        try:
            result = self._server.v1.netmanager.gateways.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_gateways_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

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

    def get_gateway_failover(self):
        """Получить настройки проверки сети шлюзов"""
        try:
            result = self._server.v1.netmanager.failover.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_gateway_failover: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

    def set_gateway_failover(self, params):
        """Изменить настройки проверки сети шлюзов"""
        try:
            result = self._server.v1.netmanager.failover.config.set(self._auth_token, params)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_admin_config: [{err.faultCode}] — {err.faultString}"
        return 0, result

################################## Interfaces ###################################
    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка utm.get_interfaces_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

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

    def add_interface_bond(self, bond):
        """Добавить bond интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.bond(self._auth_token, self.node_name, bond['name'], bond)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_interface_bond: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def add_interface_bridge(self, bridge):
        """Добавить bridge интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.bridge(self._auth_token, self.node_name, bridge['name'], bridge)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_interface_bridge: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def add_interface_vlan(self, vlan):
        """Добавить vlan интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.vlan(self._auth_token, self.node_name, vlan['name'], vlan)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_interface_vlan: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def add_interface_pppoe(self, ppp):
        """Добавить PPPoE интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.pppoe(self._auth_token, self.node_name, ppp['name'], ppp)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_interface_pppoe: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def add_interface_tunnel(self, tunnel):
        """Добавить TUNNEL интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.tunnel(self._auth_token, self.node_name, tunnel['name'], tunnel)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_interface_tunnel: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def add_interface_vpn(self, vpn):
        """Добавить VPN интерфейс"""
        try:
            result = self._server.v1.netmanager.interface.add.vpn(self._auth_token, 'cluster', vpn['name'], vpn)
        except rpc.Fault as err:
            if err.faultCode == 18004:
                return 2, f'\tИнтерфейс {vpn["name"]} пропущен так как содержит IP принадлежащий подсети другого интерфейса VPN!.'
            else:
                return 2, f'\tОшибка utm.add_interface_vpn: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result     # Возвращает ID добавленного правила

##################################### DHCP ######################################
    def get_dhcp_list(self):
        """Получить список подсетей для dhcp"""
        try:
            result = self._server.v1.netmanager.dhcp.subnets.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка utm.get_dhcp_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_dhcp_subnet(self, subnet):
        """Добавить DHCP subnet"""
        try:
            result = self._server.v1.netmanager.dhcp.subnet.add(self._auth_token, self.node_name, subnet)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 1017:
                return 1, f'\tDHCP subnet "{subnet["name"]}" уже существует.'
            else:
                return 2, f"\tОшибка utm.add_dhcp_subnet: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

##################################### DNS ######################################
    def get_dns_config(self):
        """Получить настройки DNS"""
        try:
            dns_servers = self._server.v2.settings.custom.dnses.list(self._auth_token)  # список системных DNS-серверов
            dns_rules = self._server.v1.dns.rules.list(self._auth_token, 0, 1000, {})   # список правил DNS
            static_records = self._server.v1.dns.static.records.list(self._auth_token, 0, 1000, {})   # список статических записей
        except rpc.Fault as err:
            print(f"Ошибка utm.get_dns_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return dns_servers, dns_rules['items'], static_records['items']

    def add_dns_server(self, dns_server):
        """Добавить DNS server"""
        try:
            result = self._server.v2.settings.custom.dns.add(self._auth_token, dns_server)
        except rpc.Fault as err:
            if err.faultCode == 18004:
                return 1, f"\tDNS server {dns_server['dns']} уже существует."
            else:
                return 2, f"\tОшибка utm.add_dns_server: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_dns_rule(self, dns_rule):
        """Добавить правило DNS"""
        try:
            result = self._server.v1.dns.rule.add(self._auth_token, dns_rule)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПравило DNS {dns_rule['name']} уже существует."
            else:
                return 2, f"\tОшибка utm.add_dns_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def add_dns_record(self, dns_record):
        """Добавить статическую запись DNS"""
        try:
            result = self._server.v1.dns.static.record.add(self._auth_token, dns_record)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'\tСтатическая запись DNS "{dns_record["name"]}" уже существует.'
            else:
                return 2, f"\tОшибка utm.add_dns_record: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result
######################################## WCCP  ########################################
    def get_wccp_list(self):
        """Получить список правил wccp"""
        try:
            result = self._server.v1.wccp.rules.list(self._auth_token)
        except rpc.Fault as err:
            if err.faultCode == 102:
                    return 1, f'\tОшибка: нет прав на чтение конфигурации WCCP. Конфигурация WWCP не выгружена.'
            else:
                print(f"Ошибка utm.get_wccp_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

    def add_wccp_rule(self, rule):
        """Добавить правило wccp"""
        try:
            result = self._server.v1.wccp.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_wccp_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_wccp_rule(self, rule_id, rule):
        """Изменить правило wccp"""
        try:
            result = self._server.v1.wccp.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_wccp_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

######################################## Маршруты  ########################################
    def get_routers_list(self):
        """Получить список маршрутов"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.netmanager.virtualrouters.list(self._auth_token)
            else:
                result = self._server.v1.netmanager.route.list(self._auth_token, self.node_name, {})
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

    def get_ospf_config(self):
        """Получить конфигурацию OSPF (только для v.5)"""
        try:
            data = self._server.v1.netmanager.ospf.router.fetch(self._auth_token, self.node_name)
            ifaces = self._server.v1.netmanager.ospf.interfaces.list(self._auth_token, self.node_name)
            areas = self._server.v1.netmanager.ospf.areas.list(self._auth_token, self.node_name)
        except rpc.Fault as err:
            print(f"Ошибка utm.get_ospf_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return data, ifaces, areas

    def get_bgp_config(self):
        """Получить конфигурацию BGP (только для v.5)"""
        try:
            data = self._server.v1.netmanager.bgp.router.fetch(self._auth_token, self.node_name)
            neigh = self._server.v1.netmanager.bgp.neighbors.list(self._auth_token, self.node_name)
            rmaps = self._server.v1.netmanager.bgp.routemaps.list(self._auth_token, self.node_name)
            filters = self._server.v1.netmanager.bgp.filters.list(self._auth_token, self.node_name)
        except rpc.Fault as err:
            print(f"Ошибка utm.get_bgp_config: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return data, neigh, rmaps, filters

##################################### Библиотека  ######################################
    def get_custom_url_list(self):
        """Получить список изменённых категорий URL раздела Библиотеки"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.content.override.domains.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.content.override.domains.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            return 2, f"\tНе удалось выгрузить список изменённых категорий URL!\n\tОшибка get_custom_url_list: [{err.faultCode}] — {err.faultString}"
        return 0, result['items']

    def add_custom_url(self, data):
        """Добавить изменённую категорию URL"""
        try:
            result = self._server.v1.content.override.domain.add(self._auth_token, data)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'\tКатегория URL: "{data["name"]}" уже существует'
            else:
                return 2, f"\tОшибка utm.add_custom_url: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def update_custom_url(self, data_id, data):
        """Обновить изменённую категорию URL"""
        try:
            result = self._server.v1.content.override.domain.update(self._auth_token, data_id, data)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tКатегория URL: {data['name']} - нет отличающихся параметров для изменения."
            else:
                return 2, f"\tОшибка utm.update_custom_url: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result

    def get_nlist_list(self, list_type):
        """Получить содержимое пользовательских именованных списков раздела Библиотеки"""
        array = []
        try:
            result = self._server.v2.nlists.list(self._auth_token, list_type, 0, 5000, {})
        except rpc.Fault as err:
            print(f"\tОшибка-1 utm.get_nlist_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)

        for item in result['items']:
            if item['editable']:
                item['name'] = item['name'].strip()
                try:
                    if list_type == 'ipspolicy' and self.version.startswith('5'):
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, {}, [])
                    else:
                        content = self._server.v2.nlists.list.list(self._auth_token, item['id'], 0, 5000, '', [])
                except rpc.Fault as err:
                    print(f'\033[33m\tСодержимое списка "{item["name"]}" не экспортировано. Ошибка загрузки списка!\033[0m')
                    content['items'] = []
                except ExpatError:
                    print(f'\033[33m\tСодержимое списка "{item["name"]}" не экспортировано. Список corrupted!\033[0m')
                    content['items'] = []
                if list_type == 'timerestrictiongroup' and self.version.startswith('5'):
                    item['content'] = [x['value'] for x in content['items']]
                elif list_type == 'httpcwl':
                    array = {'id': item['id'], 'content': content['items']}
                    break
                else:
                    item['content'] = content['items']
                array.append(item)
        return len(array), array

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

    def add_nlist_item(self, named_list_id, item):
        """Добавить 1 значение в именованный список"""
        try:
            result = self._server.v2.nlists.list.add(self._auth_token, named_list_id, item)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 2001:
                return 1, f"\t\tСодержимое: {item} не добавлено, так как уже существует."
            else:
                return 2, f"\t\tОшибка utm.add_nlist_item: [{err.faultCode}] — {err.faultString}"
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
            elif err.faultCode == 2003:
                return 3, f"\tСодержимое: {item} не добавлено, так как обновляется через URL."
            else:
                return 2, f'\tОшибка utm.add_nlist_items: [{err.faultCode}] — {err.faultString}'
        else:
            return 0, result

    def get_services_list(self):
        """Получить список сервисов раздела Библиотеки"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.libraries.services.list(self._auth_token, 0, 1000, '', [])
        except rpc.Fault as err:
            print(f"Ошибка get_services_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['total'], result

    def add_service(self, service):
        """Добавить список сервисов раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.add(self._auth_token, service)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tСервис: '{service['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_service: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID сервиса

    def update_service(self, service_id, service):
        """Обновить отдельный сервис раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.service.update(self._auth_token, service_id, service)
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить сервис '{service['name']}' c id: {service_id}. Данный сервис не найден."
            else:
                return 2, f"Ошибка update_service: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_shaper_list(self):
        """Получить список полос пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_shaper_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_shaper(self, shaper):
        """Добавить полосу пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.add(self._auth_token, shaper)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПолоса пропускания '{shaper['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"\tОшибка add_shaper: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID шейпера

    def update_shaper(self, shaper_id, shaper):
        """Обновить полосу пропускания раздела Библиотеки"""
        try:
            result = self._server.v1.shaper.pool.update(self._auth_token, shaper_id, shaper)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить полосу пропускания '{shaper['name']}' c id: {shaper_id}. Данный сервис не найден."
            else:
                return 2, f"Ошибка update_shaper: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_scada_list(self):
        """Получить список профилей АСУ ТП раздела Библиотеки"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, {}, [])
            else:
                result = self._server.v1.scada.profiles.list(self._auth_token, 0, 1000, '', [])
        except rpc.Fault as err:
            print(f"Ошибка get_scada_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result['total'], result['items']

    def add_scada(self, scada):
        """Добавить профиль АСУ ТП раздела Библиотеки"""
        try:
            result = self._server.v1.scada.profile.add(self._auth_token, scada)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tПрофиль АСУ ТП '{scada['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"Ошибка add_scada: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID шейпера

    def update_scada(self, scada_id, scada):
        """Обновить профиль АСУ ТП раздела Библиотеки"""
        try:
            result = self._server.v1.scada.profile.update(self._auth_token, scada_id, scada)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить Профиль АСУ ТП '{scada['name']}' c id: {scada_id}. Данный сервис не найден."
            else:
                return 2, f"Ошибка update_scada: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_templates_list(self):
        """Получить список шаблонов страниц раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.templates.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_templates_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_template(self, template):
        """Добавить новый шаблон в раздел "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.add(self._auth_token, template)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f"\tШаблон страницы '{template['name']}' уже существует. Проверка параметров..."
            else:
                return 2, f"\tОшибка add_template: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID шаблона

    def update_template(self, template_id, template):
        """Обновить шаблон в разделе "Шаблоны страниц" раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.update(self._auth_token, template_id, template)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 404:
                return 1, f"\tНе удалось обновить шаблон страницы '{template['name']}' c id: {template_id}. Данная страница не найдена."
            else:
                return 2, f"\tОшибка update_template: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_template_data(self, template_type, template_id):
        """Получить HTML страницы шаблона раздела Библиотеки"""
        try:
            result = self._server.v1.libraries.response.page.template.public.data.fetch(template_type, template_id)
        except rpc.Fault as err:
            print(f"Ошибка get_template_data: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result

    def set_template_data(self, template_id, data):
        """Импортировать страницу HTML шаблона раздела Библиотеки"""
        try:
            data64 = rpc.Binary(data)
            result = self._server.v1.libraries.response.page.template.data.update(self._auth_token, template_id, data64)
        except rpc.Fault as err:
            print(f"Ошибка set_template_data: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return 0, result    # Возвращает True

    def get_notification_profiles_list(self):
        """Получить список профилей оповещения раздела Библиотеки"""
        try:
            result = self._server.v1.notification.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"Ошибка get_notification_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_notification_profile(self, profile):
        """Добавить профиль оповещения раздела Библиотеки"""
        if profile['name'] in self.list_notifications.keys():
            return 1, f'\tПрофиль оповещения "{profile["name"]}" уже существует. Проверка параметров...'
        else:
            try:
                result = self._server.v1.notification.profile.add(self._auth_token, profile)
            except rpc.Fault as err:
                return 2, f"Ошибка add_notification_profiles: [{err.faultCode}] — {err.faultString}"
            return 0, result     # Возвращает ID добавленного профиля
        
    def update_notification_profile(self, profile):
        """Обновить профиль оповещения раздела Библиотеки"""
        try:
            np_id = self.list_notifications[profile['name']]
            result = self._server.v1.notification.profile.update(self._auth_token, np_id, profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"Ошибка update_notification_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

#    def get_idps_signatures_list(self):
#        """Получить список сигнатур IDPS"""
#        idps = {}
#        try:
#            result = self._server.v1.idps.signatures.list(self._auth_token, 0, 10000, {}, [])
#        except rpc.Fault as err:
#            print(f"Ошибка get_idps_signatures_list: [{err.faultCode}] — {err.faultString}")
#            sys.exit(1)
#        for item in result['items']:
#            idps[item['msg']] = item['id']
#        return 0, idps

    def get_netflow_profiles_list(self):
        """Получить список профилей netflow раздела Библиотеки"""
        try:
            result = self._server.v1.netmanager.netflow.profiles.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"Ошибка get_notification_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_netflow_profile(self, profile):
        """Добавить профиль netflow в Библиотеку"""
        try:
            result = self._server.v1.netmanager.netflow.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'\tПрофиль netflow "{profile["name"]}" уже существует. Проверка параметров...'
            else:
                return 2, f"Ошибка add_netflow_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_netflow_profile(self, profile):
        """Обновить профиль netflow раздела Библиотеки"""
        try:
            result = self._server.v1.netmanager.netflow.profile.update(self._auth_token, profile['id'], profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"Ошибка update_netflow_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_ssl_profiles_list(self):
        """Получить список профилей SSL раздела Библиотеки"""
        try:
            result = self._server.v1.content.ssl.profiles.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"Ошибка get_ssl_profiles_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_ssl_profile(self, profile):
        """Добавить профиль SSL в Библиотеку"""
        try:
            result = self._server.v1.content.ssl.profile.add(self._auth_token, profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'\tПрофиль SSL: "{profile["name"]}" уже существует. Проверка параметров...'
            else:
                return 2, f"Ошибка add_ssl_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного профиля

    def update_ssl_profile(self, profile):
        """Обновить профиль SSL раздела Библиотеки"""
        try:
            result = self._server.v1.content.ssl.profile.update(self._auth_token, profile['id'], profile)
        except TypeError as err:
            return 2, err
        except rpc.Fault as err:
            return 1, f"Ошибка utm.update_ssl_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

################################### Пользователи и устройства #####################################
    def get_groups_list(self):
        """Получить список локальных групп"""
        try:
            result = self._server.v3.accounts.groups.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_groups_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

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
        return len(result['items']), result['items']

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

    def get_auth_servers(self):
        """Получить список серверов авторизации"""
        try:
            ldap = self._server.v1.auth.ldap.servers.list(self._auth_token, {})
            radius = self._server.v1.auth.radius.servers.list(self._auth_token, {})
            tacacs = self._server.v1.auth.tacacs.plus.server.list(self._auth_token, {})
            ntlm = self._server.v1.auth.ntlm.server.list(self._auth_token, {})
            saml = self._server.v1.auth.saml.idp.servers.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_auth_servers: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return ldap, radius, tacacs, ntlm, saml

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

    def add_auth_server(self, type, server):
        """Добавить auth сервер"""
        if server['name'] in self.auth_servers.keys():
            return 1, f"\tСервер авторизации '{server['name']}' уже существует."
        try:
            if type == 'ldap':
                result = self._server.v1.auth.ldap.server.add(self._auth_token, server)
            elif type == 'ntlm':
                result = self._server.v1.auth.ntlm.server.add(self._auth_token, server)
            elif type == 'radius':
                result = self._server.v1.auth.radius.server.add(self._auth_token, server)
            elif type == 'tacacs':
                result = self._server.v1.auth.tacacs.plus.server.add(self._auth_token, server)
            elif type == 'saml':
                result = self._server.v1.auth.saml.idp.server.add(self._auth_token, server)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_auth_server: [{err.faultCode}] — {err.faultString}"
        else:
            self.auth_servers[server['name']] = result
            return 0, result     # Возвращает ID добавленного сервера авторизации

    def get_2fa_profiles(self):
        """Получить список профилей MFA"""
        try:
            f = getattr(self._server, 'v1.2fa.profiles.list')
            result = f(self._auth_token, 0, 100, '')
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_2fa_profiles: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_2fa_profile(self, profile):
        """Добавить новый профиль MFA"""
        if profile['name'] in self.profiles_2fa.keys():
            return 1, f"\tПрофиль MFA '{profile['name']}' уже существует."
        try:
            f = getattr(self._server, 'v1.2fa.profile.add')
            result = f(self._auth_token, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_2fa_profile: [{err.faultCode}] — {err.faultString}"
        else:
            self.profiles_2fa[profile['name']] = result
            return 0, result     # Возвращает ID добавленного профиля

    def get_auth_profiles(self):
        """Получить список профилей авторизации"""
        try:
            result = self._server.v1.auth.user.auth.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_auth_profiles: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_auth_profile(self, profile):
        """Добавить новый профиль авторизации"""
        if profile['name'] in self.auth_profiles.keys():
            return 1, f"\tПрофиль авторизации '{profile['name']}' уже существует."
        try:
            result = self._server.v1.auth.user.auth.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tПрофиль авторизации "{profile["name"]}" не добавлен — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_auth_profile: [{err.faultCode}] — {err.faultString}"
        else:
            self.auth_profiles[profile['name']] = result
            return 0, result     # Возвращает ID добавленного профиля

    def update_auth_profile(self, profile):
        """Обновить профиль авторизации"""
        try:
            result = self._server.v1.auth.user.auth.profile.update(self._auth_token, profile['id'], profile)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_auth_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_captive_profiles(self):
        """Получить список Captive-профилей"""
        try:
            result = self._server.v1.captiveportal.profiles.list(self._auth_token, 0, 1000, '')
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_captive_profiles: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_captive_profile(self, profile):
        """Добавить новый Captive-профиль"""
        if profile['name'] in self.captive_profiles.keys():
            return 1, f"\tПрофиль авторизации '{profile['name']}' уже существует."
        try:
            result = self._server.v1.captiveportal.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tПрофиль авторизации "{profile["name"]}" не добавлен — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_captive_profile: [{err.faultCode}] — {err.faultString}"
        else:
            self.captive_profiles[profile['name']] = result
            return 0, result     # Возвращает ID добавленного профиля

    def update_captive_profile(self, profile):
        """Обновить Captive-профиль"""
        try:
            profile_id = self.captive_profiles[profile['name']]
            result = self._server.v1.captiveportal.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_captive_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_captive_portal_rules(self):
        """Получить список правил Captive-попортала"""
        try:
            result = self._server.v1.captiveportal.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_captive_portal_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_captive_portal_rules(self, rule):
        """Добавить новое правило Captive-портала"""
        if rule['name'] in self.captive_portal_rules.keys():
            return 1, f'\tПравило Captive-портала "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.captiveportal.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tПравило Captive-портала "{rule["name"]}" не добавлено — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_captive_portal_rules: [{err.faultCode}] — {err.faultString}"
        else:
            self.captive_portal_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_captive_portal_rule(self, rule):
        """Обновить правило Captive-портала"""
        try:
            rule_id = self.captive_portal_rules[rule['name']]
            result = self._server.v1.captiveportal.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_captive_portal_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_byod_policy(self):
        """Получить список политик BYOD"""
        try:
            result = self._server.v1.byod.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_byod_policy: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_byod_policy(self, rule):
        """Добавить новое правило в Политики BYOD"""
        if rule['name'] in self.byod_rules.keys():
            return 1, f'\tПравило BYOD "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.byod.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tПравило BYOD "{rule["name"]}" не добавлено — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_byod_policy: [{err.faultCode}] — {err.faultString}"
        else:
            self.byod_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_byod_policy(self, rule):
        """Обновить правило Captive-портала"""
        try:
            rule_id = self.byod_rules[rule['name']]
            result = self._server.v1.byod.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_byod_policy: [{err.faultCode}] — {err.faultString}"
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

    def get_ldap_user_name(self, user_guid):
        """Получить имя пользователя LDAP по его GUID"""
        user = []
        try:
            result = self._server.v1.ldap.user.fetch(self._auth_token, user_guid)
        except rpc.Fault as err:
            if err.faultCode == 1:
                return 2, f'\tНе возможно получить имя доменного пользователя.\n\tПроверьте что версия UTM 5.0.6.4973 (6.1.3.10697) или выше.'
            else:
                return 1, f"\tОшибка utm.get_ldap_user_name: [{err.faultCode}] — {err.faultString}\n\tПроверьте настройки LDAP-коннектора!"
        name = result['name']
        i = name.find('(')
        return 0, name[i+1:len(name)-1]

    def get_ldap_group_name(self, group_guid):
        """Получить имя группы LDAP по её GUID"""
        user = []
        try:
            result = self._server.v1.ldap.group.fetch(self._auth_token, group_guid)
        except rpc.Fault as err:
            if err.faultCode == 1:
                return 2, f'\tНе возможно получить имя доменной группы.\n\tПроверьте что версия UTM 5.0.6.4973 (6.1.3.10697) или выше.'
            else:
                return 1, f"\tОшибка utm.get_ldap_group_name: [{err.faultCode}] — {err.faultString}\n\tПроверьте настройки LDAP-коннектора!"
        data = [x.split('=') for x in result['name'].split(',')]
        for y in data:
            if y[0] == 'CN':
                return 0, f"{result['guid'].split(':')[0]}\\{y[1]}"

################### Политики сети ############################################################
    def get_firewall_rules(self):
        """Получить список правил межсетевого экрана"""
        try:
            result = self._server.v1.firewall.rules.list(self._auth_token, 0, 5000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_firewall_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_firewall_rule(self, rule):
        """Добавить новое правило в МЭ"""
        if rule['name'] in self.firewall_rules.keys():
            return 1, f'\tПравило МЭ "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.firewall.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tПравило МЭ "{rule["name"]}" не добавлено — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_firewall_rule: [{err.faultCode}] — {err.faultString}"
        else:
            self.firewall_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_firewall_rule(self, rule):
        """Обновить правило МЭ"""
        try:
            rule_id = self.firewall_rules[rule['name']]
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

    def get_loadbalancing_rules(self):
        """Получить список правил балансировки нагрузки"""
        try:
            tcpudp = self._server.v1.virtualserver.rules.list(self._auth_token)
            icap = self._server.v1.icap.loadbalancing.rules.list(self._auth_token)
            reverse = self._server.v1.reverseproxy.loadbalancing.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_loadbalancing_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return tcpudp, icap, reverse

    def add_virtualserver_rule(self, rule):
        """Добавить новое правило балансировки нагрузки TCP/UDP"""
        if rule['name'] in self.tcpudp_rules.keys():
            return 1, f'\tПравило "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.virtualserver.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 409:
                return 1, f'\tПравило "{rule["name"]}" уже существует.'
            else:
                return 2, f"\tОшибка utm.add_virtualserver_rule: [{err.faultCode}] — {err.faultString}"
        else:
            self.tcpudp_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_virtualserver_rule(self, rule):
        """Обновить правило балансировки нагрузки TCP/UDP"""
        try:
            rule_id = self.tcpudp_rules[rule['name']]
            result = self._server.v1.virtualserver.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_virtualserver_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def add_icap_loadbalancing_rule(self, rule):
        """Добавить новое правило балансировки нагрузки ICAP"""
        if rule['name'] in self.icap_loadbalancing.keys():
            return 1, f'\tПравило "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.icap.loadbalancing.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
                return 2, f"\tОшибка utm.add_icap_loadbalancing_rule: [{err.faultCode}] — {err.faultString}"
        else:
            self.icap_loadbalancing[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_icap_loadbalancing_rule(self, rule):
        """Обновить правило балансировки нагрузки ICAP"""
        try:
            rule_id = self.icap_loadbalancing[rule['name']]
            result = self._server.v1.icap.loadbalancing.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_icap_loadbalancing_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def add_reverse_loadbalancing_rule(self, rule):
        """Добавить новое правило балансировки нагрузки reverse-proxy"""
        if rule['name'] in self.reverse_rules.keys():
            return 1, f'\tПравило "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.reverseproxy.loadbalancing.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
                return 2, f"\tОшибка utm.add_reverse_loadbalancing_rule: [{err.faultCode}] — {err.faultString}"
        else:
            self.reverse_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_reverse_loadbalancing_rule(self, rule):
        """Обновить правило балансировки нагрузки reverse-proxy"""
        try:
            rule_id = self.reverse_rules[rule['name']]
            result = self._server.v1.reverseproxy.loadbalancing.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_reverse_loadbalancing_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_shaper_rules(self):
        """Получить список правил пропускной способности"""
        try:
            result = self._server.v1.shaper.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_shaper_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_shaper_rule(self, shaper_rules, rule):
        """Добавить новое правило пропускной способности"""
        if rule['name'] in shaper_rules.keys():
            return 1, f'\tПравило "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.shaper.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_shaper_rule: [{err.faultCode}] — {err.faultString}"
        else:
            shaper_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_shaper_rule(self, rule_id, rule):
        """Обновить сценарий"""
        try:
            result = self._server.v1.shaper.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_shaper_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_content_rules(self):
        """Получить список правил фильтрации контента"""
        try:
            result = self._server.v1.content.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_content_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

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

    def get_safebrowsing_rules(self):
        """Получить список правил веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_safebrowsing_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_safebrowsing_rule(self, rule):
        """Добавить новое правило веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_safebrowsing_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_safebrowsing_rule(self, rule_id, rule):
        """Обновить правило веб-безопасности"""
        try:
            result = self._server.v1.content.filtering.options.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_safebrowsing_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_ssldecrypt_rules(self):
        """Получить список правил инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_ssldecrypt_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_ssldecrypt_rule(self, rule):
        """Добавить новое правило инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_ssldecrypt_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_ssldecrypt_rule(self, rule_id, rule):
        """Обновить правило инспектирования SSL"""
        try:
            result = self._server.v1.content.ssl.decryption.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_ssldecrypt_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_sshdecrypt_rules(self):
        """Получить список правил инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_sshdecrypt_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_sshdecrypt_rule(self, rule):
        """Добавить новое правило инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_sshdecrypt_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_sshdecrypt_rule(self, rule_id, rule):
        """Обновить правило инспектирования SSH"""
        try:
            result = self._server.v1.content.ssh.decryption.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_sshdecrypt_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_idps_rules(self):
        """Получить список правил СОВ"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.idps.rules.list(self._auth_token, 0, 1000, {})
                return len(result['items']), result['items']
            else:
                result = self._server.v1.idps.rules.list(self._auth_token, {})
                return len(result), result
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_idps_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
    
    def add_idps_rule(self, rule):
        """Добавить новое правило СОВ"""
        try:
            result = self._server.v1.idps.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_idps_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_idps_rule(self, rule_id, rule):
        """Обновить правило СОВ"""
        try:
            result = self._server.v1.idps.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_idps_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_scada_rules(self):
        """Получить список правил АСУ ТП"""
        try:
            if self.version.startswith('6'):
                result = self._server.v1.scada.rules.list(self._auth_token, 0, 1000, {})
                return len(result['items']), result['items']
            else:
                result = self._server.v1.scada.rules.list(self._auth_token, {})
                return len(result), result
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_scada_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)

    def add_scada_rule(self, rule):
        """Добавить новое правило АСУ ТП"""
        try:
            result = self._server.v1.scada.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_scada_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_scada_rule(self, rule_id, rule):
        """Обновить правило АСУ ТП"""
        try:
            result = self._server.v1.scada.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_scada_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_scenarios_rules(self):
        """Получить список сценариев"""
        try:
            result = self._server.v1.scenarios.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_scenarios_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_scenarios_rule(self, rule):
        """Добавить новый сценарий в Сценарии"""
        if rule['name'] in self.scenarios_rules.keys():
            return 1, f'\tСценарий "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.scenarios.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tСценарий "{rule["name"]}" не добавлен — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_scenarios_rule: [{err.faultCode}] — {err.faultString}"
        else:
            self.scenarios_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_scenarios_rule(self, rule):
        """Обновить сценарий"""
        try:
            rule_id = self.scenarios_rules[rule['name']]
            result = self._server.v1.scenarios.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_scenarios_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_mailsecurity_rules(self):
        """Получить список правил защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.rules.list(self._auth_token, 0, 1000, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_mailsecurity_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_mailsecurity_rule(self, rule):
        """Добавить новое правило защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_mailsecurity_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_mailsecurity_rule(self, rule_id, rule):
        """Обновить правило защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_mailsecurity_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_mailsecurity_dnsbl(self):
        """Получить список dnsbl и batv защиты почтового трафика"""
        try:
            dnsbl = self._server.v1.mailsecurity.dnsbl.config.get(self._auth_token)
            batv = self._server.v1.mailsecurity.batv.config.get(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_mailsecurity_dnsbl: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return dnsbl, batv

    def set_mailsecurity_dnsbl(self, rule):
        """Установить конфигурацию DNSBL защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.dnsbl.config.set(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_mailsecurity_dnsbl: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def set_mailsecurity_batv(self, rule):
        """Установить конфигурацию BATV защиты почтового трафика"""
        try:
            result = self._server.v1.mailsecurity.batv.config.set(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.set_mailsecurity_batv: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def get_icap_servers(self):
        """Получить список серверов ICAP"""
        try:
            result = self._server.v1.icap.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_icap_servers: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_icap_server(self, profile):
        """Добавить новый ICAP сервер"""
        if profile['name'] in self.icap_servers.keys():
            return 1, f'\tICAP-сервер "{profile["name"]}" уже существует.'
        try:
            result = self._server.v1.icap.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            if err.faultCode == 110:
                return 2, f'\tСервер "{profile["name"]}" не добавлен — {err.faultString}.'
            else:
                return 2, f"\tОшибка utm.add_icap_server: [{err.faultCode}] — {err.faultString}"
        else:
            self.icap_servers[profile['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_icap_server(self, profile):
        """Обновить ICAP сервер"""
        try:
            profile_id = self.icap_servers[profile['name']]
            result = self._server.v1.icap.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_icap_server: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_icap_rules(self):
        """Получить список правил ICAP"""
        try:
            if self.version.startswith('5'):
                result = self._server.v1.icap.rules.list(self._auth_token, {})
            else:
                result = self._server.v1.icap.rules.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_icap_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result if self.version.startswith('5') else result['items']

    def add_icap_rule(self, icap_rules, rule):
        """Добавить новое ICAP-правило"""
        if rule['name'] in icap_rules.keys():
            return 1, f'\tICAP-правило "{rule["name"]}" уже существует.'
        try:
            result = self._server.v1.icap.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_icap_rule: [{err.faultCode}] — {err.faultString}"
        else:
            icap_rules[rule['name']] = result
            return 0, result     # Возвращает ID добавленного правила

    def update_icap_rule(self, icap_rules, rule):
        """Обновить ICAP-правило"""
        try:
            rule_id = icap_rules[rule['name']]
            result = self._server.v1.icap.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 1, f"\tОшибка utm.update_icap_rules: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_dos_profiles(self):
        """Получить список профилей DoS"""
        try:
            result = self._server.v1.dos.profiles.list(self._auth_token, 0, 100, '')
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_dos_profiles: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_dos_profile(self, profile):
        """Добавить новый профиль DoS"""
        try:
            result = self._server.v1.dos.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_dos_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_dos_profile(self, profile_id, profile):
        """Обновить профиль DoS"""
        try:
            result = self._server.v1.dos.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_dos_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_dos_rules(self):
        """Получить список правил защиты DoS"""
        try:
            result = self._server.v1.dos.rules.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_dos_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result['items']), result['items']

    def add_dos_rule(self, rule):
        """Добавить новое правило защиты DoS"""
        try:
            result = self._server.v1.dos.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_dos_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_dos_rule(self, rule_id, rule):
        """Обновить правило защиты DoS"""
        try:
            result = self._server.v1.dos.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_dos_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_proxyportal_rules(self):
        """Получить список ресурсов URL веб-портала"""
        try:
            result = self._server.v1.proxyportal.bookmarks.list(self._auth_token, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_proxyportal_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_proxyportal_rule(self, rule):
        """Добавить новый URL-ресурс веб-портала"""
        try:
            result = self._server.v1.proxyportal.bookmark.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_proxyportal_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_proxyportal_rule(self, rule_id, rule):
        """Обновить URL-ресурс веб-портала"""
        try:
            result = self._server.v1.proxyportal.bookmark.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_proxyportal_rule: [{err.faultCode}] — {err.faultString}"
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

    def get_vpn_security_profiles(self):
        """Получить список профилей безопасности VPN"""
        try:
            result = self._server.v1.vpn.security.profiles.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_vpn_security_profiles: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_vpn_security_profile(self, profile):
        """Добавить новый профиль безопасности VPN"""
        try:
            result = self._server.v1.vpn.security.profile.add(self._auth_token, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_vpn_security_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_vpn_security_profile(self, profile_id, profile):
        """Обновить профиль безопасности VPN"""
        try:
            result = self._server.v1.vpn.security.profile.update(self._auth_token, profile_id, profile)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_vpn_security_profile: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_vpn_networks(self):
        """Получить список сетей VPN"""
        try:
            result = self._server.v1.vpn.tunnels.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_vpn_networks: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_vpn_network(self, network):
        """Добавить новую сеть VPN"""
        try:
            result = self._server.v1.vpn.tunnel.add(self._auth_token, network)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_vpn_network: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_vpn_network(self, network_id, network):
        """Обновить сеть VPN"""
        try:
            result = self._server.v1.vpn.tunnel.update(self._auth_token, network_id, network)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_vpn_network: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_vpn_server_rules(self):
        """Получить список серверных правил VPN"""
        try:
            result = self._server.v1.vpn.server.rules.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_vpn_server_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        if self.version.startswith('5'):
            return len(result), result
        else:
            return len(result['items']), result['items']

    def add_vpn_server_rule(self, rule):
        """Добавить новое серверное правило VPN"""
        try:
            result = self._server.v1.vpn.server.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_vpn_server_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_vpn_server_rule(self, rule_id, rule):
        """Обновить серверное правило VPN"""
        try:
            result = self._server.v1.vpn.server.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_vpn_server_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

    def get_vpn_client_rules(self):
        """Получить список клиентских правил VPN"""
        try:
            result = self._server.v1.vpn.client.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_vpn_client_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def add_vpn_client_rule(self, rule):
        """Добавить новое клиентское правило VPN"""
        try:
            if self.version.startswith('6.2'):
                result = self._server.v1.vpn.client.rule.add(self._auth_token, rule)
            else:
                result = self._server.v1.vpn.client.rule.add(self._auth_token, self.node_name, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_vpn_client_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_vpn_client_rule(self, rule_id, rule):
        """Обновить клиентское правило VPN"""
        try:
            if self.version.startswith('6.2'):
                result = self._server.v1.vpn.client.rule.update(self._auth_token, rule_id, rule)
            else:
                result = self._server.v1.vpn.client.rule.update(self._auth_token, self.node_name, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_vpn_client_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает True

########################################### Оповещения ###########################################
    def get_snmp_rules(self):
        """Получить список правил SNMP"""
        try:
            result = self._server.v1.snmp.rules.list(self._auth_token)
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_vpn_client_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def add_snmp_rule(self, rule):
        """Добавить новое правило SNMP"""
        try:
            result = self._server.v1.snmp.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_snmp_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_snmp_rule(self, rule_id, rule):
        """Обновить правило SNMP"""
        try:
            result = self._server.v1.snmp.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_snmp_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID изменённого правила

    def get_notification_alert_rules(self):
        """Получить список правил оповещений"""
        try:
            result = self._server.v1.notification.alert.rules.list(self._auth_token, 0, 100, {})
        except rpc.Fault as err:
            print(f"\tОшибка utm.get_notification_alert_rules: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return result

    def add_notification_alert_rule(self, rule):
        """Добавить новое правило SNMP"""
        try:
            result = self._server.v1.notification.alert.rule.add(self._auth_token, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.add_notification_alert_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID добавленного правила

    def update_notification_alert_rule(self, rule_id, rule):
        """Обновить правило SNMP"""
        try:
            result = self._server.v1.notification.alert.rule.update(self._auth_token, rule_id, rule)
        except rpc.Fault as err:
            return 2, f"\tОшибка utm.update_notification_alert_rule: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result     # Возвращает ID изменённого правила

class UtmError(Exception): pass

character_map = {
    ord('\n'): '',
    ord('\t'): '',
    ord('\r'): '',
    ':': '_',
    '/': '_',
    '\\': '_',
    '.': '_',
    ' ': '_',
}
