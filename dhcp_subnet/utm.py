#!/usr/bin/python3
# Общий класс для работы с xml-rpc
import sys
import xmlrpc.client as rpc


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

    def get_interfaces_list(self):
        """Получить список сетевых интерфейсов"""
        try:
            result = self._server.v1.netmanager.interfaces.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_interfaces_list: [{err.faultCode}] — {err.faultString}")
            sys.exit(1)
        return len(result), result

    def get_dhcp_list(self):
        """Получить список подсетей для dhcp"""
        try:
            result = self._server.v1.netmanager.dhcp.subnets.list(self._auth_token, self.node_name, {})
        except rpc.Fault as err:
            print(f"Ошибка get_dhcp_list: [{err.faultCode}] — {err.faultString}")
        return len(result), result

    def add_dhcp_subnet(self, subnet):
        """Добавить DHCP subnet"""
        try:
            result = self._server.v1.netmanager.dhcp.subnet.add(self._auth_token, self.node_name, subnet)
        except TypeError as err:
            return 11, err
        except rpc.Fault as err:
            if err.faultCode == 1017:
                return 1, f"DHCP subnet: {subnet['name']} уже существует."
            else:
                return 2, f"Ошибка add_dhcp_subnet: [{err.faultCode}] — {err.faultString}"
        else:
            return 0, result


class UtmError(Exception): pass
