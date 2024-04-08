#!/usr/bin/python3
#
# Версия 1.5
#-----------------------------------------------------------------------------------------------------------------------------

import os, json, ipaddress
from PyQt6.QtGui import QBrush, QColor, QFont, QPalette
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QWidget, QFrame, QDialog, QMessageBox,
                             QListWidget, QListWidgetItem, QPushButton, QLabel, QSpacerItem, QLineEdit, QComboBox, QScrollArea,
                             QTreeWidget, QTreeWidgetItem, QSizePolicy, QSplitter)
import config_style as cs
import export_functions as ef
import import_functions as tf
import get_temporary_data as gtd
from utm import UtmXmlRpc
from common_func import create_dir, message_inform, message_question, message_alert


class SelectAction(QWidget):
    """Класс для выбора режима: экспорт/импорт. Номер в стеке 0."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        text1 = "<b><font color='green' size='+2'>Экспорт/Импорт конфигурации NGFW UserGate</font></b>"
        text2 = "Экспорт конфигурации из NGFW версий 5, 6, 7 и сохранение её в файлах json в каталоге 'data' в текущей директории. \
После экспорта вы можете просмотреть результат и изменить содержимое файлов в соответствии с вашими потребностями."
        text3 = "Импорт файлов конфигурации из каталога 'data' на NGFW версий 5, 6 и 7."
        label1 = QLabel(text1)
        label1.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        label2 = QLabel(text2)
        label2.setWordWrap(True)
        label3 = QLabel(text3)
        
        layout = QGridLayout()
        layout.addWidget(QLabel("<font color='blue'>Экспорт конфигурации:</font>"), 0, 0, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(label2, 0, 1)
        layout.addWidget(QLabel("<font color='blue'>Импорт конфигурации:</font>"), 1, 0)
        layout.addWidget(label3, 1, 1)

        self.btn_export = QPushButton("Экспорт конфигурации")
        self.btn_export.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_export.setFixedWidth(200)
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.set_export_page)
        self.btn_import = QPushButton("Импорт конфигурации")
        self.btn_import.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import.setFixedWidth(200)
        self.btn_import.setEnabled(False)
        self.btn_import.clicked.connect(self.set_import_page)
        btn_exit = QPushButton("Выход")
        btn_exit.setStyleSheet('color: darkred; background: white;')
        btn_exit.setFixedWidth(200)
        btn_exit.clicked.connect(self.parent.close)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)

        btn_vbox = QVBoxLayout()
        btn_vbox.addSpacerItem(QSpacerItem(5, 10))
        btn_vbox.addWidget(self.btn_export)
        btn_vbox.addWidget(self.btn_import)
        btn_vbox.addSpacerItem(QSpacerItem(5, 10))
        btn_vbox.addWidget(btn_exit)
        btn_vbox.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        vbox = QVBoxLayout()
        vbox.addWidget(label1)
        vbox.addSpacerItem(QSpacerItem(5, 10))
        vbox.addLayout(layout)
        vbox.addSpacerItem(QSpacerItem(5, 15))
        vbox.addWidget(line)
        vbox.addLayout(btn_vbox)
        self.setLayout(vbox)
        
        self.parent.stacklayout.currentChanged.connect(self.resize_window)

    def resize_window(self, e):
        if e == 0:
            self.parent.resize(610, 291)

    def set_export_page(self):
        """Переходим на страницу экспорта конфигурации."""
        self.parent.stacklayout.setCurrentIndex(1)

    def set_import_page(self):
        """Переходим на страницу импорта конфигурации."""
        self.parent.stacklayout.setCurrentIndex(2)

    def enable_buttons(self):
        self.btn_export.setStyleSheet('color: forestgreen; background: white;')
        self.btn_export.setEnabled(True)
        self.btn_import.setStyleSheet('color: steelblue; background: white;')
        self.btn_import.setEnabled(True)

class SelectMode(QWidget):
    """Класс для выбора раздела конфигурации для экспорта/импорта."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.selected_points = []
        self.current_path = None
        self.utm = None
        self.thread = None
        self.log_list = QListWidget()
        
        self.title = QLabel()
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title.setFixedHeight(22)

        frame_nodeinfo = QFrame()
        frame_nodeinfo.setFixedHeight(20)
        frame_nodeinfo.setStyleSheet(
            'background-color: #2690c8; '
            'color: white; font-size: 12px; font-weight: bold; '
            'border-radius: 4px; padding: 0px; margin: 0px;'
        )
        self.label_node_name = QLabel()
        self.label_node_name.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.label_version = QLabel()
        self.label_version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_config_directory = QLabel()
        self.label_config_directory.setAlignment(Qt.AlignmentFlag.AlignRight)
        hbox_nodeinfo = QHBoxLayout()
        hbox_nodeinfo.addWidget(self.label_node_name)
        hbox_nodeinfo.addWidget(self.label_version)
        hbox_nodeinfo.addWidget(self.label_config_directory)
        hbox_nodeinfo.setContentsMargins(0, 2, 0, 2)
        frame_nodeinfo.setLayout(hbox_nodeinfo)

        self.tree = MainTree()

        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.log_list)
        hbox_splitter = QHBoxLayout()
        hbox_splitter.addWidget(splitter)

        self.btn1 = QPushButton("Назад")
        self.btn1.setFixedWidth(100)
        self.btn1.clicked.connect(self.run_page_0)
        self.btn2 = QPushButton()
        self.btn2.setFixedWidth(190)
        self.btn3 = QPushButton()
        self.btn3.setFixedWidth(140)
        self.btn4 = QPushButton("Сохранить лог")
        self.btn4.setFixedWidth(100)

        hbox_btn = QHBoxLayout()
        hbox_btn.addWidget(self.btn1)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn2)
        hbox_btn.addWidget(self.btn3)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn4)
        
        vbox = QVBoxLayout()
        vbox.addWidget(self.title)
        vbox.addWidget(frame_nodeinfo)
        vbox.addLayout(hbox_splitter)
        vbox.addSpacerItem(QSpacerItem(1, 3))
        vbox.addLayout(hbox_btn)
        self.setLayout(vbox)

        self.disable_buttons()
        self.tree.itemSelected.connect(self.get_selected_item)


    def disable_buttons(self):
        self.btn1.setStyleSheet('color: gray; background: gainsboro;')
        self.btn1.setEnabled(False)
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
        self.btn3.setEnabled(False)
        self.btn4.setStyleSheet('color: gray; background: gainsboro;')
        self.btn4.setEnabled(False)

    def enable_buttons(self):
        self.btn1.setStyleSheet('color: steelblue; background: white;')
        self.btn1.setEnabled(True)
        self.btn2.setStyleSheet('color: forestgreen; background: white;')
        self.btn2.setEnabled(True)
        self.btn3.setStyleSheet('color: darkred; background: white;')
        self.btn3.setEnabled(True)
        self.btn4.setStyleSheet('color: steelblue; background: white;')
        self.btn4.setEnabled(True)

    def get_auth(self):
        """Вызываем окно авторизации, если авторизация не прошла, возвращаемся в начальный экран."""
        if self.utm:
            self.utm.logout()
            self.utm = None
        dialog = LoginWindow(parent=self)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.utm = dialog.utm
            self.label_node_name.setText(f'  {self.utm.node_name}')
            self.label_version.setText(f'Версия: {self.utm.version}')
            return True
        else:
            return False

    def get_selected_item(self, selected_item):
        """
        Получаем выбранный пункт меню и устанавливаем путь к разделу конфигурации.
        Запоминаем выбранный пункт/пункты раздела в массиве self.selected_points.
        """
        self.current_path = os.path.join(self.parent.get_config_path(), selected_item['path'])
        self.selected_points = selected_item['points']

    def init_temporary_data(self, mode):
        """
        Запускаем в потоке itd.GetTemporaryData() для получения часто используемых данных с NGFW.
        """
        if self.thread is None:
            self.disable_buttons()
            self.thread = gtd.GetExportTemporaryData(self.utm) if mode == 'export' else gtd.GetImportTemporaryData(self.utm)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        path_logfile = os.path.join(self.parent.get_config_path(), log_file)
        list_items = [self.log_list.item(row).text() for row in range(self.log_list.count())]
        with open(path_logfile, 'w') as fh:
            print(*list_items, sep='\n', file=fh)
            fh.write('\n')
        message_inform(self, 'Сохранение лога', f'Лог сохранён в файл "{path_logfile}".')

    def run_page_0(self):
        """Возвращаемся на стартовое окно"""
        if self.utm:
            self.utm.logout()
        self.utm = None
        self.label_node_name.setText('')
        self.label_version.setText('')
        self.label_config_directory.setText('')
        self.log_list.clear()
        self.selected_points = []
        self.current_path = None
        self.tree.version = None
        self.parent.stacklayout.setCurrentIndex(0)

    def add_item_log(self, message, color='BLACK'):
        """
        Добавляем запись лога в log_list.
        """
        i = QListWidgetItem(message)
        i.setForeground(QColor(cs.color[color]))
        self.log_list.addItem(i)

    def on_step_changed(self, msg):
        color, message = msg.split('|')
        self.add_item_log(message, color=color)
        self.log_list.scrollToBottom()
        if color in ('iORANGE', 'iGREEN', 'iRED'):
            message_inform(self, 'Внимание!', message)

    def on_finished(self):
        self.thread = None
        self.enable_buttons()


class SelectExportMode(SelectMode):
    """Класс для выбора раздела конфигурации для экспорта. Номер в стеке 1."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title.setText("<b><font color='green' size='+2'>Выбор раздела конфигурации для экспорта</font></b>")
        self.btn2.setText("Экспорт выбранного раздела")
        self.btn2.clicked.connect(self.export_selected_points)
        self.btn3.setText("Экспортировать всё")
        self.btn3.clicked.connect(self.export_all)
        self.btn4.clicked.connect(lambda: self._save_logs('export.log'))
        self.parent.stacklayout.currentChanged.connect(self.init_export_widget)

    def init_export_widget(self, e):
        """
        При открытии этой вкладки выбираем/создаём каталог для экспорта/импорта конфигурации.
        """
        if e == 1:
            self.parent.resize(900, 500)
            dialog =  SelectConfigDirectoryWindow(self.parent, mode='export')
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'{self.parent.get_config_path()}  ')
                if self.get_auth():
                    self.enable_buttons()
                    self.tree.version = f'{self.utm.version_hight}.{self.utm.version_midle}'
                    self.tree.change_items_status()
                    self.tree.setCurrentItem(self.tree.topLevelItem(0))
                    self.init_temporary_data('export')
                else:
                    self.run_page_0()
            else:
                self.run_page_0()

    def export_selected_points(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем экспорт выбранного раздела конфигурации.
        """
        err = 0; msg = ' '
        match self.utm.ping_session()[0]:
            case 1:
                err, msg = self.utm.connect()
            case 2:
                err, msg = self.utm.login()
        if err:
            message_alert(self, msg, '')
            self.run_page_0()

        if self.selected_points:
            self.disable_buttons()
            if self.thread is None:
                self.thread = ef.ExportSelectedPoints(self.utm, self.parent.get_config_path(), self.current_path, self.selected_points)
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {key} {self.thread}')
        else:
            message_inform(self, "Внимание!", "Вы не выбрали раздел для экспорта.")

    def export_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем экспорт выбранного раздела конфигурации.
        """
        err = 0; msg = ' '
        match self.utm.ping_session()[0]:
            case 1:
                err, msg = self.utm.connect()
            case 2:
                err, msg = self.utm.login()
        if err:
            message_alert(self, msg, '')
            self.run_page_0()

        all_points = self.tree.select_all_items()

        self.disable_buttons()
        if self.thread is None:
            self.thread = ef.ExportAll(self.utm, self.parent.get_config_path(), all_points)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {key} {self.thread}')


class SelectImportMode(SelectMode):
    """Класс для выбора раздела конфигурации для импорта. Номер в стеке 2."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title.setText("<b><font color='green' size='+2'>Выбор раздела конфигурации для импорта</font></b>")
        self.btn2.setText("Импорт выбранного раздела")
        self.btn2.clicked.connect(self.import_selected_points)
        self.btn3.setText("Импортировать всё")
        self.btn3.clicked.connect(self.import_all)
        self.btn4.clicked.connect(lambda: self._save_logs('import.log'))
        self.parent.stacklayout.currentChanged.connect(self.init_import_widget)

    def init_import_widget(self, e):
        """
        При открытии этой вкладки выбираем каталог с конфигурацией для импорта.
        """
        if e == 2:
            self.parent.resize(900, 500)
            dialog =  SelectConfigDirectoryWindow(self.parent, mode='import')
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'{self.parent.get_config_path()}  ')
                if self.get_auth():
                    self.enable_buttons()
                    self.tree.version = f'{self.utm.version_hight}.{self.utm.version_midle}'
                    self.tree.change_items_status()
                    self.tree.setCurrentItem(self.tree.topLevelItem(0))
                    self.init_temporary_data('import')
                else:
                    self.run_page_0()
            else:
                self.run_page_0()

    def import_selected_points(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт выбранного раздела конфигурации.
        """
        err = 0; msg = ' '
        match self.utm.ping_session()[0]:
            case 1:
                err, msg = self.utm.connect()
            case 2:
                err, msg = self.utm.login()
        if err:
            message_alert(self, msg, '')
            self.run_page_0()

        if self.selected_points:
            if self.thread is None:
                self.disable_buttons()
                arguments = {
                    'ngfw_ports': '',
                    'dhcp_settings': '',
                    'ngfw_vlans': '',
                    'new_vlans': '',
                    'iface_settings': '',
                }
                self.set_arguments(arguments)

                self.thread = tf.ImportSelectedPoints(self.utm, self.parent.get_config_path(), self.current_path, self.selected_points, arguments)
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

        else:
            message_inform(self, "Внимание!", "Вы не выбрали раздел для импорта.")

    def import_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт всей конфигурации.
        """
        err = 0; msg = ' '
        match self.utm.ping_session()[0]:
            case 1:
                err, msg = self.utm.connect()
            case 2:
                err, msg = self.utm.login()
        if err:
            message_alert(self, msg, '')
            self.run_page_0()

        all_points = self.tree.select_all_items()
        arguments = {
            'ngfw_ports': '',
            'dhcp_settings': '',
            'ngfw_vlans': '',
            'new_vlans': '',
            'iface_settings': '',
        }
        for item in all_points:
            self.current_path = os.path.join(self.parent.get_config_path(), item['path'])
            self.selected_points = item['points']
            self.set_arguments(arguments)

        if self.thread is None:
            self.disable_buttons()
            self.thread = tf.ImportAll(self.utm, self.parent.get_config_path(), all_points, arguments)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

        self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def set_arguments(self, arguments):
        """Заполняем структуру параметров для импорта."""
        if 'DHCP' in self.selected_points:
            err, result = self.import_dhcp()
            arguments['ngfw_ports'] = err
            arguments['dhcp_settings'] = result
        if 'Interfaces' in self.selected_points:
            if self.utm.version_hight == 5:
                arguments['ngfw_vlans'] = 2
                arguments['new_vlans'] = f'bRED|    VLAN нельзя импортировать на NGFW версии {self.utm.version}.'
            else:
                err, result = self.create_vlans()
                if err:
                    arguments['ngfw_vlans'] = err
                    arguments['new_vlans'] = result
                else:
                    arguments['iface_settings'] = result[0]
                    arguments['ngfw_vlans'] = result[1]
                    arguments['new_vlans'] = result[2]

    def create_vlans(self):
        """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
        iface_path = os.path.join(self.current_path, 'Interfaces')
        json_file = os.path.join(iface_path, 'config_interfaces.json')
        err, data = self.read_json_file(json_file)
        if err:
            return err, data

        vlans = sorted([item['vlan_id'] for item in data if item['kind'] == 'vlan'])
        if not vlans:
            return 3, 'LBLUE|    Нет VLAN для импорта.'

        err, result = self.utm.get_zones_list()
        if err:
            return err, f'RED|    {result}'
        zones = sorted([x['name'] for x in result])
        zones.insert(0, "Undefined")

        # Составляем список легитимных интерфейсов (interfaces_list).
        ngfw_vlans = {}
        management_port = ''
        interfaces_list = []
        err, result = self.utm.get_interfaces_list()
        if err:
            return err, f'RED|    {result}'

        for item in result:
            if item['kind'] == 'vlan':
                ngfw_vlans[item['vlan_id']] = item['name']
                continue
            for ip in item['ipv4']:
                if ip.startswith(self.utm.server_ip):
                    management_port = item["name"]
                    self.on_step_changed(f'NOTE|    Интерфейс {item["name"]} - {self.utm.server_ip} используется для текущей сессии.')
                    self.on_step_changed('NOTE|    Он не будет использоваться для создания интерфейсов VLAN.')
            if item['kind'] not in ('bridge', 'bond', 'adapter') or item['master']:
                continue
            if item["name"] == management_port:
                continue
            interfaces_list.append(item['name'])
        interfaces_list.insert(0, "Undefined")

        dialog = VlanWindow(self, vlans=vlans, ports=interfaces_list, zones=zones)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            new_vlans = {}
            for key, value in dialog.vlans.items():
                new_vlans[key] = {'port': value['port'].currentText(), 'zone': value['zone'].currentText()}
            return 0, [data, ngfw_vlans, new_vlans]
        else:
            return 3, 'LBLUE|    Импорт настроек VLAN отменён пользователем.'

    def import_dhcp(self):
        dhcp_path = os.path.join(self.current_path, 'DHCP')
        json_file = os.path.join(dhcp_path, 'config_dhcp_subnets.json')
        err, data = self.read_json_file(json_file)
        if err:
            return err, data

        err, result = self.utm.get_interfaces_list()
        if err:
            return err, f'RED|    {result}'
        ngfw_ports = [x['name'] for x in result if x.get('ipv4', False) and x['kind'] in {'bridge', 'bond', 'adapter', 'vlan'}]
        ngfw_ports.insert(0, 'Undefined')

        dialog = CreateDhcpSubnetsWindow(self, ngfw_ports, data)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            return ngfw_ports, data
        else:
            return 3, 'LBLUE|    Импорт настроек DHCP отменён пользователем.'

    def read_json_file(self, json_file_path):
        """Читаем файл json с конфигурацией"""
        try:
            with open(json_file_path, 'r') as fh:
                data = json.load(fh)
        except FileNotFoundError as err:
            return 2, f'dGRAY|    Нет данных для импорта. Не найден файл {json_file_path} с конфигурацией.'
        except Exception as err:
            return 1, f'iRED|    {err}'
        if not data:
            return 3, f'dGRAY|    Нет данных для импорта. Файл {json_file_path} пуст.'
        return 0, data


class SelectConfigDirectoryWindow(QDialog):
    """Диалоговое окно выбора каталога для экспорта/импорта конфигурации"""
    def __init__(self, parent, mode):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Выбор каталога")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        list_dir = os.listdir(self.main_window.get_base_config_path())
        self.config_directory = QComboBox()
        self.config_directory.addItems(sorted(list_dir))
        if mode == 'export':
            self.setFixedHeight(160)
            self.config_directory.setEditable(True)
            text = "<b><font color='green'>Введите название каталога для экспорта конфигурации.<br> \
Каталог будет создан в текущей директории в каталоге data.<br>Или выберите из уже существующих.</font></b>"
        else:
            self.setFixedHeight(120)
            self.config_directory.setEditable(False)
            text = "<b><font color='green'>Выберите каталог с импортируемой конфигурацией.<br>"

        title = QLabel(text)
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        btn_enter = QPushButton("Ввод")
        btn_enter.setStyleSheet('color: steelblue; background: white;')
        btn_enter.setFixedWidth(80)
        btn_enter.clicked.connect(self._send_accept)
        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(btn_enter)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(self.config_directory)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
    def _send_accept(self):
        if self.config_directory.currentText():
            self.main_window.set_config_path(self.config_directory.currentText())
            err, msg = create_dir(self.main_window.get_config_path(), delete='no')
            if err:
                self.main_window.del_config_path()
                message_alert(self, msg, '')
            else:
                self.accept()


class LoginWindow(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Авторизация на UG NGFW")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        self.setFixedHeight(190)
        title = QLabel(f"<b><font color='green'>Введите учётнные данные<br>администратора NGFW</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        self.ngfw_ip = QLineEdit()
        self.ngfw_ip.setPlaceholderText("Введите IP-адрес...")

        self.login = QLineEdit()
        self.login.setPlaceholderText("Введите логин...")

        self.password = QLineEdit()
        self.password.setPlaceholderText("Введите пароль...")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        form = QFormLayout()
        form.addRow('IP-адрес:', self.ngfw_ip)
        form.addRow('Логин:', self.login)
        form.addRow('Пароль:', self.password)

        btn_login = QPushButton("Вход")
        btn_login.setStyleSheet('color: steelblue; background: white;')
        btn_login.setFixedWidth(80)
        btn_login.clicked.connect(self._send_accept)
        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(btn_login)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(form)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
    def _send_accept(self):
        if self.check_ip_is_valid(self.ngfw_ip.text()) and self.login.text() and self.password.text():
            self.utm = UtmXmlRpc(self.ngfw_ip.text(), self.login.text(), self.password.text())
            err, result = self.utm.connect()
            if err:
                message_alert(self, 'Не удалось подключиться с указанными параметрами!', result)
            else:
                self.accept()

    def check_ip_is_valid(self, ip_addr):
        """Проверяем введённый ip-адрес на валидность."""
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except ValueError:
            message_inform(self, 'Ошибка!', 'Вы ввели не корректный IP-адрес.')
            return False


class ColorLabel(QLabel):
    def __init__(self, text="Empty", color="darkred", name=None):
        super().__init__(text)
#        self.color = color
        if name:
            self.setObjectName(name)
        self.setStyleSheet(f"color: {color}")


class VlanWindow(QDialog):
    """Окно настройки VLAN-ов. Для установки порта и зоны каждого VLAN."""
    def __init__(self, parent, vlans=None, ports=None, zones=None):
        super().__init__(parent)
        self.setWindowTitle("Настройка VLANs")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
#        self.setFixedHeight(300)
        self.vlans = {item: {'port': '', 'zone': ''} for item in vlans}
        title = QLabel(f"<b><font color='green'>Настройка добавляемых интерфейсов VLAN</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        text1 = QLabel("Для импортируемых VLAN установите порт и зону.<br>Если порт не будет назначен, VLAN не будет импортирован.")

        grid_title_hbox = QHBoxLayout()
        grid_title_hbox.addStretch(1)
        grid_title_hbox.addWidget(ColorLabel(f'Vlan', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel(f'Порт', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel(f'Зона', 'blue'))
        grid_title_hbox.addStretch(10)

        grid_layout = QGridLayout()
        for i, vlan in enumerate(self.vlans.keys()):
            self.vlans[vlan]['port'] = QComboBox()
            self.vlans[vlan]['port'].addItems(ports)
            self.vlans[vlan]['zone'] = QComboBox()
            self.vlans[vlan]['zone'].addItems(zones)
            grid_layout.addWidget(QLabel(f'VLAN {vlan}'), i, 0)
            grid_layout.addWidget(self.vlans[vlan]['port'], i, 1)
            grid_layout.addWidget(self.vlans[vlan]['zone'], i, 2)

        widget = QWidget()
        widget.setLayout(grid_layout)
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)

        btn_ok = QPushButton("Ввод")
        btn_ok.setStyleSheet('color: forestgreen; background: white;')
        btn_ok.setFixedWidth(80)
        btn_ok.clicked.connect(self.accept)
        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_ok)
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(text1)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(grid_title_hbox)
        layout.addWidget(scroll)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)


class CreateDhcpSubnetsWindow(QDialog):
    """Окно настройки VLAN-ов. Для установки порта и зоны каждого VLAN."""
    def __init__(self, parent, ngfw_ports, new_subnets):
        super().__init__(parent)
        self.parent = parent
        self.ngfw_ports = ngfw_ports
        self.new_subnets = new_subnets
        self.dhcp = {}

        self.setWindowTitle("Настройка DHCP")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        title = QLabel(f"<b><font color='green'>Настройка DHCP subnets</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        text1 = QLabel("Для импортируемых DHCP subnets установите порт.<br>Если порт не будет назначен<br>subnet не будет импортирована.")

        grid_title_hbox = QHBoxLayout()
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel(f'DHCP subnet', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel(f'Порт', 'blue'))
        grid_title_hbox.addStretch(10)

        grid_layout = QGridLayout()
        for i, subnet in enumerate(self.new_subnets):
            if subnet['name'] == '':
                subnet['name'] = f'No Name subnet-{i}'
            self.dhcp[subnet['name']] = QComboBox()
            self.dhcp[subnet['name']].addItems(self.ngfw_ports)
            grid_layout.addWidget(QLabel(subnet['name']), i, 0)
            grid_layout.addWidget(self.dhcp[subnet['name']], i, 1)

        widget = QWidget()
        widget.setLayout(grid_layout)
        scroll = QScrollArea()
        scroll.setWidget(widget)
        scroll.setWidgetResizable(True)

        btn_ok = QPushButton("Ввод")
        btn_ok.setStyleSheet('color: forestgreen; background: white;')
        btn_ok.setFixedWidth(80)
        btn_ok.clicked.connect(self._send_accept)
        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_ok)
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(text1)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(grid_title_hbox)
        layout.addWidget(scroll)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)

    def _send_accept(self):
        for subnet in self.new_subnets:
            subnet['iface_id'] = self.dhcp[subnet['name']].currentText()
        self.accept()


class MainTree(QTreeWidget):
    itemSelected = pyqtSignal(dict)
    def __init__(self):
        super().__init__()
        self.setStyleSheet(cs.Style.MainTree)
        self.version = None     # Версия NGFW

        self.compliances = {
            "UserGate": "UserGate",
            "GeneralSettings": "Настройки",
            "DeviceManagement": "Управление устройсвом",
            "Administrators": "Администраторы",
            "Certificates": "Сертификаты",
            "UserCertificateProfiles": "Профили пользовательских сертификатов",
            "Network": "Сеть",
            "Zones": "Зоны",
            "Interfaces": "Интерфейсы",
            "Gateways": "Шлюзы",
            "DHCP": "DHCP",
            "DNS": "DNS",
            "VRF": "Виртуальные маршрутизаторы",
            "Routes": "Маршруты",
            "OSPF": "OSPF",
            "BGP": "BGP",
            "WCCP": "WCCP",
            "UsersAndDevices": "Пользователи и устройства",
            "Groups": "Группы",
            "Users": "Пользователи",
            "AuthServers": "Серверы аутентификации",
            "AuthProfiles": "Профили аутентификации",
            "CaptivePortal": "Captive-портал",
            "CaptiveProfiles": "Captive-профили",
            "TerminalServers": "Терминальные серверы",
            "MFAProfiles": "Профили MFA",
            "UserIDagent": "UserID агент",
            "BYODPolicies": "Политики BYOD",
            "NetworkPolicies": "Политики сети",
            "Firewall": "Межсетевой экран",
            "NATandRouting": "NAT и маршрутизация",
            "LoadBalancing": "Балансировка нагрузки",
            "TrafficShaping": "Пропускная способность",
            "SecurityPolicies": "Политики безопасности",
            "ContentFiltering": "Фильтрация контента",
            "SafeBrowsing": "Веб-безопасность",
            "TunnelInspection": "Инспектирование туннелей",
            "SSLInspection": "Инспектирование SSL",
            "SSHInspection": "Инспектирование SSH",
            "IntrusionPrevention": "СОВ",
            "Scenarios": "Сценарии",
            "MailSecurity": "Защита почтового трафика",
            "ICAPRules": "ICAP-правила",
            "ICAPServers": "ICAP-серверы",
            "DoSRules": "Правила защиты DoS",
            "DoSProfiles": "Профили DoS",
            "SCADARules": "Правила АСУ ТП",
            "GlobalPortal": "Глобальный портал",
            "WebPortal": "Веб-портал",
            "ReverseProxyRules": "Правила reverse-прокси",
            "ReverseProxyServers": "Серверы reverse-прокси",
            "WAF": "WAF",
            "WAFprofiles": "WAF-профили",
            "CustomWafLayers": "Персональные WAF-слои",
            "SystemWafRules": "Системные WAF-правила",
            "VPN": "VPN",
            "ServerRules": "Серверные правила",
            "ClientRules": "Клиентские правила",
            "VPNNetworks": "Сети VPN",
            "SecurityProfiles": "Профили безопасности VPN",
            "ServerSecurityProfiles": "Серверные профили безопасности",
            "ClientSecurityProfiles": "Клиентские профили безопасности",
            "Libraries": "Библиотеки",
            "Morphology": "Морфология",
            "Services": "Сервисы",
            "ServicesGroups": "Группы сервисов",
            "IPAddresses": "IP-адреса",
            "Useragents": "Useragent браузеров",
            "ContentTypes": "Типы контента",
            "URLLists": "Списки URL",
            "TimeSets": "Календари",
            "BandwidthPools": "Полосы пропускания",
            "SCADAProfiles": "Профили АСУ ТП",
            "ResponcePages": "Шаблоны страниц",
            "URLCategories": "Категории URL",
            "OverURLCategories": "Изменённые категории URL",
            "Applications": "Приложения",
            "ApplicationProfiles": "Профили приложений",
            "ApplicationGroups": "Группы приложений",
            "Emails": "Почтовые адреса",
            "Phones": "Номера телефонов",
            "IPDSSignatures": "Сигнатуры СОВ",
            "IDPSProfiles": "Профили СОВ",
            "NotificationProfiles": "Профили оповещений",
            "NetflowProfiles": "Профили netflow",
            "LLDPProfiles": "Профили LLDP",
            "SSLProfiles": "Профили SSL",
            "SSLForwardingProfiles": "Профили пересылки SSL",
            "HIDObjects": "HID объекты",
            "HIDProfiles": "HID профили",
            "BfdProfiles": "Профили BFD",
            "UserIdAgentSyslogFilters": "Syslog фильтры UserID агента",
            "Notifications": "Оповещения",
            "AlertRules": "Правила оповещений",
            "SNMP": "SNMP",
            "SNMPParameters": "Параметры SNMP",
            "SNMPSecurityProfiles": "Профили безопасности SNMP",
        }
        
        self.over_compliances = {v: k for k, v in self.compliances.items()}

        data = {
            "UserGate": ["Настройки", "Управление устройсвом", "Администраторы", "Сертификаты",
                         "Профили пользовательских сертификатов"],
            "Сеть": ["Зоны", "Интерфейсы", "Шлюзы", "DHCP", "DNS", "Виртуальные маршрутизаторы", "WCCP", "Маршруты", "OSPF", "BGP"],
            "Пользователи и устройства": [
                "Группы", "Пользователи", "Серверы аутентификации", "Профили аутентификации", "Captive-профили", "Captive-портал",
                "Терминальные серверы", "Профили MFA", "Политики BYOD", "UserID агент",
            ],
            "Политики сети": ["Межсетевой экран", "NAT и маршрутизация", "Балансировка нагрузки", "Пропускная способность"],
            "Политики безопасности": [
                "Фильтрация контента", "Веб-безопасность", "Инспектирование туннелей", "Инспектирование SSL",
                "Инспектирование SSH", "СОВ", "Правила АСУ ТП", "Сценарии", "Защита почтового трафика", "ICAP-серверы", "ICAP-правила",
                "Профили DoS", "Правила защиты DoS"
            ],
            "Глобальный портал": ["Веб-портал", "Серверы reverse-прокси", "Правила reverse-прокси"],
            "WAF": ["Персональные WAF-слои", "Системные WAF-правила", "WAF-профили"],
            "VPN": [
                "Профили безопасности VPN", "Серверные профили безопасности", "Клиентские профили безопасности", "Сети VPN",
                "Серверные правила", "Клиентские правила"
            ],
            "Библиотеки": [
                "Морфология", "Сервисы", "Группы сервисов", "IP-адреса", "Useragent браузеров", "Типы контента", "Списки URL",
                "Календари", "Полосы пропускания", "Профили АСУ ТП", "Шаблоны страниц", "Категории URL", "Изменённые категории URL",
                "Приложения", "Профили приложений", "Группы приложений", "Почтовые адреса", "Номера телефонов", "Сигнатуры СОВ",
                "Профили СОВ", "Профили оповещений", "Профили netflow", "Профили LLDP", "Профили SSL", "Профили пересылки SSL",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
            ],
            "Оповещения": ["Правила оповещений", "Профили безопасности SNMP", "SNMP", "Параметры SNMP"],
        }

        self.restricted_items = {
            "7.1": (
                "Маршруты", "OSPF", "BGP", "Системные WAF-правила",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"),
            "7.0": (
                "Профили пользовательских сертификатов",
                "Маршруты", "OSPF", "BGP",
                "Политики BYOD",
                "UserID агент",
                "Правила АСУ ТП",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Серверные профили безопасности", "Клиентские профили безопасности",
                "Профили АСУ ТП",
                "Профили приложений", "Приложения",
                "Сигнатуры СОВ",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
                "Параметры SNMP", "Профили безопасности SNMP",
            ),
            "6.1": (
                "Профили пользовательских сертификатов",
                "Маршруты", "OSPF", "BGP",
                "Инспектирование туннелей",
                "UserID агент",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Серверные профили безопасности", "Клиентские профили безопасности",
                "Группы сервисов", "Профили приложений", "Приложения",
                "Сигнатуры СОВ",
                "Профили LLDP",
                "Профили пересылки SSL",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
                "Параметры SNMP", "Профили безопасности SNMP",
            ),
            "5.0": (
                "Профили пользовательских сертификатов",
                "Виртуальные маршрутизаторы",
                "Терминальные серверы",
                "UserID агент",
                "Инспектирование туннелей",
                "Инспектирование SSH",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Серверные профили безопасности", "Клиентские профили безопасности",
                "Группы сервисов", "Профили приложений", "Приложения",
                "Сигнатуры СОВ", "Профили LLDP", "Профили SSL", "Профили пересылки SSL",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
                "Параметры SNMP", "Профили безопасности SNMP",
            ),
        }

        tree_head_font = QFont("Noto Sans", pointSize=10, weight=300)

        self.setHeaderHidden(True)
        self.setIndentation(10)

        items = []
        for key, values in data.items():
            item = QTreeWidgetItem([key])
#            item.setFlags(Qt.ItemFlag.ItemIsEnabled)
            item.setForeground(0, Qt.GlobalColor.darkBlue)
            item.setFont(0, tree_head_font)
            for value in values:
                child = QTreeWidgetItem([value])
                child.setDisabled(True)
                item.addChild(child)
            items.append(item)
        self.insertTopLevelItems(0, items)
        self.expandAll()
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Expanding)
        
        self.itemSelectionChanged.connect(self.select_item)

    def change_items_status(self):
        """Скрываем пункты меню отсутствующие в данной версии NGFW и активируем остальные."""
#        item = self.findItems(self.compliances[name], Qt.MatchFlag.MatchRecursive)[0]
        for item in self.findItems('*', Qt.MatchFlag.MatchWrap|Qt.MatchFlag.MatchWildcard|Qt.MatchFlag.MatchRecursive):
            if item.text(0) in self.restricted_items[self.version]:
                item.setHidden(True)
            else:
                item.setHidden(False)
                item.setDisabled(False)

    def select_item(self):
        """
        При выборе раздела в дереве, получаем выбранный раздел и его родителя.
        Отдаём словарь {'path': Раздел, 'points': [выбранный подпункт | все подпункты в разделе если выбран раздел]}.
        """
        if self.selectedItems():
            selected_item = self.selectedItems()[0]
            if selected_item.parent():
                parent = selected_item.parent().text(0)
                selected_path = {'path': self.over_compliances[parent], 'points': [self.over_compliances[selected_item.text(0)]]}
            else:
                item_childs = []
                for i in range(selected_item.childCount()):
                    child_text = selected_item.child(i).text(0)
                    try:
                        if child_text not in self.restricted_items[self.version]:
                            item_childs.append(self.over_compliances[child_text])
                    except KeyError:
                        pass
                selected_path = {'path': self.over_compliances[selected_item.text(0)], 'points': item_childs}
            self.itemSelected.emit(selected_path)

    def select_all_items(self):
        """
        Получить все разделы для данной версии.
        Отдаём список словарей [{'path': Раздел, 'points': [выбранный подпункт | все подпункты в разделе если выбран раздел]}, ...].
        """
        array = []
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            item_text = self.over_compliances[item.text(0)]
            if item_text in self.restricted_items[self.version]:
                continue
            item_childs = []
            for i in range(item.childCount()):
                child_text = item.child(i).text(0)
                try:
                    if child_text not in self.restricted_items[self.version]:
                        item_childs.append(self.over_compliances[child_text])
                except KeyError:
                    pass
            array.append({'path': item_text, 'points': item_childs})
        return array

#----------------------------------------------------------------------------------------------------------------------------
def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
