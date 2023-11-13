#
import os, json, ipaddress
from PyQt6.QtGui import QBrush, QColor, QFont, QPalette
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QWidget, QFrame, QDialog, QMessageBox,
                             QListWidget, QListWidgetItem, QPushButton, QLabel, QSpacerItem, QLineEdit, QComboBox, QScrollArea)
import convert_functions as cf
import import_functions as tf
from utm import UtmXmlRpc


class SelectAction(QWidget):
    """Класс для выбора режима: экспорт/импорт. Номер в стеке 0."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        text1 = "<b><font color='green' size='+2'>Конвертация конфигурации CheckPoint на UG NGFW v.7</font></b>"
        text2 = "Преобразование конфигурации CheckPoint в формат UserGate и сохранение её в файлах json в каталоге 'data_ug' \
в текущей директории. После экспорта вы можете просмотреть результат и изменить содержимое файлов в соответствии с вашими потребностями."
        text3 = "Импорт файлов конфигурации из каталога 'data_ug' на UG NGFW версии 7."
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
        self.btn_export.setStyleSheet('color: forestgreen; background: white;')
        self.btn_export.setFixedWidth(200)
        self.btn_export.clicked.connect(self.run_next_page)
        self.btn_import = QPushButton("Импорт конфигурации")
        self.btn_import.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import.setFixedWidth(200)
        self.btn_import.setEnabled(False)
        self.btn_import.clicked.connect(self.set_import_page)
        btn_exit = QPushButton("Выход")
        btn_exit.setStyleSheet('color: darkred;')
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

    def run_next_page(self):
        """
        Преобразуем файлы конфигурации CheckPoint в читабельный вид и пишем их в каталог data_json
        и переходим на страницу выбора SecureGateway.
        """
        if os.path.isdir(self.parent.cp_path):
            if os.path.exists(os.path.join(self.parent.cp_path, 'index.json')):
                if create_dir(self, self.parent.cp_data_json):
                    files = os.listdir(self.parent.cp_path)
                    for file_name in files:
                        if file_name.endswith('.json'):
                            try:
                                with open(os.path.join(self.parent.cp_path, file_name), 'r') as fh:
                                    data = json.load(fh)
                                with open(os.path.join(self.parent.cp_data_json, file_name), 'w') as fh:
                                    json.dump(data, fh, indent=4, ensure_ascii=False)
                            except json.decoder.JSONDecodeError as err:
                                message_alert(self, err, f"Ошибка парсинга файла конфигурации\n{file_name}")
                    self.parent.stacklayout.setCurrentIndex(1)
            else:
                QMessageBox.warning(self, "Ошибка!", "Не найдена конфигурация Check Point в каталоге data_cp.", buttons=QMessageBox.StandardButton.Cancel)
        else:
            QMessageBox.warning(self, "Ошибка!", "Не найден каталог с конфигурацией Check Point.", buttons=QMessageBox.StandardButton.Cancel)

    def set_import_page(self):
        self.parent.stacklayout.setCurrentIndex(2)


class SelectSecureGateway(QWidget):
    """Класс для выбора SecureGateway для конвертации. Номер в стеке 1."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent

        title = QLabel("<b><font color='green' size='+2'>Выбор Gateways policy package</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        label = QLabel("Выберите SecureGateway для конвертации.")
        label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.sg_list = QListWidget()

        btn1 = QPushButton("Назад")
        btn1.setStyleSheet('color: steelblue; background: white;')
        btn1.setFixedWidth(100)
        btn1.clicked.connect(self.run_page_0)
        btn2 = QPushButton("Далее")
        btn2.setStyleSheet('color: forestgreen; background: white;')
        btn2.setFixedWidth(100)
        btn2.clicked.connect(self.run_next_page)
        btn_exit = QPushButton("Выход")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(100)
        btn_exit.clicked.connect(self.parent.close)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(btn1)
        btn_hbox.addWidget(btn2)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        vbox = QVBoxLayout()
        vbox.addWidget(title)
        vbox.addSpacerItem(QSpacerItem(5, 20))
        vbox.addWidget(label)
        vbox.addWidget(self.sg_list)
        vbox.addSpacerItem(QSpacerItem(5, 10))
        vbox.addLayout(btn_hbox)
        self.setLayout(vbox)

        self.parent.stacklayout.currentChanged.connect(self.add_sglist_items)
        self.sg_list.currentTextChanged.connect(self.select_secure_gateway)

    def add_sglist_items(self, e):
        """
        При открытии этой вкладки читаем index.json и заполняем список для выбора SecureGateway
        При переходе на предыдущую вкладку, очищаем список.
        """
        if e == 1:
            with open(os.path.join(self.parent.cp_path, 'index.json'), 'r') as fh:
                data = json.load(fh)
            for item in data['policyPackages']:
                self.sg_list.addItem(item['packageName'])
                self.parent.sg_index[item['packageName']] = item
        elif e == 0:
            self.sg_list.clear()

    def select_secure_gateway(self, item_text):
        self.parent.sg_name = item_text

    def run_next_page(self):
        """Запускаем диалоговое окно преобразования конфигурации в формат UG NGFW."""
        if self.parent.sg_name:
            dialog = ExportList(self.parent)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                pass
            else:
                message_inform(self, "Внимание!", "Конвертация прервана пользователем!")
        else:
            message_inform(self, "Внимание!", "Вы не выбрали SecureGateway для конвертации.")

    def run_page_0(self):
        self.parent.stacklayout.setCurrentIndex(0)


class SelectImportMode(QWidget):
    """Класс для выбора раздела конфигурации для импорта. Номер в стеке 2."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.selected_point = ""
        self.utm = None
        self.thread = None
        self.func = {
            '1. Импорт часового пояса': tf.ImportUi,
            '2. Импорт домена captive-портала': tf.ImportModules,
            '3. Импорт серверов NTP': tf.ImportNtpSettings,
            '4. Импорт серверов DNS': tf.ImportDnsServers,
            '5. Импорт Зон': tf.ImportZones,
            '6. Импорт интерфейсов VLAN': None,
            '7. Импорт шлюзов': tf.ImportGateways,
            '8. Импорт статических маршрутов': tf.ImportStaticRoutes,
            '9. Импорт списка сервисов': tf.ImportServices,
            '10. Импорт групп сервисов': tf.ImportServicesGroups,
            '11. Импорт списков IP-адресов': tf.ImportIpLists,
            '12. Импорт списков URL': tf.ImportUrlLists,
            '13. Импорт групп URL категорий': tf.ImportUrlCategories,
            '14. Импорт групп приложений': tf.ImportApplicationGroups,
            '15. Импорт правил МЭ': tf.ImportFirewallRules,
            '16. Импорт правил КФ': tf.ImportContentRules,
        }

        title = QLabel("<b><font color='green' size='+2'>Выбор раздела конфигурации для импорта</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        label = QLabel('Выберите раздела конфигурации для импорта или нажмите кнопку "Импортировать всё".')
        label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.sg_list = QListWidget()
        self.sg_list.setFixedWidth(210)
        self.log_list = QListWidget()

        self.btn1 = QPushButton("Назад")
        self.btn1.setFixedWidth(100)
        self.btn1.clicked.connect(self.run_page_0)
        self.btn2 = QPushButton("Импорт выбранного раздела")
        self.btn2.setFixedWidth(190)
        self.btn2.clicked.connect(self.import_selected_point)
#        self.btn3 = QPushButton("Импортировать всё")
#        self.btn3.setFixedWidth(140)
#        self.btn3.clicked.connect(self.import_all)
        self.btn4 = QPushButton("Сохранить лог")
        self.btn4.setFixedWidth(100)
        self.btn4.clicked.connect(self._save_logs)

        lists_hbox = QHBoxLayout()
        lists_hbox.addWidget(self.sg_list)
        lists_hbox.addWidget(self.log_list)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(self.btn1)
        btn_hbox.addStretch()
        btn_hbox.addWidget(self.btn2)
#        btn_hbox.addWidget(self.btn3)
        btn_hbox.addStretch()
        btn_hbox.addWidget(self.btn4)

        vbox = QVBoxLayout()
        vbox.addWidget(title)
        vbox.addWidget(label)
        vbox.addLayout(lists_hbox)
        vbox.addSpacerItem(QSpacerItem(1, 3))
        vbox.addLayout(btn_hbox)
        self.setLayout(vbox)

        self.parent.stacklayout.currentChanged.connect(self.add_sglist_items)
        self.sg_list.currentTextChanged.connect(self.select_item)
        self.disable_buttons()

    def disable_buttons(self):
        self.btn1.setStyleSheet('color: gray; background: gainsboro;')
        self.btn1.setEnabled(False)
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
#        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
#        self.btn3.setEnabled(False)
        self.btn4.setStyleSheet('color: gray; background: gainsboro;')
        self.btn4.setEnabled(False)

    def enable_buttons(self):
        self.btn1.setStyleSheet('color: steelblue; background: white;')
        self.btn1.setEnabled(True)
        self.btn2.setStyleSheet('color: forestgreen; background: white;')
        self.btn2.setEnabled(True)
#        self.btn3.setStyleSheet('color: darkred; background: white;')
#        self.btn3.setEnabled(True)
        self.btn4.setStyleSheet('color: steelblue; background: white;')
        self.btn4.setEnabled(True)

    def add_sglist_items(self, e):
        """
        При открытии этой вкладки заполняем список разделами для импорта.
        При переходе на предыдущую вкладку, очищаем список и лог, деактивируем все кнопки.
        """
        if e == 2:
            self.parent.resize(900, 500)
            for key in self.func.keys():
                self.sg_list.addItem(key)
            self.sg_list.setCurrentRow(0)
            self.get_auth()

    def select_item(self, item_text):
        """Выбрали раздел для импорта."""
        self.selected_point = item_text

    def get_auth(self):
        """Вызываем окно авторизации, если авторизация не прошла, возвращаемся в начальный экран."""
        if not self.utm:
            dialog = LoginWindow(parent=self)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.utm = dialog.utm
                self.add_item_log(f"Импорт конфигурации на UG NGFW, ip: {self.utm.server_ip}, NGFW v.{self.utm.version}")
                self.add_item_log(f"{'-'*120}")
                if self.utm.version_hight < 7:
                    self.add_item_log("Импорт возможен только на NGFW версии 7 и выше!", 1)
                    self.btn1.setStyleSheet('color: steelblue; background: white;')
                    self.btn1.setEnabled(True)
                else:
                    self.enable_buttons()
            else:
                self.run_page_0()

    def import_selected_point(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт выбранного раздела конфигурации.
        """
        match self.utm.ping_session()[0]:
            case 1:
                self.utm.connect()
            case 2:
                self.utm.login()
        if self.selected_point:
            self.disable_buttons()
            if self.thread is None:
                point_number, point_name = self.selected_point.split('.')
                if point_number ==  '6':
                    cv = CreateVlans(self, self.utm)
                    self.thread = tf.ImportVlans(self.utm, cv.utm_vlans, cv.utm_zones, cv.new_vlans, cv.ifaces)
                else:
                    self.thread = self.func[self.selected_point](self.utm)
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                message_inform(self, 'Ошибка', f'Произошла ошибка при импорте! {key} {self.thread}')
        else:
            message_inform(self, "Внимание!", "Вы не выбрали раздел для импорта.")

    def on_step_changed(self, msg):
        err, message = msg.split('|')
        self.add_item_log(f'    {message}' if int(err) else message, color=int(err))
        self.log_list.scrollToBottom()
        if int(err) in (5, 6):
            _, title = self.selected_point.split('.')
            message_inform(self, title, message)

    def on_finished(self):
        self.thread = None
        self.enable_buttons()

    def import_all(self):
        msg = "Импортировать всю конфигурацию?\n\nХорошей практикой является импорт по шагам с последующей проверкой импортируемых разделов."
        result = message_question(self, "Импортировать всё", msg)

        if result == 'yes':
            self.disable_buttons()
            cv = CreateVlans(self, self.utm)
            if self.thread is None:
                self.thread = tf.ImportAll(self.utm, cv.utm_vlans, cv.utm_zones, cv.new_vlans, cv.ifaces)
                self.thread.stepChanged.connect(self.on_batch_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                message_inform(self, 'Ошибка', 'Произошла ошибка при запуске процесса импорта!')

    def on_batch_changed(self, msg):
        err, message = msg.split('|')
        if int(err) in (5, 6):
            self.log_list.addItem('')
            self.add_item_log(message, int(err))
            self.log_list.addItem('')
            message_inform(self, 'Импорт', message)
        else:
            self.add_item_log(f'    {message}' if int(err) else message, int(err))

        self.log_list.scrollToBottom()

    def _save_logs(self):
        """Сохраняем лог импорта из log_list в файл "import.log" в текущей директории"""
        list_items = [self.log_list.item(row).text() for row in range(self.log_list.count())]
        with open('import.log', 'w') as fh:
            print(*list_items, sep='\n', file=fh)
            fh.write('\n')
        message_inform(self, 'Сохранение лога импорта', 'Лог импорта конфигурации на UG NGFW сохранён в файл "import.log" в текущей директории.')

    def run_page_0(self):
        """Возвращаемся на стартовое окно"""
        if self.utm:
            self.utm.logout()
        self.utm = None
        self.sg_list.clear()
        self.log_list.clear()
        self.parent.stacklayout.setCurrentIndex(0)

    def add_item_log(self, message, color=0):
        """
        Добавляем запись лога в log_list.
        Цвета: [black, darkred, black, dodgerblue, darkorange, darkgreen, darkorange]
        """
        colors = ['#000000', '#8b0000', '#000000', '#1e90ff', '#ff8c00', '#006400', '#ff8c00']
        i = QListWidgetItem(message)
        i.setForeground(QColor(colors[color]))
        self.log_list.addItem(i)


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
                message_alert(self, result, 'Не удалось подключиться с указанными параметрами!')
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

class CreateVlans:
    """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
    def __init__(self, parent, utm):
        self.utm = utm
        self.parent = parent
        self.utm_vlans = {}
        self.utm_zones = {}
        self.new_vlans = None
        self.ifaces = None

        parent.add_item_log('Импорт VLAN в раздел "Сеть/Интерфейсы"')
        json_file = "data_ug/Network/Interfaces/config_interfaces.json"
        err, self.ifaces = tf.read_json_file(json_file, '1|Ошибка импорта VLAN!', '1|Нет VLAN для импорта.')
        if err:
            self.new_vlans = self.ifaces
            return

        management_port = ''
        interfaces_list = []

        _, result = self.utm.get_zones_list()
        self.utm_zones = {x['name']: x['id'] for x in result}

        # Составляем список легитимных интерфейсов (interfaces_list).
        err, result = self.utm.get_interfaces_list()
        if err:
            self.new_vlans = f'1|{result}'
            return
        for item in result:
            if item['kind'] == 'vlan':
                self.utm_vlans[item['vlan_id']] = item['name']
            for ip in item['ipv4']:
                if ip.startswith(self.utm.server_ip):
                    management_port = item["name"]
#                    message = f'Интерфейс {item["name"]} - {self.utm.server_ip} используется для текущей сессии.\nОн не будет использоваться для создания интерфейсов VLAN.'
                    parent.add_item_log(f'    Интерфейс {item["name"]} - {self.utm.server_ip} используется для текущей сессии.')
                    parent.add_item_log('    Он не будет использоваться для создания интерфейсов VLAN.')
            if item['kind'] not in ('bridge', 'bond', 'adapter') or item['master']:
                continue
            if item["name"] == management_port:
                continue
            interfaces_list.append(item['name'])

        vlans = sorted([item['vlan_id'] for item in self.ifaces])
        zones = list(self.utm_zones.keys())
        zones.insert(0, "Undefined")
        interfaces_list.insert(0, "Undefined")
        
        dialog = VlanWindow(parent, vlans=vlans, ports=interfaces_list, zones=zones)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.new_vlans = {}
            for key, value in dialog.vlans.items():
                self.new_vlans[key] = {'port': value['port'].currentText(), 'zone': value['zone'].currentText()}
            

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


class ExportList(QDialog):
    """Класс для конвертации конфигурации в формат UG NGFW"""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.thread = None
        self.setWindowTitle("Преобразование конфигурации")
        self.resize(800, 700)
        title = QLabel(f"<b><font color='green' size='+2'>Gateways policy package - {self.parent.sg_name}</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        btn_start = QPushButton("Конвертировать")
        btn_start.setStyleSheet('color: steelblue; background: white;')
        btn_start.clicked.connect(self._convert_config)

        self.log_list = QListWidget()
        self.btn2 = QPushButton("Сохранить лог")
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn2.setFixedWidth(100)
        self.btn2.clicked.connect(self._save_logs)
        btn_exit = QPushButton("Закрыть")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(100)
        btn_exit.clicked.connect(self.accept)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(self.btn2)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        layout = QVBoxLayout()
        layout.addWidget(title)
        layout.addWidget(btn_start)
        layout.addWidget(self.log_list)
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
    def _convert_config(self):
        config_cp = []
        try:
            with open(os.path.join(self.parent.cp_path, 'config_cp.txt'), 'r') as fh:
                for line in fh:
                    x = line.strip('\n').split()
                    if x and x[0] in {'set', 'add'}:
                        config_cp.append(x[1:])
        except FileNotFoundError as err:
            message_alert(self, err, 'Не найден файл "config_cp.txt" c конфигурацией Check Point.')
            self.reject()
            return

        objects_file = self.parent.sg_index[self.parent.sg_name]['objects']['htmlObjectsFileName'].replace('html', 'json')
        try:
            with open(os.path.join(self.parent.cp_path, objects_file), 'r') as fh:
                data = json.load(fh)
            self.objects = {x['uid']: x for x in data}
        except FileNotFoundError as err:
            message_alert(self, err, f'Не найден файл конфигурации Check Point "{objects_file}"!')
            self.reject()
            return

        if self.thread is None:
            self.thread = cf.ConvertAll(config_cp, self.objects, self.parent)
            self.thread.stepChanged.connect(self.on_batch_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            message_inform(self, 'Ошибка', 'Произошла ошибка при запуске процесса конвертации!')

    def on_batch_changed(self, msg):
        try:
            error, message = msg.split('|')
        except ValueError as err:
            message_alert(self, err, msg)
        else:
            if int(error) == 8:
                self.add_item_list(message, color=5)
                message_inform(self, 'Конвертация', message)
            elif int(error) == 9:
                self.add_item_list(message, color=4)
                message_inform(self, 'Конвертация', message)
            else:
                self.add_item_list(f'    {message}' if int(error) else message, color=int(error))
            self.log_list.scrollToBottom()

    def on_finished(self):
        self.thread = None
        self.btn2.setStyleSheet('color: forestgreen; background: white;')
        self.btn2.setEnabled(True)
        # удалить потом
        with open("objects.json", "w") as fh:
            json.dump(self.objects, fh, indent=4, ensure_ascii=False)

    def _save_logs(self):
        list_items = [f"Преобразование конфигурации Gateways policy package - {self.parent.sg_name}",
                       "-------------------------------------------------------------------------------------\n"]
        list_items.extend([self.log_list.item(row).text() for row in range(self.log_list.count())])
        with open('export.log', 'w') as fh:
            print(*list_items, sep='\n', file=fh)
            fh.write('\n')
        message_inform(self, 'Сохранение лога экспорта', 'Лог экспорта конфигурации CheckPoint в формат UG NGFW\nсохранён в файл "export.log" в текущей директории.')
        self.parent.stacklayout.setCurrentIndex(0)

    def add_item_list(self, message, color=0):
        """
        Добавляем запись лога в log_list.
        Цвета: [darkblue, darkred, black, dimgray, darkorange, darkgreen, dodgerblue]
        """
        colors = ['#00008b', '#8b0000', '#000000', '#696969', '#ff8c00', '#006400', '#1e90ff']
        i = QListWidgetItem(message)
        i.setForeground(QColor(colors[color]))
        self.log_list.addItem(i)

#-------------------------------------- Служебные функции --------------------------------------------------
def create_dir(self, folder):
    if not os.path.isdir(folder):
        try:
            os.makedirs(folder)
        except Exception as err:
            message_alert(self, err, f"Ошибка создания каталога:\n{folder}")
            return False
        else:
            return True
    else:
        return True

def message_inform(self, title, message):
    """Общее информационное окно. Принимает родителя, заголовок и текст сообщения"""
    QMessageBox.information(self, title, message, defaultButton=QMessageBox.StandardButton.Ok)

def message_question(self, title, message):
    """Общее окно подтверждения. Принимает родителя, заголовок и текст сообщения"""
    result = QMessageBox.question(self, title, message, defaultButton=QMessageBox.StandardButton.No)
    return 'yes' if result == QMessageBox.StandardButton.Yes else 'no'

def message_alert(self, err, message):
    """Алерт при любых ошибках"""
    QMessageBox.critical(self, "Ошибка!", f"{message}\n\n{err}", buttons=QMessageBox.StandardButton.Cancel)
