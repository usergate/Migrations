#!/usr/bin/python3
#
# Версия 1.11    25.03.2025
#-----------------------------------------------------------------------------------------------------------------------------

import os, json, ipaddress
from datetime import datetime as dt
from PyQt6.QtGui import QBrush, QColor, QFont, QPalette
from PyQt6.QtCore import Qt, QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QWidget, QFrame, QDialog, QMessageBox,
                             QListWidget, QListWidgetItem, QPushButton, QLabel, QSpacerItem, QLineEdit, QComboBox, QScrollArea,
                             QTreeWidget, QTreeWidgetItem, QSizePolicy, QSplitter, QInputDialog)
import config_style as cs
import common_func as func
import export_blue_coat_config as bluecoat
import export_cisco_asa_config as asa
import export_cisco_fpr_config as fpr
import export_fortigate_config as fg
import export_huawei_config as huawei
import export_checkpoint_config as cp
import export_mikrotik_config as mikrotik
import import_functions as tf
import import_to_mc
import get_temporary_data as gtd
from get_mc_temporary_data import ImportMcTemporaryData
from utm import UtmXmlRpc
from mclib import McXmlRpc


class SelectAction(QWidget):
    """Класс для выбора режима: экспорт/импорт. Номер в стеке 0."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        text1 = "<b><font color='green' size='+2'>Перенос конфигурации сторонних вендоров<br>на UserGate NGFW, DCFW и Management Center</font></b>"
        text2 = "Экспорт конфигурации из конфигурационных файлов <b>Blue Coat</b>, <b>Cisco ASA</b>, <b>Cisco FPR</b>, <b>Check Point</b>, \
<b>Fortigate</b>, <b>Huawei</b>, <b>MikroTik</b>  и сохранение её в формате UserGate в каталоге <b>data_usergate</b> текущей директории. \
После экспорта вы можете просмотреть результат и изменить содержимое файлов в соответствии с вашими потребностями."
        text3 = "Импорт файлов конфигурации из каталога <b>data_usergate</b> на <b>UserGate NGFW</b> (версий <b>5, 6, 7</b>) и <b>DCFW</b>."
        text4 = "Импорт файлов конфигурации из каталога <b>data_usergate</b> в группу шаблонов NGFW <b>UserGate Management Center</b> версии <b>7</b>."
        label1 = QLabel(text1)
        label1.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        label2 = QLabel(text2)
        label2.setWordWrap(True)
        label3 = QLabel(text3)
        label3.setWordWrap(True)
        label4 = QLabel(text4)
        label4.setWordWrap(True)
        
        btn_font = QFont("SansSerif", pointSize=9, weight=600)

        self.btn_export = QPushButton("Экспорт конфигурации")
        self.btn_export.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_export.setFont(btn_font)
        self.btn_export.setFixedWidth(280)
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.set_export_page)

        self.btn_import = QPushButton("Импорт конфигурации на UG NGFW|DCFW")
        self.btn_import.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import.setFont(btn_font)
        self.btn_import.setFixedWidth(280)
        self.btn_import.setEnabled(False)
        self.btn_import.clicked.connect(self.set_import_page)

        self.btn_import_mc = QPushButton("Импорт конфигурации в группу шаблонов\nUG Мanagement Center")
        self.btn_import_mc.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import_mc.setFont(btn_font)
        self.btn_import_mc.setFixedWidth(280)
        self.btn_import_mc.setEnabled(False)
        self.btn_import_mc.clicked.connect(self.set_import_mc_page)

        layout = QGridLayout()
        layout.addWidget(self.btn_export, 0, 0, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(label2, 0, 1)
        layout.addWidget(self.btn_import, 1, 0)
        layout.addWidget(label3, 1, 1)
        layout.addWidget(self.btn_import_mc, 2, 0)
        layout.addWidget(label4, 2, 1)
        layout.setHorizontalSpacing(20)
        layout.setVerticalSpacing(20)
        layout.setColumnStretch(1, 10)

        btn_exit = QPushButton("Выход")
        btn_exit.setStyleSheet('color: darkred; background: white;')
        btn_exit.setFixedWidth(200)
        btn_exit.clicked.connect(self.parent.close)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)

        btn_vbox = QVBoxLayout()
        btn_vbox.addSpacerItem(QSpacerItem(5, 10))
        btn_vbox.addWidget(btn_exit)
        btn_vbox.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        vbox = QVBoxLayout()
        vbox.addWidget(label1)
        vbox.addSpacerItem(QSpacerItem(5, 10))
        vbox.addLayout(layout)
        vbox.addSpacerItem(QSpacerItem(5, 10))
        vbox.addWidget(line)
        vbox.addLayout(btn_vbox)
        self.setLayout(vbox)

        self.parent.stacklayout.currentChanged.connect(self.resize_window)

    def resize_window(self, e):
        if e == 0:
            self.parent.resize(610, 360)

    def set_export_page(self):
        """Переходим на страницу экспорта конфигурации. Номер в стеке 1."""
        self.parent.stacklayout.setCurrentIndex(1)

    def set_import_page(self):
        """Переходим на страницу импорта конфигурации на NGFW. Номер в стеке 2."""
        self.parent.stacklayout.setCurrentIndex(2)

    def set_import_mc_page(self):
        """Переходим на страницу импорта конфигурации в шаблон МС. Номер в стеке 3."""
        self.parent.stacklayout.setCurrentIndex(3)

    def enable_buttons(self):
        self.btn_export.setStyleSheet('color: forestgreen; background: white;')
        self.btn_export.setEnabled(True)
        self.btn_import.setStyleSheet('color: steelblue; background: white;')
        self.btn_import.setEnabled(True)
        self.btn_import_mc.setStyleSheet('color: steelblue; background: white;')
        self.btn_import_mc.setEnabled(True)


class SelectMode(QWidget):
    """Класс для выбора раздела конфигурации для импорта."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.selected_points = []
        self.current_ug_path = None
        self.utm = None
        self.product = 'NGFW'
        self.thread = None
        self.log_list = QListWidget()
        self.tmp_list = []
        
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
        self.btn2 = QPushButton()
        self.btn2.setFixedWidth(230)
        self.btn3 = QPushButton()
        self.btn3.setFixedWidth(230)
        self.btn4 = QPushButton("Сохранить лог")
        self.btn4.setFixedWidth(130)

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

    def get_auth(self, mod='fw'):
        """Вызываем окно авторизации, если авторизация не прошла, возвращаемся в начальный экран."""
        if self.utm:
            self.utm.logout()
            self.utm = None
        dialog = LoginWindow(parent=self, mode=mod)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.utm = dialog.utm
            self.product = 'NGFW' if self.utm.product == 'utm' else self.utm.product.upper()
            self.label_node_name.setText(f'  {self.utm.node_name}')
            self.label_version.setText(f'Версия {self.product}: {self.utm.version}')
            return True
        else:
            return False

    def get_selected_item(self, selected_item):
        """
        Получаем выбранный пункт меню и устанавливаем путь к разделу конфигурации.
        Запоминаем выбранный пункт/пункты раздела в массиве self.selected_points.
        """
        self.current_ug_path = os.path.join(self.parent.get_ug_config_path(), selected_item['path'])
        self.selected_points = selected_item['points']

    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        today = dt.now()
        path_logfile = os.path.join(self.parent.get_ug_config_path(), f'{today:%Y-%m-%d_%M:%S}-{log_file}')
        list_items = [self.log_list.item(row).text() for row in range(self.log_list.count())]
        with open(path_logfile, 'w') as fh:
            print(*list_items, sep='\n', file=fh)
            fh.write('\n')
        func.message_inform(self, 'Сохранение лога', f'Лог сохранён в файл "{path_logfile}".')

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
        self.current_ug_path = None
        self.tree.version = None
        if os.path.isfile('temporary_data.bin'):
            os.remove('temporary_data.bin')
        self.parent.stacklayout.setCurrentIndex(0)

    def add_item_log(self, message, color='BLACK'):
        """Добавляем запись лога в log_list."""
        i = QListWidgetItem(message)
        i.setForeground(QColor(cs.color.get(color, 'RED')))
        self.log_list.addItem(i)

    def on_step_changed(self, msg):
        color, _, message = msg.partition('|')
        if color == 'RED':
            self.add_item_log(message, color=color)
            self.log_list.scrollToBottom()
        elif color in ('BLACK', 'NOTE'):
            self.tmp_list.append((message, color))
        else:
            if self.tmp_list:
                for x in self.tmp_list:
                    self.add_item_log(x[0], color=x[1])
                self.tmp_list.clear()
            self.add_item_log(message, color=color)
            self.log_list.scrollToBottom()
        if color in ('iORANGE', 'iGREEN', 'iRED'):
            func.message_inform(self, 'Внимание!', message)

    def on_finished(self):
        self.tmp_list.clear()
        self.thread = None
        self.enable_buttons()


class SelectExportMode(QWidget):
    """
    Класс для конвертации выбранного вендора. Номер в стеке 1.
    1. Выбираем вендора, выбираем/создаём каталог с нужной конфигурацией стороннего вендора для экспорта.
    2. Выбираем/создаём каталог куда будем писать конвертированную в формат UG NGFW конфигурацию.
    3. Конвертируем конфигурацию в формат UG NGFW.
    """
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.selected_point = ''
        self.vendor_base_path = ''
        self.vendor_current_path = ''
        self.thread = None
        self.log_list = QListWidget()
        self.tmp_list = []
        
        self.title = QLabel("<b><font color='green' size='+2'>Конвертация сторонней конфигурации в формат UserGate</font></b>")
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

        list_item_font = QFont("Serif", pointSize=14, weight=600)
        vendors = ['Blue Coat', 'Cisco ASA', 'Cisco FPR', 'Check Point', 'Fortigate', 'Huawei', 'MikroTik']
        self.vendor_list = QListWidget()
        self.vendor_list.setMaximumWidth(150)
        for vendor in vendors:
            new_item = QListWidgetItem()
            new_item.setText(vendor)
            new_item.setForeground(Qt.GlobalColor.darkBlue)
            new_item.setFont(list_item_font)
            self.vendor_list.addItem(new_item)
        self.vendor_list.currentTextChanged.connect(self.get_selected_item)

        splitter = QSplitter()
        splitter.addWidget(self.vendor_list)
        splitter.addWidget(self.log_list)
        hbox_splitter = QHBoxLayout()
        hbox_splitter.addWidget(splitter)

        self.btn1 = QPushButton("Назад")
        self.btn1.setFixedWidth(100)
        self.btn1.clicked.connect(self.run_page_0)
        self.btn2 = QPushButton('Экспорт')
        self.btn2.setFixedWidth(190)
        self.btn2.clicked.connect(self.export_selected_vendor)
        self.btn3 = QPushButton("Сохранить лог")
        self.btn3.setFixedWidth(100)
        self.btn3.clicked.connect(lambda: self._save_logs('export.log'))

        hbox_btn = QHBoxLayout()
        hbox_btn.addWidget(self.btn1)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn2)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn3)
        
        vbox = QVBoxLayout()
        vbox.addWidget(self.title)
        vbox.addWidget(frame_nodeinfo)
        vbox.addLayout(hbox_splitter)
        vbox.addSpacerItem(QSpacerItem(1, 3))
        vbox.addLayout(hbox_btn)
        self.setLayout(vbox)

        self.disable_buttons()
        self.parent.stacklayout.currentChanged.connect(self.init_export_widget)

    def disable_buttons(self):
        self.btn1.setStyleSheet('color: gray; background: gainsboro;')
        self.btn1.setEnabled(False)
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
        self.btn3.setEnabled(False)

    def enable_buttons(self):
        self.btn1.setStyleSheet('color: steelblue; background: white;')
        self.btn1.setEnabled(True)
        self.btn2.setStyleSheet('color: forestgreen; background: white;')
        self.btn2.setEnabled(True)

    def init_export_widget(self, e):
        """
        При открытии этой вкладки меняем размер окна и активируем кнопки.
        """
        if e == 1:
            self.parent.resize(900, 500)
            self.enable_buttons()
            self.vendor_list.setCurrentRow(1)
            self.vendor_list.setCurrentRow(0)

    def get_selected_item(self, selected_item):
        """
        Получаем выбранный пункт меню и устанавливаем путь к базовому разделу конфигураций вендора.
        """
        self.selected_point = selected_item
        self.vendor_base_path = self.parent.get_vendor_base_path(selected_item)

    def export_selected_vendor(self):
        """
        Проверяем что выбран вендор. Если выбран, запускаем экспорт выбранного раздела конфигурации.
        """
        if self.vendor_base_path:
            dialog = SelectConfigDirectories(self.parent, self.vendor_base_path, self.selected_point)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.vendor_current_path = dialog.vendor_current_path
                self.label_node_name.setText(f'  IN:  {self.vendor_current_path}')
                self.label_version.setText(f'{self.selected_point}')
                self.label_config_directory.setText(f'OUT:  {self.parent.get_ug_config_path()}   ')
            else:
                return

            self.disable_buttons()
            if self.thread is None:
                match self.selected_point:
                    case 'Blue Coat':
                        self.thread = bluecoat.ConvertBlueCoatConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Cisco ASA':
                        self.thread = asa.ConvertCiscoASAConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Cisco FPR':
                        self.thread = fpr.ConvertCiscoFPRConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Check Point':
                        err, msg = self._create_checkpoint_datajson()
                        if err:
                            self.add_item_log(msg, color='RED')
                            self.enable_buttons()
                            self.btn3.setStyleSheet('color: darkred; background: white;')
                            self.btn3.setEnabled(True)
                            return
                        self.label_version.setText(f'{self.selected_point} - {msg}')
                        self.thread = cp.ConvertCheckPointConfig(self.vendor_current_path, self.parent.get_ug_config_path(), msg)
                    case 'Fortigate':
                        self.thread = fg.ConvertFortigateConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'Huawei':
                        self.thread = huawei.ConvertHuaweiConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                    case 'MikroTik':
                        self.thread = mikrotik.ConvertMikrotikConfig(self.vendor_current_path, self.parent.get_ug_config_path())
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {key} {self.thread}')
        else:
            func.message_inform(self, "Внимание!", "Вы не выбрали раздел для экспорта.")

    def _create_checkpoint_datajson(self):
        """
        Преобразуем файлы конфигурации CheckPoint в читабельный вид и пишем их в каталог data_json
        и переходим на страницу выбора SecureGateway.
        """
        if os.path.exists(os.path.join(self.vendor_current_path, 'index.json')):
            if os.path.exists(os.path.join(self.vendor_current_path, 'config_cp.txt')):
                cp_data_json = os.path.join(self.vendor_current_path, 'data_json')
                err, msg = func.create_dir(cp_data_json)
                if err:
                    return err, data
                files = os.listdir(self.vendor_current_path)
                for file_name in files:
                    if file_name.endswith('.json'):
                        try:
                            with open(os.path.join(self.vendor_current_path, file_name), 'r') as fh:
                                data = json.load(fh)
                            with open(os.path.join(cp_data_json, file_name), 'w') as fh:
                                json.dump(data, fh, indent=4, ensure_ascii=False)
                        except json.decoder.JSONDecodeError as err:
                            return 1, f'Ошибка парсинга файла конфигурации "{file_name}" [{err}].'
                        except UnicodeDecodeError as err:
                            return 1, f'Ошибка файла конфигурации "{file_name}" [{err}].'

                dialog = SelectSecureGateway(self.parent, cp_data_json)
                result = dialog.exec()
                if result == QDialog.DialogCode.Accepted:
                    return 0, dialog.sg_name
                else:
                    return 1, 'Конвертация конфигурации Check Point прервана пользователем.'
            else:
                return 1, f'Не найден файл конфигурации Check Point "config_cp.txt" в каталоге "{self.vendor_current_path}".'
        else:
            return 1, f'Не найдена конфигурация Check Point в каталоге "{self.vendor_current_path}".'

    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        today = dt.now()
        path_logfile = os.path.join(self.vendor_current_path, f'{today:%Y-%m-%d_%M:%S}-{log_file}')
        list_items = [self.log_list.item(row).text() for row in range(self.log_list.count())]
        with open(path_logfile, 'w') as fh:
            print(*list_items, sep='\n', file=fh)
            fh.write('\n')
        func.message_inform(self, 'Сохранение лога', f'Лог сохранён в файл "{path_logfile}".')

    def run_page_0(self):
        """Возвращаемся на стартовое окно"""
        self.label_node_name.setText('')
        self.label_version.setText('')
        self.label_config_directory.setText('')
        self.log_list.clear()
        self.selected_point = ''
        self.vendor_base_path = ''
        self.vendor_current_path = ''
        self.parent.stacklayout.setCurrentIndex(0)

    def add_item_log(self, message, color='BLACK'):
        """
        Добавляем запись лога в log_list.
        """
        i = QListWidgetItem(message)
        i.setForeground(QColor(cs.color[color]))
        self.log_list.addItem(i)

    def items_add_and_scroll(self):
        if self.tmp_list:
            for x in self.tmp_list:
                self.log_list.addItem(x)
            self.tmp_list.clear()
            self.log_list.scrollToBottom()

    def on_step_changed(self, msg):
        color, _, message = msg.partition('|')
        i = QListWidgetItem(message)
        i.setForeground(QColor(cs.color[color]))
        if color in ('BLACK', 'NOTE', 'uGRAY'):
            self.tmp_list.append(i)
            if len(self.tmp_list) > 20:
                self.items_add_and_scroll()
        else:
            if color == 'RED':
                self.log_list.addItem(i)
                self.log_list.scrollToBottom()
            else:
                self.items_add_and_scroll()
                self.log_list.addItem(i)
                self.log_list.scrollToBottom()
        if color in ('iORANGE', 'iGREEN', 'iRED'):
            func.message_inform(self, 'Внимание!', message)

    def on_finished(self):
        self.tmp_list.clear()
        self.thread = None
        self.enable_buttons()
        self.btn3.setStyleSheet('color: darkred; background: white;')
        self.btn3.setEnabled(True)


class SelectImportMode(SelectMode):
    """Класс для выбора раздела конфигурации для импорта на NGFW. Номер в стеке 2."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title.setText(f"<b><font color='green' size='+2'>Импорт конфигурации на UserGate</font></b>")
        self.btn1.clicked.connect(self.run_page_0)
        self.btn2.setText("Импорт выбранного раздела")
        self.btn2.clicked.connect(self.import_selected_points)
        self.btn3.setText("Импортировать всё")
        self.btn3.clicked.connect(self.import_all)
        self.btn4.clicked.connect(lambda: self._save_logs('import.log'))
        self.parent.stacklayout.currentChanged.connect(self.init_import_widget)

    def init_temporary_data(self):
        """
        Запускаем в потоке gtd.GetTemporaryData() для получения часто используемых данных с NGFW.
        """
        if self.thread is None:
            self.disable_buttons()
            self.thread = gtd.GetImportTemporaryData(self.utm)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка получения служебных структур данных с {self.product}! {self.thread}')

    def init_import_widget(self, e):
        """
        При открытии этой вкладки выбираем каталог с конфигурацией для импорта.
        """
        if e == 2:
            self.parent.resize(980, 750)
            dialog =  SelectImportConfigDirectory(self.parent)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'{self.parent.get_ug_config_path()}  ')
                if self.get_auth(mod='fw'):
                    self.title.setText(f"<b><font color='green' size='+2'>Импорт конфигурации на UserGate {self.product}</font></b>")
                    self.enable_buttons()
                    self.tree.version = self.utm.float_version
                    self.tree.product = self.utm.product
                    self.tree.change_items_status(self.parent.get_ug_config_path())
                    title = f'Импорт конфигурации из "{self.parent.get_ug_config_path()}" на {self.product} {self.utm.version}.'
                    self.add_item_log(f'{title:>100}', color='GREEN')
                    self.add_item_log(f'{"="*100}', color='ORANGE')
                    self.init_temporary_data()
                else:
                    self.run_page_0()
            else:
                self.run_page_0()

    def import_selected_points(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт выбранного раздела конфигурации.
        """
        if not func.check_auth(self):
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
                if not func.check_auth(self):
                    self.run_page_0()

                self.thread = tf.ImportSelectedPoints(
                    self.utm,
                    self.parent.get_ug_config_path(),
                    arguments,
                    all_points=None,
                    selected_path=self.current_ug_path,
                    selected_points=self.selected_points
                )
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

        else:
            func.message_inform(self, "Внимание!", "Нет данных для импорта.\n Выбранный раздел пуст.")

    def import_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт всей конфигурации.
        """
        if not func.check_auth(self):
            self.run_page_0()

        all_points = self.tree.select_all_items()
        if not all_points:
            func.message_inform(self, 'Внимание!', 'Нет данных для импорта.')
            return

        arguments = {
            'ngfw_ports': '',
            'dhcp_settings': '',
            'ngfw_vlans': '',
            'new_vlans': '',
            'iface_settings': '',
        }
        for item in all_points:
            self.current_ug_path = os.path.join(self.parent.get_ug_config_path(), item['path'])
            self.selected_points = item['points']
            self.set_arguments(arguments)
        self.tree.set_current_item()

        if self.thread is None:
            self.disable_buttons()
            self.thread = tf.ImportSelectedPoints(self.utm, self.parent.get_ug_config_path(), arguments, all_points=all_points)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

    def set_arguments(self, arguments):
        """Заполняем структуру параметров для импорта."""
        err, ngfw_interfaces = self.utm.get_interfaces_list()
        if err:
            return err, f'RED|    {ngfw_interfaces}'

        if 'DHCP' in self.selected_points:
            err, result = self.import_dhcp(ngfw_interfaces)
            arguments['ngfw_ports'] = err
            arguments['dhcp_settings'] = result
        if 'Interfaces' in self.selected_points:
            if self.utm.version_hight == 5:
                arguments['ngfw_vlans'] = 2
                arguments['new_vlans'] = f'bRED|    VLAN нельзя импортировать на NGFW версии {self.utm.version}.'
            else:
                err, result = self.create_vlans(ngfw_interfaces)
                if err:
                    arguments['ngfw_vlans'] = err
                    arguments['new_vlans'] = result
                else:
                    arguments['iface_settings'] = result[0]
                    arguments['ngfw_vlans'] = result[1]
                    arguments['new_vlans'] = result[2]

    def create_vlans(self, ngfw_interfaces):
        """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
        iface_path = os.path.join(self.current_ug_path, 'Interfaces')
        json_file = os.path.join(iface_path, 'config_interfaces.json')
        err, data = func.read_json_file(self, json_file)
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
        interfaces_list = ['Undefined']

        for item in ngfw_interfaces:
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

        dialog = VlanWindow(self, vlans=vlans, ports=interfaces_list, zones=zones)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            new_vlans = {}
            for key, value in dialog.vlans.items():
                new_vlans[key] = {'port': value['port'].currentText(), 'zone': value['zone'].currentText()}
            return 0, [data, ngfw_vlans, new_vlans]
        else:
            return 3, 'LBLUE|    Импорт настроек интерфейсов отменён пользователем.'

    def import_dhcp(self, ngfw_interfaces):
        dhcp_path = os.path.join(self.current_ug_path, 'DHCP')
        json_file = os.path.join(dhcp_path, 'config_dhcp_subnets.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            return err, data

        ngfw_ports = [x['name'] for x in ngfw_interfaces if x.get('ipv4', False) and x['kind'] in {'bridge', 'bond', 'adapter', 'vlan'}]
        ngfw_ports.insert(0, 'Undefined')

        dialog = CreateDhcpSubnetsWindow(self, ngfw_ports, data)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            return ngfw_ports, data
        else:
            return 3, 'LBLUE|    Импорт настроек DHCP отменён пользователем.'


class SelectMcImportMode(SelectMode):
    """Класс для импорта конфигурации в шаблон МС. Номер в стеке 3."""
    def __init__(self, parent):
        super().__init__(parent)
        self.templates_group_name = None
        self.templates_ids = None
        self.template_id = None
        self.template_name = None
        self.templates = None
        self.id_nodes = [f'node_{i}' for i in range(1, 100)]
        self.title.setText("<b><font color='green' size='+2'>Импорт конфигурации в шаблон UserGate Management Center</font></b>")
        self.btn1.clicked.connect(self.select_template)
        self.btn2.setText("Импорт выбранного раздела")
        self.btn2.clicked.connect(self.import_selected_points)
        self.btn3.setText("Импортировать всё")
        self.btn3.clicked.connect(self.import_all)
        self.btn4.clicked.connect(lambda: self._save_logs('import.log'))
        
        self.parent.stacklayout.currentChanged.connect(self.init_import_widget)


    def init_temporary_data(self):
        """
        Запускаем в потоке ImportMcTemporaryData() для получения часто используемых данных с MC.
        """
        if self.thread is None:
            self.disable_buttons()
            self.thread = ImportMcTemporaryData(self.utm, self.template_id, self.templates)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка получения служебных структур данных с МС! {self.thread}')


    def init_import_widget(self, e):
        """
        При открытии этой вкладки выбираем каталог с конфигурацией для импорта.
        """
        if e == 3:
            self.parent.resize(980, 750)
            dialog =  SelectImportConfigDirectory(self.parent)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'{self.parent.get_ug_config_path()}  ')
                if self.get_auth(mod='mc'):
                    if self.utm.float_version < 7.1:
                        message = f'Импорт на Management Center версии менее чем 7.1 не поддерживается. Ваша версия: {self.utm.version}'
                        self.add_item_log(message, color='RED')
                        func.message_inform(self, 'Внимание!', message)
                        self.run_page_0()
                        return

                    groups_dialog = SelectMcGroupTemplates(self, self.parent)
                    groups_result = groups_dialog.exec()
                    if groups_result == QDialog.DialogCode.Accepted:
                        self.templates_group_name = groups_dialog.current_group_name
                        self.templates_ids = groups_dialog.templates
                    else:
                        self.run_page_0()
                        return
                    self.select_template(init=True)
                else:
                    self.run_page_0()
            else:
                self.run_page_0()


    def select_template(self, init=False):
        if not func.check_auth(self):
            self.run_page_0()

        template_dialog = SelectMcDestinationTemplate(self.utm, self.parent, self.templates_group_name, templates=self.templates_ids)
        template_result = template_dialog.exec()
        if template_result == QDialog.DialogCode.Accepted:
            self.template_name = template_dialog.current_template_name
            self.template_id = template_dialog.templates[self.template_name]
            self.templates = {uid: name for name, uid in template_dialog.templates.items()}
            self.label_version.setText(f'MC (версия {self.utm.version})  Группа шаблонов: {self.templates_group_name}  Шаблон: {self.template_name}')
            self.enable_buttons()
            self.tree.version = self.utm.float_version
            self.tree.product = self.utm.product
            self.tree.change_items_status(self.parent.get_ug_config_path())
            title = f'Импорт конфигурации в шаблон "{self.templates_group_name}/{self.template_name}" на МС.'
            self.add_item_log(f'{title:>100}', color='GREEN')
            self.add_item_log(f'{"="*100}', color='ORANGE')
            if init:
                self.init_temporary_data()
        else:
            self.run_page_0()


    def import_selected_points(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт выбранного раздела конфигурации.
        """
        if not func.check_auth(self):
            self.run_page_0()

        if self.selected_points:
            arguments = {
                'ngfw_ports': '',
                'dhcp_settings': '',
                'ngfw_vlans': '',
                'new_vlans': '',
                'iface_settings': '',
            }
            node_name = 'node_1'
            if not {'Interfaces', 'Gateways', 'DHCP', 'VRF', 'SNMPParameters'}.isdisjoint(self.selected_points):
                node_name, ok = QInputDialog.getItem(self, 'Выбор идентификатора узла', 'Выберите идентификатор узла кластера', self.id_nodes)
                if not ok:
                    func.message_inform(self, 'Ошибка', f'Импорт прерван, так как не указан идентификатор узла.')
                    return
                self.set_arguments(node_name, arguments)
            if self.thread is None:
                self.disable_buttons()
                self.thread = import_to_mc.ImportSelectedPoints(
                    self.utm,
                    self.parent.get_ug_config_path(),
                    self.template_id,
                    self.templates,
                    arguments,
                    node_name,
                    all_points=None,
                    selected_path=self.current_ug_path,
                    selected_points=self.selected_points
                )
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

        else:
            func.message_inform(self, "Внимание!", "Вы не выбрали раздел для импорта.")

    def import_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт всей конфигурации.
        """
        if not func.check_auth(self):
            self.run_page_0()

        message = 'Перед тем как импортировать всё, убедитесь, что на Management Center существуют интерфейсы и зоны. Это необходимо для создания '
        message1 = 'интерфейсов VLAN, подсетей DHCP, Gateways и VRF. Если нет интерфейсов, VLAN и подсети DHCP не будут созданы, в VRF настройки OSPF и RIP будут не полными.'
        func.message_inform(self, 'Внимание!', f'{message}{message1}')

        node_name = 'node_1'
        node_name, ok = QInputDialog.getItem(self, 'Выбор идентификатора узла', 'Выберите идентификатор узла кластера', self.id_nodes)
        if not ok:
            func.message_inform(self, 'Ошибка', f'Импорт прерван, так как не указан идентификатор узла.')
            return

        all_points = self.tree.select_all_items()
        arguments = {
            'ngfw_ports': '',
            'dhcp_settings': '',
            'ngfw_vlans': '',
            'new_vlans': '',
            'iface_settings': '',
        }
        for item in all_points:
            self.current_ug_path = os.path.join(self.parent.get_ug_config_path(), item['path'])
            self.selected_points = item['points']
            if not {'Interfaces', 'Gateways', 'DHCP', 'VRF', 'SNMPParameters'}.isdisjoint(self.selected_points):
                self.set_arguments(node_name, arguments)
        self.tree.set_current_item()

        if self.thread is None:
            self.disable_buttons()
            self.thread = import_to_mc.ImportSelectedPoints(
                                                 self.utm,
                                                 self.parent.get_ug_config_path(),
                                                 self.template_id,
                                                 self.templates,
                                                 arguments,
                                                 node_name,
                                                 all_points=all_points
                                                 )
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

    def set_arguments(self, node, arguments):
        """Заполняем структуру параметров для импорта."""
        mc_interfaces = []
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_interfaces_list(uid)
            if err:
                return err, f'RED|    {result}'
            for item in result:
                if item['kind'] not in ('bridge', 'bond', 'adapter', 'vlan') or item['master']:
                    continue
                if item['node_name'] == node:
                    mc_interfaces.append({'name': item['name'], 'kind': item['kind'], 'vlan_id': item.get('vlan_id', 0)})

        if not mc_interfaces:
            msg = f'Для "{node}" отсутствуют интерфейсы.\nVLAN и subnet DHCP не будут импортированы.'
            func.message_inform(self, 'Внимание!', msg)
            arguments['ngfw_ports'] = 3
            arguments['dhcp_settings'] = f'ORANGE|    Импорт настроек DHCP отменён из-за отсутствия портов на узле {node} шаблона.'
            arguments['ngfw_vlans'] = 3
            arguments['new_vlans'] = f'ORANGE|    Импорт настроек VLAN отменён из-за отсутствия портов на узле {node} шаблона.'
            return
 
        if 'DHCP' in self.selected_points:
            err, result = self.import_dhcp(mc_interfaces)
            arguments['ngfw_ports'] = err
            arguments['dhcp_settings'] = result
        if 'Interfaces' in self.selected_points:
            err, result = self.create_vlans(mc_interfaces)
            if err:
                arguments['ngfw_vlans'] = err
                arguments['new_vlans'] = result
            else:
                arguments['iface_settings'] = result[0]
                arguments['ngfw_vlans'] = result[1]
                arguments['new_vlans'] = result[2]

    def create_vlans(self, mc_interfaces):
        """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
        iface_path = os.path.join(self.current_ug_path, 'Interfaces')
        json_file = os.path.join(iface_path, 'config_interfaces.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            return err, data

        vlans = sorted([item['vlan_id'] for item in data if item['kind'] == 'vlan'])
        if not vlans:
            return 3, 'LBLUE|    Нет VLAN для импорта.'

        tmp_zones = set()
        for uid, name in self.templates.items():
            err, result = self.utm.get_template_zones_list(uid)
            if err:
                return err, f'RED|    {result}'
            for x in result:
                tmp_zones.add(x['name'])

        zones = sorted([x for x in tmp_zones])
        zones.insert(0, "Undefined")

        # Составляем список легитимных интерфейсов (interfaces_list).
        ngfw_vlans = {}
        interfaces_list = ['Undefined']

        for item in mc_interfaces:
            if item['kind'] == 'vlan':
                ngfw_vlans[item['vlan_id']] = item['name']
                continue
            interfaces_list.append(item['name'])

        dialog = VlanWindow(self, vlans=vlans, ports=sorted(interfaces_list), zones=zones)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            new_vlans = {}
            for key, value in dialog.vlans.items():
                new_vlans[key] = {'port': value['port'].currentText(), 'zone': value['zone'].currentText()}
            return 0, [data, ngfw_vlans, new_vlans]
        else:
            return 3, 'LBLUE|    Импорт настроек VLAN отменён пользователем.'

    def import_dhcp(self, mc_interfaces):
        dhcp_path = os.path.join(self.current_ug_path, 'DHCP')
        json_file = os.path.join(dhcp_path, 'config_dhcp_subnets.json')
        err, data = func.read_json_file(self, json_file)
        if err:
            return err, data

        ngfw_ports = sorted([x['name'] for x in mc_interfaces])
        ngfw_ports.insert(0, 'Undefined')

        dialog = CreateDhcpSubnetsWindow(self, ngfw_ports, data)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            return ngfw_ports, data
        else:
            return 3, 'LBLUE|    Импорт настроек DHCP отменён пользователем.'


class SelectMcGroupTemplates(QDialog):
    """Базовый класс для выбора группы шаблонов MC."""
    def __init__(self, parent, main_window):
        super().__init__(main_window)
        self.main_window = main_window
        self.parent = parent
        self.groups = {}
        self.current_group_name = None
        self.templates = None
        self.setWindowTitle("Выбор группы шаблонов MC")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        self.setFixedHeight(200)

        self.label = QLabel("<b><font color='green'>Выберите группу шаблонов Management Center.</font></b><br>")
        self.label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.groups_list = QListWidget()

        self.btn_enter = QPushButton("Ввод")
        self.btn_enter.setStyleSheet('color: steelblue; background: white;')
        self.btn_enter.setFixedWidth(80)
        self.btn_enter.clicked.connect(self.enter_group)

        self.btn_exit = QPushButton("Отмена")
        self.btn_exit.setStyleSheet('color: darkred;')
        self.btn_exit.setFixedWidth(80)
        self.btn_exit.clicked.connect(self.reject)

        self.btn_hbox = QHBoxLayout()
        self.btn_hbox.addWidget(self.btn_enter)
        self.btn_hbox.addStretch()
        self.btn_hbox.addWidget(self.btn_exit)

        self.vbox = QVBoxLayout()
        self.vbox.addWidget(self.label)
        self.vbox.addWidget(self.groups_list)
        self.vbox.addSpacerItem(QSpacerItem(3, 5))
        self.vbox.addLayout(self.btn_hbox)
        self.setLayout(self.vbox)

        self.groups_list.currentTextChanged.connect(self.select_dest_group)
        self.disable_buttons()
        self.add_groups_items()

    def disable_buttons(self):
        self.btn_enter.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_enter.setEnabled(False)

    def _send_accept(self):
        self.accept()

    def add_groups_items(self):
        """При открытии этого диалога получаем с МС список групп шаблонов и заполняем список выбора групп."""
        err, result = self.parent.utm.get_device_templates_groups()
        if err:
            func.message_alert(self, 'Не удалось получить список групп шаблонов!', result)
        else:
            self.groups_list.clear()
            for item in result:
                self.groups_list.addItem(item['name'])
                self.groups[item['name']] = item['device_templates']
            self.groups_list.setCurrentRow(0)

    def select_dest_group(self, item_text):
        self.current_group_name = item_text
        self.btn_enter.setStyleSheet('color: steelblue; background: white;')
        self.btn_enter.setEnabled(True)

    def enter_group(self):
        if self.groups[self.current_group_name]:
            self.templates = self.groups[self.current_group_name]
            self._send_accept()
        else:
            func.message_inform(self, 'Пустая группа', 'В выбранной группе нет шаблонов.\nВыберите другую группу.')


class SelectMcDestinationTemplate(QDialog):
    """Для МС. Диалоговое окно для выбора шаблона MC для импорта."""
    def __init__(self, utm, main_window, group_name, templates=None):
        super().__init__(main_window)
        self.main_window = main_window
        self.utm = utm
        self.name_group_templates = group_name
        self.group_templates = templates
        self.templates = {}
        self.current_template_name = None
        self.setWindowTitle(f'Выбор шаблона MC для импорта')
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        label = QLabel(f'<b><font color="green">Выберите шаблон для импорта конфигурации.</font></b><br>Шаблоны группы: <font color="blue">"{self.name_group_templates}"</font>')
        label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.device_templates_list = QListWidget()

        self.btn_enter = QPushButton("Ввод")
        self.btn_enter.setStyleSheet('color: steelblue; background: white;')
        self.btn_enter.setFixedWidth(80)
        self.btn_enter.clicked.connect(self._send_accept)

        btn_exit = QPushButton("Отмена")
        btn_exit.setStyleSheet('color: darkred;')
        btn_exit.setFixedWidth(80)
        btn_exit.clicked.connect(self.reject)

        btn_hbox = QHBoxLayout()
        btn_hbox.addWidget(self.btn_enter)
        btn_hbox.addStretch()
        btn_hbox.addWidget(btn_exit)

        vbox = QVBoxLayout()
        vbox.addWidget(label)
        vbox.addWidget(self.device_templates_list)
        vbox.addSpacerItem(QSpacerItem(3, 5))
        vbox.addLayout(btn_hbox)
        self.setLayout(vbox)

        self.device_templates_list.currentTextChanged.connect(self.select_dest_template)
        self.disable_buttons()
        self.add_device_template_items()

    def disable_buttons(self):
        self.btn_enter.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_enter.setEnabled(False)

    def _send_accept(self):
        self.accept()

    def add_device_template_items(self):
        """При открытии этого диалога получаем с МС список шаблонов устройств и заполняем список выбора шаблонов."""
        self.device_templates_list.clear()
        for template_id in self.group_templates:
            err, result = self.utm.fetch_device_template(template_id)
            if err:
                func.message_alert(self, 'Не удалось получить список шаблонов группы.', result)
            else:
                self.device_templates_list.addItem(result['name'])
                self.templates[result['name']] = result['id']
            self.device_templates_list.setCurrentRow(0)

    def select_dest_template(self, item_text):
        self.current_template_name = item_text
        self.btn_enter.setStyleSheet('color: steelblue; background: white;')
        self.btn_enter.setEnabled(True)


class SelectSecureGateway(QDialog):
    """Для CheckPoint. Диалоговое окно выбора Secure Gateway для конвертации"""
    def __init__(self, parent, cp_data_json):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Выбор Gateways policy package")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        self.setFixedHeight(200)
        self.sg_name = None

        title =QLabel("<b><font color='green'>Выберите Secure Gateway для конвертации.<br>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.sg_list = QListWidget()
        with open(os.path.join(cp_data_json, 'index.json'), 'r') as fh:
            data = json.load(fh)
        for item in data['policyPackages']:
            self.sg_list.addItem(item['packageName'])

        btn_enter = QPushButton("Ввод")
        btn_enter.setStyleSheet('color: forestgreen; background: white;')
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
        layout.addWidget(self.sg_list)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
        self.sg_list.currentTextChanged.connect(self.select_secure_gateway)

    def select_secure_gateway(self, item_name):
        self.sg_name = item_name
        
    def _send_accept(self):
        if self.sg_name:
            self.accept()


class SelectConfigDirectories(QDialog):
    """Диалоговое окно выбора каталога для с экспортируемой конфигурацией"""
    def __init__(self, parent, vendor_path, vendor):
        super().__init__(parent)
        self.main_window = parent
        self.vendor_base_path = vendor_path
        self.vendor_current_path = ''
        self.vendor = vendor
        self.setWindowTitle("Выбор каталогов с конфигурацией")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        with os.scandir(self.vendor_base_path) as fh:
            list_dir = [x.name for x in fh if x.is_dir()]
        self.vendor_directory = QComboBox()
        self.vendor_directory.addItems(sorted(list_dir))
        self.vendor_directory.setEditable(True)
#        self.setFixedHeight(170)
        vendor_text = f"<b><font size='+1' color='green'>Выберите каталог с конфигурацией {self.vendor}.</font></b><br> \
Если каталог не существует, введите имя нового каталога.<br> \
Он будет создан в текущей директории в каталоге <b>{self.vendor_base_path}</b>.<br> \
Затем поместите в него конфигурацию {self.vendor}."
        vendor_title = QLabel(vendor_text)
        vendor_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)

        list_ugdir = os.listdir(self.main_window.base_ug_path)
        self.ug_directory = QComboBox()
        self.ug_directory.addItems(sorted(list_ugdir))
        self.ug_directory.setEditable(True)
        ug_text = "<b><font size='+1' color='green'>Выберите каталог для экспорта конфигурации.</font></b><br> \
Если каталог не существует, введите имя нового каталога.<br>Он будет создан в текущей директории в каталоге <b>data_ug</b>."
        ug_title = QLabel(ug_text)
        ug_title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        btn_enter = QPushButton("Запустить конвертацию")
        btn_enter.setStyleSheet('color: steelblue; background: white;')
        btn_enter.setFixedWidth(180)
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
        layout.addWidget(vendor_title)
        layout.addWidget(self.vendor_directory)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addWidget(line)
        layout.addSpacerItem(QSpacerItem(0, 2))
        layout.addWidget(ug_title)
        layout.addWidget(self.ug_directory)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)
        
    def _send_accept(self):
        if self.vendor_directory.currentText():
            self.vendor_current_path = os.path.join(self.vendor_base_path, self.vendor_directory.currentText())
            err, msg = func.create_dir(self.vendor_current_path, delete='no')
            if err:
                func.message_alert(self, msg, '')
            else:
                if self.ug_directory.currentText():
                    self.main_window.set_ug_config_path(self.ug_directory.currentText())
                    err, msg = func.create_dir(self.main_window.get_ug_config_path(), delete='no')
                    if err:
                        func.message_alert(self, msg, '')
                        self.main_window.del_ug_config_path()
                    else:
                        self.accept()


class SelectImportConfigDirectory(QDialog):
    """Диалоговое окно выбора каталога для импорта конфигурации"""
    def __init__(self, parent):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Выбор каталога для импорта")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        list_dir = os.listdir(self.main_window.base_ug_path)
        self.config_directory = QComboBox()
        self.config_directory.addItems(sorted(list_dir))
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
            self.main_window.set_ug_config_path(self.config_directory.currentText())
            self.accept()


class LoginWindow(QDialog):
    def __init__(self, parent, mode='fw'):
        super().__init__(parent)
        self.mode = mode
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        if self.mode == 'fw':
            self.setWindowTitle("Авторизация на UG NGFW")
            self.setFixedHeight(190)
            title = QLabel(f"<b><font color='green'>Введите учётнные данные<br>администратора NGFW</font></b>")
        elif self.mode == 'mc':
            self.setWindowTitle("Авторизация на UG MC")
            self.setFixedHeight(200)
            title = QLabel(f"<b><font color='green'>Введите учётнные данные<br>администратора области<br>Management Center</font></b>")
            title.setWordWrap(True)
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
            if self.mode == 'fw':
                self.utm = UtmXmlRpc(self.ngfw_ip.text(), self.login.text(), self.password.text())
            elif self.mode == 'mc':
                self.utm = McXmlRpc(self.ngfw_ip.text(), self.login.text(), self.password.text())
            err, result = self.utm.connect()
            if err:
                func.message_alert(self, 'Не удалось подключиться с указанными параметрами!', result)
            else:
                self.accept()

    def check_ip_is_valid(self, ip_addr):
        """Проверяем введённый ip-адрес на валидность."""
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except ValueError:
            func.message_inform(self, 'Ошибка!', 'Вы ввели не корректный IP-адрес.')
            return False


class ColorLabel(QLabel):
    def __init__(self, text="Empty", color="darkred", name=None):
        super().__init__(text)
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
        grid_title_hbox.addWidget(ColorLabel('Vlan', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel('Порт', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel('Зона', 'blue'))
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
    """Окно настройки subnets для DHCP."""
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
        grid_title_hbox.addWidget(ColorLabel('DHCP subnet', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel('Порт', 'blue'))
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
        self.product = None     # Тип продукта (ngfw, dcfw, mc)

        self.compliances = {
            "UserGate": "UserGate",
            "GeneralSettings": "Настройки",
            "DeviceManagement": "Управление устройством",
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
            "UserIDagent": "Агент UserID",
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
            "Tags": "Тэги",
            "Notifications": "Оповещения",
            "AlertRules": "Правила оповещений",
            "SNMP": "SNMP",
            "SNMPParameters": "Параметры SNMP",
            "SNMPSecurityProfiles": "Профили безопасности SNMP",
        }
        
        self.over_compliances = {v: k for k, v in self.compliances.items()}

        data = {
            "UserGate": ["Настройки", "Управление устройством", "Администраторы", "Сертификаты",
                         "Профили пользовательских сертификатов"],
            "Сеть": ["Зоны", "Интерфейсы", "Шлюзы", "DHCP", "DNS", "Виртуальные маршрутизаторы", "WCCP", "Маршруты", "OSPF", "BGP"],
            "Пользователи и устройства": [
                "Группы", "Пользователи", "Профили MFA", "Серверы аутентификации", "Профили аутентификации", "Captive-профили",
                "Captive-портал", "Терминальные серверы", "Политики BYOD", "Агент UserID"
            ],
            "Политики сети": ["Межсетевой экран", "NAT и маршрутизация", "Балансировка нагрузки", "Пропускная способность"],
            "Политики безопасности": [
                "Фильтрация контента", "Веб-безопасность", "Инспектирование туннелей", "Инспектирование SSL",
                "Инспектирование SSH", "СОВ", "Правила АСУ ТП", "Защита почтового трафика", "ICAP-серверы", "ICAP-правила",
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
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента", "Сценарии", "Тэги"
            ],
            "Оповещения": ["Правила оповещений", "Профили безопасности SNMP", "SNMP", "Параметры SNMP"],
        }

        self.restricted_items = {
            'dcfw-8.0': {
                "WCCP", "Маршруты", "OSPF", "BGP", "Системные WAF-правила", "Политики BYOD", "Агент UserID", "Политики безопасности",
                "Фильтрация контента", "Веб-безопасность", "Инспектирование туннелей", "Инспектирование SSL", "Инспектирование SSH",
                "СОВ", "Правила АСУ ТП", "Защита почтового трафика", "ICAP-серверы", "ICAP-правила", "Профили DoS",
                "Правила защиты DoS", "Глобальный портал", "Веб-портал", "Серверы reverse-прокси", "Правила reverse-прокси",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Профили безопасности VPN", "Профили АСУ ТП", "Морфология", "Useragent браузеров", "Типы контента", "Категории URL",
                "Изменённые категории URL", "HID объекты", "HID профили", "Сценарии"},
            8.0: {
                "Маршруты", "OSPF", "BGP",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.3: {
                "Маршруты", "OSPF", "BGP", "WAF", "Персональные WAF-слои", "Системные WAF-правила", "WAF-профили",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.2: {
                "Маршруты", "OSPF", "BGP", "WAF", "Персональные WAF-слои", "Системные WAF-правила", "WAF-профили",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.1: {
                "Маршруты", "OSPF", "BGP", "WAF", "Персональные WAF-слои", "Системные WAF-правила", "WAF-профили",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.0: {
                "Профили пользовательских сертификатов",
                "Маршруты", "OSPF", "BGP",
                "Политики BYOD",
                "Агент UserID",
                "Правила АСУ ТП",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Серверные профили безопасности", "Клиентские профили безопасности",
                "Профили АСУ ТП",
                "Профили приложений", "Приложения",
                "Сигнатуры СОВ",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
                "Параметры SNMP", "Профили безопасности SNMP",
            },
            6.1: {
                "Профили пользовательских сертификатов",
                "Маршруты", "OSPF", "BGP",
                "Инспектирование туннелей",
                "Агент UserID",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Серверные профили безопасности", "Клиентские профили безопасности",
                "Группы сервисов", "Профили приложений", "Приложения",
                "Сигнатуры СОВ",
                "Профили LLDP",
                "Профили пересылки SSL",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
                "Параметры SNMP", "Профили безопасности SNMP",
            },
            5.0: {
                "Профили пользовательских сертификатов",
                "Виртуальные маршрутизаторы",
                "Терминальные серверы",
                "Агент UserID",
                "Инспектирование туннелей",
                "Инспектирование SSH",
                "WAF", "WAF-профили", "Персональные WAF-слои", "Системные WAF-правила",
                "Серверные профили безопасности", "Клиентские профили безопасности",
                "Группы сервисов", "Профили приложений", "Приложения",
                "Сигнатуры СОВ", "Профили LLDP", "Профили SSL", "Профили пересылки SSL",
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента",
                "Параметры SNMP", "Профили безопасности SNMP",
            },
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

    def change_items_status(self, current_ug_path):
        """Скрываем пункты меню отсутствующие в данной версии NGFW и активируем те, для которых есть конфигурация."""
        if self.product == 'dcfw':
            key = f'dcfw-{self.version}'
        else:
            key = self.version
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item.text(0) in self.restricted_items[key]:
                item.setHidden(True)
            else:
                item_dir = self.over_compliances[item.text(0)]
                item_config_path = os.path.join(current_ug_path, item_dir)
                if os.path.isdir(item_config_path):
                    item.setHidden(False)
                    item.setDisabled(False)
                    for i in range(item.childCount()):
                        child_text = item.child(i).text(0)
                        try:
                            if child_text in self.restricted_items[key]:
                                item.child(i).setHidden(True)
                            else:
                                child_dir = self.over_compliances[child_text]
                                child_config_path = os.path.join(item_config_path, child_dir)
                                if os.path.isdir(child_config_path):
                                    item.child(i).setHidden(False)
                                    item.child(i).setDisabled(False)
                                else:
                                    item.child(i).setHidden(True)
                        except KeyError:
                            pass
                else:
                    item.setHidden(True)
        self.set_current_item()

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
                    if selected_item.child(i).isHidden():
                        continue
                    child_text = selected_item.child(i).text(0)
                    try:
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
            if item.isHidden():
                continue
            item_text = self.over_compliances[item.text(0)]
            item_childs = []
            for i in range(item.childCount()):
                if item.child(i).isHidden():
                    continue
                child_text = item.child(i).text(0)
                try:
                    item_childs.append(self.over_compliances[child_text])
                except KeyError:
                    pass
            if item_childs:
                array.append({'path': item_text, 'points': item_childs})
        return array

    def set_current_item(self):
        """Устанавливаем верхний раздел дерева в качестве текущего (выделенного)."""
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if not item.isHidden():
                self.setCurrentItem(item)
                break

#---------------------------------------------------------------------------------------------------------------------------------
def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
