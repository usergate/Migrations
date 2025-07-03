#!/usr/bin/python3
#
# Это только для ug_ngfw_converter
# Версия 2.3   02.07.2025
#-----------------------------------------------------------------------------------------------------------------------------

import os, json, ipaddress
from datetime import datetime as dt
from PyQt6.QtGui import QBrush, QColor, QFont, QPalette
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout, QWidget, QFrame, QDialog, QMessageBox,
                             QListWidget, QListWidgetItem, QPushButton, QLabel, QSpacerItem, QLineEdit, QComboBox, QScrollArea,
                             QTreeWidget, QTreeWidgetItem, QSizePolicy, QSplitter, QInputDialog, QRadioButton, QButtonGroup)
import common_func as func
import config_style as cs
import export_from_ngfw as ef
import export_from_mc as expmc
import get_ngfw_temporary_data as gtd
from get_mc_ngfw_temp_data import GetMcNgfwTemporaryData
from get_mc_dcfw_temp_data import GetMcDcfwTemporaryData
from import_ngfw_to_mc import ImportMcNgfwSelectedPoints
from import_dcfw_to_mc import ImportMcDcfwSelectedPoints
from import_functions import ImportNgfwSelectedPoints
from import_mc_ngfw_templates import ImportMcNgfwTemplates
from import_mc_dcfw_templates import ImportMcDcfwTemplates
from utm import UtmXmlRpc
from mclib import McXmlRpc


class SelectAction(QWidget):
    """Класс для выбора режима: экспорт/импорт. Номер в стеке 0."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        text1 = "<b><font color='green' size='+2'>Экспорт/Импорт конфигурации UserGate: NGFW, DCFW, MC</font></b>"
        text2 = "Экспорт конфигурации из <b>UG NGFW</b> (версий <b>5, 6, 7</b>) и <b>DCFW</b> и сохранение её в файлах json в каталоге <b>data</b> в текущей директории."
        text3 = "Экспорт группы шаблонов NGFW <b>UserGate Management Center</b> версии <b>7</b> и сохранение в каталог <b>mc_templates</b> в текущей директории."
        text4 = "Импорт файлов конфигурации NGFW из каталога <b>data</b> на <b>UserGate NGFW</b> (версий <b>5, 6, 7</b>) и <b>DCFW</b>."
        text5 = "Импорт файлов конфигурации NGFW и DCFW из каталога <b>data</b> в группу шаблонов NGFW или DCFW <b>UserGate Management Center</b> версии <b>7</b>."
        text6 = "Импорт из каталога <b>mc_templates</b> ранее экспортированной группы шаблонов в административную область <b>UserGate Management Center</b> версии <b>7</b>."
        label1 = QLabel(text1)
        label1.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        label2 = QLabel(text2)
        label2.setWordWrap(True)
        label3 = QLabel(text3)
        label3.setWordWrap(True)
        label4 = QLabel(text4)
        label4.setWordWrap(True)
        label5 = QLabel(text5)
        label5.setWordWrap(True)
        label6 = QLabel(text6)
        label6.setWordWrap(True)

        btn_font = QFont("SansSerif", pointSize=9, weight=600)

        self.btn_export = QPushButton("Экспорт конфигурации из UG NGFW|DCFW")
        self.btn_export.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_export.setFont(btn_font)
        self.btn_export.setFixedWidth(280)
        self.btn_export.setEnabled(False)
        self.btn_export.clicked.connect(self.set_export_page)

        self.btn_export_mc = QPushButton("Экспорт группы шаблонов из\n UG Management Center")
        self.btn_export_mc.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_export_mc.setFont(btn_font)
        self.btn_export_mc.setFixedWidth(280)
        self.btn_export_mc.setEnabled(False)
        self.btn_export_mc.clicked.connect(self.set_export_mc_page)
        
        self.btn_import = QPushButton("Импорт конфигурации на UG NGFW|DCFW")
        self.btn_import.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import.setFont(btn_font)
        self.btn_import.setFixedWidth(280)
        self.btn_import.setEnabled(False)
        self.btn_import.clicked.connect(self.set_import_page)

        self.btn_import_mc = QPushButton("Импорт конфигурации NGFW|DCFW в\nгруппу шаблонов UG Management Center")
        self.btn_import_mc.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import_mc.setFont(btn_font)
        self.btn_import_mc.setFixedWidth(280)
        self.btn_import_mc.setEnabled(False)
        self.btn_import_mc.clicked.connect(self.set_import_mc_page)

        self.btn_import_mc_template = QPushButton("Импорт группы шаблонов МС на\n UG Management Center")
        self.btn_import_mc_template.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_import_mc_template.setFont(btn_font)
        self.btn_import_mc_template.setFixedWidth(280)
        self.btn_import_mc_template.setEnabled(False)
        self.btn_import_mc_template.clicked.connect(self.set_import_mc_template)
        
        layout = QGridLayout()
        layout.addWidget(self.btn_export, 0, 0, alignment=Qt.AlignmentFlag.AlignTop)
        layout.addWidget(label2, 0, 1)
        layout.addWidget(self.btn_import, 1, 0)
        layout.addWidget(label4, 1, 1)
        layout.addWidget(self.btn_import_mc, 2, 0)
        layout.addWidget(label5, 2, 1)
        layout.addWidget(self.btn_export_mc, 3, 0)
        layout.addWidget(label3, 3, 1)
        layout.addWidget(self.btn_import_mc_template, 4, 0)
        layout.addWidget(label6, 4, 1)
        layout.setHorizontalSpacing(15)
        layout.setVerticalSpacing(15)
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
        """Переходим на страницу экспорта конфигурации из NGFW. Номер в стеке 1."""
        self.parent.stacklayout.setCurrentIndex(1)

    def set_export_mc_page(self):
        """Переходим на страницу экспорта конфигурации из шаблона MC. Номер в стеке 2."""
        self.parent.stacklayout.setCurrentIndex(2)

    def set_import_page(self):
        """Переходим на страницу импорта конфигурации на NGFW. Номер в стеке 3."""
        self.parent.stacklayout.setCurrentIndex(3)

    def set_import_mc_page(self):
        """Переходим на страницу импорта конфигурации NGFW в шаблон МС. Номер в стеке 4."""
        self.parent.stacklayout.setCurrentIndex(4)
        pass

    def set_import_mc_template(self):
        """Переходим на страницу импорта группы шаблонов на МС. Номер в стеке 5."""
        self.parent.stacklayout.setCurrentIndex(5)
        pass

    def enable_buttons(self):
        self.btn_export.setStyleSheet('color: forestgreen; background: white;')
        self.btn_export.setEnabled(True)
        self.btn_export_mc.setStyleSheet('color: forestgreen; background: white;')
        self.btn_export_mc.setEnabled(True)
        self.btn_import.setStyleSheet('color: steelblue; background: white;')
        self.btn_import.setEnabled(True)
        self.btn_import_mc.setStyleSheet('color: steelblue; background: white;')
        self.btn_import_mc.setEnabled(True)
        self.btn_import_mc_template.setStyleSheet('color: steelblue; background: white;')
        self.btn_import_mc_template.setEnabled(True)


class SelectMode(QWidget):
    """Класс для выбора раздела конфигурации для экспорта/импорта."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.selected_points = []
        self.current_path = None
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
        self.label_config_directory = QLabel()
        self.label_config_directory.setAlignment(Qt.AlignmentFlag.AlignLeft)
        self.label_version = QLabel()
        self.label_version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_node_name = QLabel()
        self.label_node_name.setAlignment(Qt.AlignmentFlag.AlignRight)
        hbox_nodeinfo = QHBoxLayout()
        hbox_nodeinfo.addWidget(self.label_config_directory)
        hbox_nodeinfo.addWidget(self.label_version)
        hbox_nodeinfo.addWidget(self.label_node_name)
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

        self.hbox_btn = QHBoxLayout()
        self.hbox_btn.addWidget(self.btn1)
        self.hbox_btn.addStretch()
        self.hbox_btn.addWidget(self.btn2)
        self.hbox_btn.addWidget(self.btn3)
        self.hbox_btn.addStretch()
        self.hbox_btn.addWidget(self.btn4)
        
        vbox = QVBoxLayout()
        vbox.addWidget(self.title)
        vbox.addWidget(frame_nodeinfo)
        vbox.addLayout(hbox_splitter)
        vbox.addSpacerItem(QSpacerItem(1, 3))
        vbox.addLayout(self.hbox_btn)
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
        dialog = LoginWindow(self, mode=mod)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.utm = dialog.utm
            self.product = 'NGFW' if self.utm.product == 'utm' else self.utm.product.upper()
            self.label_node_name.setText(f'{self.utm.node_name}   ')
            self.label_version.setText(f'{self.product} (Версия {self.utm.version})')
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
        Запускаем в потоке GetTemporaryData() для получения часто используемых данных с NGFW.
        """
        if self.thread is None:
            self.disable_buttons()
            self.thread = gtd.GetExportTemporaryData(self.utm) if mode == 'export' else gtd.GetImportTemporaryData(self.utm)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка получения служебных структур данных с {self.product}! {self.thread}')

    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        today = dt.now()
        path_logfile = os.path.join(self.parent.get_config_path(), f'{today:%Y-%m-%d_%M:%S}-{log_file}')
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
        self.current_path = None
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
        elif color in ('BLACK'):
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


class SelectExportMode(SelectMode):
    """Класс для выбора раздела конфигурации для экспорта из NGFW. Номер в стеке 1."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title.setText("<b><font color='green' size='+2'>Экспорт конфигурации из UserGate</font></b>")
        self.btn1.clicked.connect(self.run_page_0)
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
            self.parent.resize(980, 750)
            dialog =  SelectConfigDirectoryWindow(self.parent, mode='export')
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'{self.parent.get_config_path()}  ')
                if self.get_auth(mod='fw'):
                    self.title.setText(f"<b><font color='green' size='+2'>Экспорт конфигурации из UserGate {self.product}</font></b>")
                    self.enable_buttons()
                    self.tree.version = self.utm.float_version
                    self.tree.product = self.utm.product
                    self.tree.waf_license = self.utm.waf_license
                    self.tree.change_items_status_for_export()
                    self.tree.setCurrentItem(self.tree.topLevelItem(0))
                    title = f'Экспорт конфигурации из {self.product} версии {self.utm.version} в каталог "{self.parent.get_config_path()}".'
                    self.add_item_log(f'{title:>100}', color='GREEN')
                    self.add_item_log(f'{"="*100}', color='ORANGE')
                    with open(os.path.join(self.parent.get_config_path(), 'version.json'), 'w') as fh:
                        json.dump({'device': self.product, 'version': self.utm.version, 'float_version': self.utm.float_version}, fh, indent=4)
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
        if not func.check_auth(self):
            self.run_page_0()

        if self.selected_points:
            self.disable_buttons()
            if self.thread is None:
                self.thread = ef.ExportSelectedPoints(
                    self.utm,
                    self.parent.get_config_path(),
                    selected_path=self.current_path,
                    selected_points=self.selected_points
                )
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {key} {self.thread}')
        else:
            func.message_inform(self, "Внимание!", "Вы не выбрали раздел для экспорта.")

    def export_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем экспорт выбранного раздела конфигурации.
        """
        if not func.check_auth(self):
            self.run_page_0()

        all_points = self.tree.select_all_items()

        self.disable_buttons()
        if self.thread is None:
            self.thread = ef.ExportSelectedPoints(self.utm, self.parent.get_config_path(), all_points=all_points)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {key} {self.thread}')


class SelectMcExportMode(QWidget):
    """Класс для экспорта конфигурации NGFW из группы шаблонов MC. Номер в стеке 2."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.utm = None
        self.groups = {}
        self.base_path = {}
        self.group_path = None
        self.selected_group = None
        self.thread = None

        self.title = QLabel()
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title.setFixedHeight(22)
        self.title.setText("<b><font color='green' size='+2'>Экспорт конфигурации из группы шаблонов UserGate Management Center</font></b>")

        frame_nodeinfo = QFrame()
        frame_nodeinfo.setFixedHeight(22)
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
        hbox_info = QHBoxLayout()
        hbox_info.addWidget(self.label_node_name)
        hbox_info.addWidget(self.label_version)
        hbox_info.addWidget(self.label_config_directory)
        hbox_info.setContentsMargins(0, 2, 0, 2)
        frame_nodeinfo.setLayout(hbox_info)

        self.log_list = QListWidget()
        self.tree = TreeGroupTemplates()
        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.log_list)
        hbox_splitter = QHBoxLayout()
        hbox_splitter.addWidget(splitter)

        self.btn1 = QPushButton('Назад')
        self.btn1.setFixedWidth(100)
        self.btn1.setStyleSheet('color: steelblue; background: white;')
        self.btn1.clicked.connect(self.run_page_0)
        self.btn2 = QPushButton('Экспорт выбранной группы шаблонов')
        self.btn2.setFixedWidth(260)
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn2.clicked.connect(self.export_selected_group)
        self.btn3 = QPushButton('Сохранить лог')
        self.btn3.setFixedWidth(130)
        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
        self.btn3.setEnabled(False)
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

        self.parent.stacklayout.currentChanged.connect(self.init_export_widget)
        self.tree.itemSelected.connect(self.get_selected_item)

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
        self.btn3.setStyleSheet('color: steelblue; background: white;')
        self.btn3.setEnabled(True)

    def get_auth(self):
        """Вызываем окно авторизации, если авторизация не прошла, возвращаемся в начальный экран."""
        if self.utm:
            self.utm.logout()
            self.utm = None
        dialog = LoginWindow(self, mode='mc')
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.utm = dialog.utm
            return True
        else:
            return False

    def init_export_widget(self, e):
        """
        При открытии этой вкладки создаём каталог для области.
        Пишем туда файл version.json и затем инициализируем дерево групп шаблонов.
        """
        if e == 2:
            self.parent.resize(980, 750)
            if self.get_auth():
                self.label_node_name.setText(f'  {self.utm.node_name}/{self.utm._login.split("/")[1]}')
                self.label_version.setText(f'MC (версия {self.utm.version})')
                if self.utm.float_version < 7.1:
                    message = f'Экспорт шаблонов Management Center версии мене чем 7.1 не поддерживается. Ваша версия: {self.utm.version}'
                    self.add_item_log(message, color='RED')
                    func.message_inform(self, 'Внимание!', message)
                    self.run_page_0()
                    return

                dialog = SelectConfigDirectoryWindow(self.parent, mode='export', device_type='MC')
                result = dialog.exec()
                if result == QDialog.DialogCode.Accepted:
                    err, msg = self.create_all_dirs()
                    if err:
                        func.message_alert(self, msg, '')
                        self.run_page_0()
                        return

                    with open(os.path.join(self.parent.get_config_path(), 'version.json'), 'w') as fh:
                        json.dump({'device': 'MC', 'node name': self.utm.node_name, 'version': self.utm.version, 'admin': self.utm._login}, fh, indent=4)
                    self.groups['NGFW'] = self.get_ngfw_groups_templates()
                    self.groups['DCFW'] = {}
                    self.groups['EndPoint'] = self.get_endpoint_groups_templates()
                    self.groups['LogAn'] = {}
                    
                    tree_dirs = {key: {key1: [y for y in val1.values()] for key1, val1 in value.items()} for key, value in self.groups.items()}
                    self.tree.init_tree(tree_dirs)
                    self.tree.setHidden(False)
                else:
                    self.run_page_0()
            else:
                self.run_page_0()

    def create_all_dirs(self):
        """"""
        self.base_path['NGFW'] = os.path.join(self.parent.get_config_path(), self.utm._login.split('/')[1], 'NGFW')
        self.base_path['DCFW'] = os.path.join(self.parent.get_config_path(), self.utm._login.split('/')[1], 'DCFW')
        self.base_path['EndPoint'] = os.path.join(self.parent.get_config_path(), self.utm._login.split('/')[1], 'EndPoint')
        self.base_path['LogAn'] = os.path.join(self.parent.get_config_path(), self.utm._login.split('/')[1], 'LogAn')
        try:
            for path in self.base_path.values():
                if not os.path.isdir(path):
                    os.makedirs(path)
        except Exception as err:
            return 1, f'Ошибка создания каталога: "{path}" [{err}]'
        return 0, 'Ok'

    def get_ngfw_groups_templates(self):
        """Для NGFW. Получаем группы шаблонов области и шаблоны каждой группы."""
        groups = {}
        err, result = self.utm.get_device_templates()
        if err:
            func.message_alert(self, 'Не удалось получить список шаблонов', result)
        else:
            realm_templates = {x['id']: x['name'] for x in result}

            err, result = self.utm.get_device_templates_groups()
            if err:
                func.message_alert(self, 'Не удалось получить список групп шаблонов', result)
            else:
                for item in result:
                    groups[item['name']] = {template_id: realm_templates[template_id] for template_id in item['device_templates']}
        return groups

    def get_endpoint_groups_templates(self):
        """Для EndPoint. Получаем группы шаблонов области и шаблоны каждой группы."""
        groups = {}
        err, result = self.utm.get_endpoint_templates()
        if err:
            func.message_alert(self, 'Не удалось получить список шаблонов', result)
        else:
            realm_templates = {x['id']: x['name'] for x in result}

            err, result = self.utm.get_endpoint_templates_groups()
            if err:
                func.message_alert(self, 'Не удалось получить список групп шаблонов', result)
            else:
                for item in result:
                    groups[item['name']] = {template_id: realm_templates[template_id] for template_id in item['endpoint_templates']}
        return groups

    def get_selected_item(self, selected_item):
        """Получаем выбранную группу шаблонов"""
        self.device = selected_item
        if self.tree.selected_path:
            self.selected_group = self.tree.selected_path['group']
            self.group_path = os.path.join(self.base_path[self.device], self.selected_group)
            self.label_config_directory.setText(f'{self.group_path}  ')
            self.btn2.setStyleSheet('color: forestgreen; background: white;')
            self.btn2.setEnabled(True)
        else:
            self.label_config_directory.setText(f'{self.base_path[self.device]}  ')
            self.btn2.setStyleSheet('color: gray; background: gainsboro;')
            self.btn2.setEnabled(False)


    def export_selected_group(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Создаём каталог для выбранной группы шаблонов если в ней есть шаблоны.
        Затем запускаем экспорт выбранной группы шаблонов.
        """
        if not func.check_auth(self):
            self.run_page_0()

        if self.selected_group:
            self.log_list.clear()
            if self.device in ('DCFW', 'EndPoint', 'LogAn'):
                message = f'Экспорт шаблонов "{self.device}" из Management Center пока не реализован.'
                self.add_item_log(message, color='ORANGE')
                func.message_inform(self, 'Внимание', message)
                return

            title = f'Экспорт группы шаблонов "{self.selected_group}" из МС версии {self.utm.version} в каталог "{self.group_path}".'
            self.add_item_log(f'{title:>160}', color='GREEN')
            self.add_item_log(f'{"="*160}', color='ORANGE')
            templates = self.groups[self.device][self.selected_group]
            if templates:
                err, msg = func.create_dir(self.group_path, delete='no')
                if err:
                    func.message_alert(self, msg, '')
                    return
                self.disable_buttons()
                self.tree.setEnabled(False)

                if self.thread is None:
                    self.thread = expmc.ExportAll(
                        self.utm,
                        self.selected_group,
                        self.group_path,
                        templates
                    )
                    self.thread.stepChanged.connect(self.on_step_changed)
                    self.thread.finished.connect(self.on_finished)
                    self.thread.start()
                else:
                    func.message_inform(self, 'Ошибка', f'Произошла ошибка при экспорте! {self.thread}')
            else:
                message = f'В группе шаблонов "{self.selected_group}" отсутствуют шаблоны для экспорта.'
                func.message_inform(self, 'Внимание!', message)
                self.add_item_log(f'{message}\n', color='ORANGE')
        else:
            func.message_inform(self, "Внимание!", "Вы не выбрали группу шаблонов для экспорта.")

    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        today = dt.now()
        path_logfile = os.path.join(self.group_path, f'{today:%Y-%m-%d_%M:%S}-{log_file}')
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
        self.base_path.clear()
        self.group_path = None
        self.groups.clear()
        self.selected_group = None
        self.label_node_name.setText('')
        self.label_version.setText('')
        self.label_config_directory.setText('')
        self.log_list.clear()
        self.tree.clear()
        self.tree.setHidden(True)
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
        self.add_item_log(message, color=color)
        self.log_list.scrollToBottom()
        if color in ('iORANGE', 'iGREEN', 'iRED'):
            func.message_inform(self, 'Внимание!', message)

    def on_finished(self):
        self.thread = None
        self.enable_buttons()
        self.tree.setEnabled(True)


class SelectImportMode(SelectMode):
    """Класс для импорта конфигурации на NGFW и DCFW. Номер в стеке 3."""
    def __init__(self, parent):
        super().__init__(parent)
        self.title.setText("<b><font color='green' size='+2'>Импорт конфигурации на UserGate</font></b>")
        self.btn1.clicked.connect(self.run_page_0)
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
        if e == 3:
            self.parent.resize(980, 750)
            dialog =  SelectConfigDirectoryWindow(self.parent, mode='import')
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'{self.parent.get_config_path()}  ')
                if self.get_auth(mod='fw'):
                    self.title.setText(f"<b><font color='green' size='+2'>Импорт конфигурации на UserGate {self.product}</font></b>")
                    self.enable_buttons()
                    self.tree.version = self.utm.float_version
                    self.tree.product = self.utm.product
                    self.tree.waf_license = self.utm.waf_license
                    self.tree.change_items_status_for_import(self.parent.get_config_path())
                    title = f'Импорт конфигурации из "{self.parent.get_config_path()}" на {self.product} {self.utm.version}.'
                    self.add_item_log(f'{title:>100}', color='GREEN')
                    self.add_item_log(f'{"="*100}', color='ORANGE')
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
                    'adapter_ports': set()
                }
                if not {'DHCP', 'Interfaces'}.isdisjoint(self.selected_points):
                    self.set_arguments(arguments)
                if not func.check_auth(self):
                    self.run_page_0()

                self.thread = ImportNgfwSelectedPoints(
                    self.utm,
                    self.parent.get_config_path(),
                    arguments,
                    selected_path=self.current_path,
                    selected_points=self.selected_points
                )
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

        else:
            func.message_inform(self, "Внимание!", "Нет данных для импорта.\n Выбранный раздел пуст. ")

    def import_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт всей конфигурации.
        """
        if not func.check_auth(self):
            self.run_page_0()

        all_points = self.tree.select_all_items()
        if not all_points:
            func.message_inform(self, "Внимание!", "Нет данных для импорта.")
            return
        
        arguments = {
            'ngfw_ports': '',
            'dhcp_settings': '',
            'ngfw_vlans': '',
            'new_vlans': '',
            'iface_settings': '',
            'adapter_ports': set()
        }
        for item in all_points:
            self.current_path = os.path.join(self.parent.get_config_path(), item['path'])
            self.selected_points = item['points']
            if not {'DHCP', 'Interfaces'}.isdisjoint(self.selected_points):
                self.set_arguments(arguments)

        if self.thread is None:
            self.disable_buttons()
            self.thread = ImportNgfwSelectedPoints(self.utm, self.parent.get_config_path(), arguments, all_points=all_points)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')

        self.tree.setCurrentItem(self.tree.topLevelItem(0))

    def set_arguments(self, arguments):
        """Заполняем структуру параметров для импорта."""
        err, ngfw_interfaces = self.utm.get_interfaces_list()
        if err:
            arguments['ngfw_ports'] = 1
            arguments['dhcp_settings'] = f'RED|    {ngfw_interfaces}\nНастойки DHCP не будут импортированы.'
            arguments['ngfw_vlans'] = 1
            arguments['new_vlans'] = f'RED|    {ngfw_interfaces}\nИнтерфейсы не будут импортированы.'
            return

        if 'DHCP' in self.selected_points:
            err, result = self.import_dhcp(ngfw_interfaces)
            arguments['ngfw_ports'] = err
            arguments['dhcp_settings'] = result
        if 'Interfaces' in self.selected_points:
            if self.utm.version_hight == 5:
                arguments['ngfw_vlans'] = 2
                arguments['new_vlans'] = f'bRED|    VLAN нельзя импортировать на NGFW версии {self.utm.version}.'
            else:
                iface_path = os.path.join(self.current_path, 'Interfaces')
                json_file = os.path.join(iface_path, 'config_interfaces.json')
                err, data = func.read_json_file(self, json_file)
                if err:
                    arguments['ngfw_vlans'] = err
                    arguments['new_vlans'] = data
                    return
                arguments['iface_settings'] = data

                err, result = self.utm.get_zones_list()
                if err:
                    arguments['ngfw_vlans'] = err
                    arguments['new_vlans'] = f'RED|    {result}'
                    return
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
                    if item["name"] == management_port:
                        continue
                    if item['kind'] not in ('bridge', 'bond', 'adapter') or item['master']:
                        continue
                    else:
                        if item['kind'] == 'adapter':
                            arguments['adapter_ports'].add(item['name'])
                    interfaces_list.append(item['name'])

                err, result = self.create_vlans(interfaces_list, zones, data)
                if err:
                    arguments['ngfw_vlans'] = err
                    arguments['new_vlans'] = result
                else:
                    arguments['ngfw_vlans'] = ngfw_vlans
                    arguments['new_vlans'] = result

    def create_vlans(self, interfaces_list, zones, data):
        """Импортируем интерфесы VLAN. Нельзя использовать интерфейсы Management и slave."""
        new_vlans = {item['vlan_id']: {'zone': item['zone_id'], 'port': item['link']} for item in data if item['kind'] == 'vlan'}
        if not new_vlans:
            return 3, 'LBLUE|    Нет VLAN для импорта.'

        dialog = VlanWindow(self, vlans=new_vlans, ports=interfaces_list, zones=zones)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            for key, value in dialog.combo_vlans.items():
                new_vlans[key]['port'] = value['port'].currentText()
                new_vlans[key]['zone'] = value['zone'].currentText()
            return 0, new_vlans
        else:
            return 3, 'LBLUE|    Импорт настроек интерфейсов отменён пользователем.'

    def import_dhcp(self, ngfw_interfaces):
        dhcp_path = os.path.join(self.current_path, 'DHCP')
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
    """Класс для импорта конфигурации NGFW и DCFW в группу шаблонов МС. Номер в стеке 4."""
    def __init__(self, parent):
        super().__init__(parent)
        self.group_name = None
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
        Запускаем в потоке mctd.GetImportTemporaryData() для получения часто используемых данных с MC.
        """
        if self.thread is None:
            self.disable_buttons()
            if self.device == 'NGFW':
                self.thread = GetMcNgfwTemporaryData(self.utm, self.templates)
            else:
                self.thread = GetMcDcfwTemporaryData(self.utm, self.templates)
            self.thread.stepChanged.connect(self.on_step_changed)
            self.thread.finished.connect(self.on_finished)
            self.thread.start()
        else:
            func.message_inform(self, 'Ошибка', f'Произошла ошибка получения служебных структур данных с МС! {self.thread}')


    def init_import_widget(self, e):
        """
        При открытии этой вкладки:
        1. Авторизуемся на МС.
        2. Выбираем каталог с конфигурацией для импорта.
        3. Выбираем группу шаблонов для импорта.
        4. Выбирает шаблон из группы шаблонов.
        """
        if e == 4:
            self.device = None
            self.parent.resize(980, 750)
            dialog =  SelectConfigDirectoryWindow(self.parent, mode='import')
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.label_config_directory.setText(f'    From: {self.parent.get_config_path()}')
                if self.get_auth(mod='mc'):
                    if self.utm.float_version < 7.1:
                        message = f'Импорт на Management Center версии менее чем 7.1 не поддерживается. Ваша версия: {self.utm.version}'
                        self.add_item_log(message, color='RED')
                        func.message_inform(self, 'Внимание!', message)
                        self.run_page_0()
                        return

                    self.current_realm_name = self.utm._login.split('/')[1]

                    groups_dialog = SelectMcGroupTemplates(self, self.parent)
                    groups_result = groups_dialog.exec()
                    if groups_result == QDialog.DialogCode.Accepted:
                        self.group_name = groups_dialog.current_group_name
                        self.templates_ids = groups_dialog.templates
                        self.device = groups_dialog.device
                        # Инициализируем дерево разделов конфигурации
                        if self.device == 'DCFW':
                            self.tree.product = 'dcfw'
                            self.tree.version = 8.0
                        else:
                            self.tree.product = 'ngfw'
                            self.tree.version = self.utm.float_version
                        self.tree.waf_license = False
                        self.tree.change_items_status_for_import(self.parent.get_config_path())
                    else:
                        self.run_page_0()
                        return

                    self.label_node_name.setText(f'Output: {self.utm.node_name}/{self.current_realm_name}/{self.device}   ')
                    # Выбираем шаблон из группы шаблонов для импорта.
                    self.select_template()
                else:
                    self.run_page_0()
            else:
                self.run_page_0()


    def select_template(self):
        """Выбираем шаблон из группы шаблонов для импорта."""
        if not func.check_auth(self):
            self.run_page_0()

        template_dialog = SelectMcDestinationTemplate(self.utm, self.parent, self.group_name, self.device, templates=self.templates_ids)
        template_result = template_dialog.exec()
        if template_result == QDialog.DialogCode.Accepted:
            self.template_name = template_dialog.current_template_name
            self.template_id = template_dialog.templates[self.template_name]
            self.templates = {uid: name for name, uid in template_dialog.templates.items()}

            title1 = f'Импорт конфигурации в шаблон "{self.group_name}/{self.template_name}"'
            title2 = f'на МС в раздел "{self.device}" области "{self.current_realm_name}".'
            self.log_list.clear()
            self.add_item_log(f'{title1:>100}', color='GREEN')
            self.add_item_log(f'{title2:>100}', color='GREEN')
            self.add_item_log(f'{"="*100}', color='ORANGE')
            self.init_temporary_data()
            self.enable_buttons()
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
            }
            node_name = 'node_1'
            if not {'Interfaces', 'Gateways', 'DHCP', 'VRF', 'UserIDagent', 'SNMPParameters'}.isdisjoint(self.selected_points):
                node_name, ok = QInputDialog.getItem(self, 'Выбор идентификатора узла', 'Выберите идентификатор узла кластера', self.id_nodes)
                if not ok:
                    func.message_inform(self, 'Ошибка', f'Импорт прерван, так как не указан идентификатор узла.')
                    return
                if 'DHCP' in self.selected_points:
                    self.set_arguments(node_name, arguments)
            if self.thread is None:
                self.disable_buttons()
                if self.device == 'NGFW':
                    self.thread = ImportMcNgfwSelectedPoints(
                        self.utm,
                        self.parent.get_config_path(),
                        self.template_id,
                        self.templates,
                        arguments,
                        node_name,
                        selected_path = self.current_path,
                        selected_points = self.selected_points
                    )
                else:
                    self.thread = ImportMcDcfwSelectedPoints(
                        self.utm,
                        self.parent.get_config_path(),
                        self.template_id,
                        self.templates,
                        arguments,
                        node_name,
                        selected_path = self.current_path,
                        selected_points = self.selected_points
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

        node_name = 'node_1'
        node_name, ok = QInputDialog.getItem(self, 'Выбор идентификатора узла', 'Выберите идентификатор узла кластера', self.id_nodes)
        if not ok:
            func.message_inform(self, 'Ошибка', f'Импорт прерван, так как не указан идентификатор узла.')
            return

        all_points = self.tree.select_all_items()
        arguments = {
            'ngfw_ports': [],
            'dhcp_settings': [],
        }
        self.tree.set_current_item()

        if self.thread is None:
            self.disable_buttons()
            if self.device == 'NGFW':
                self.thread = ImportMcNgfwSelectedPoints(
                                self.utm,
                                self.parent.get_config_path(),
                                self.template_id,
                                self.templates,
                                arguments,
                                node_name,
                                all_points=all_points
                            )
            else:
                self.thread = ImportMcDcfwSelectedPoints(
                                self.utm,
                                self.parent.get_config_path(),
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
            if self.device == 'NGFW':
                err, result = self.utm.get_template_interfaces_list(uid)
            else:
                err, result = self.utm.get_dcfw_template_interfaces(uid)
            if err:
                func.message_alert(self, 'Произошла ошибка при получении списка интерфейсов.\nИмпорт настроек DHCP отменён.', result)
                return
            for item in result:
                if item['kind'] not in ('bridge', 'bond', 'adapter', 'vlan') or item['master']:
                    continue
                if item['node_name'] == node:   # Только для нужного уза кластера.
                    mc_interfaces.append({'name': item['name'], 'kind': item['kind'], 'vlan_id': item.get('vlan_id', 0)})

        if not mc_interfaces:
            msg = f'Для "{node}" отсутствуют интерфейсы.\nSubnets DHCP не будут импортированы.'
            func.message_inform(self, 'Внимание!', msg)
            arguments['ngfw_ports'] = 3
            arguments['dhcp_settings'] = f'ORANGE|    Импорт настроек DHCP отменён из-за отсутствия портов на узле "{node}" шаблона.'
            return
 
        err, result = self.import_dhcp(mc_interfaces)
        arguments['ngfw_ports'] = err
        arguments['dhcp_settings'] = result

    def import_dhcp(self, mc_interfaces):
        json_file = os.path.join(self.current_path, 'DHCP', 'config_dhcp_subnets.json')
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


class SelectMcTemplateGroupImport(QWidget):
    """Класс для импорта ранее экспортированной группы шаблонов МС в область МС. Номер в стеке 5."""
    def __init__(self, parent):
        super().__init__()
        self.parent = parent
        self.utm = None
        self.device = 'NGFW'
        self.base_path = {}
        self.groups = {}
        self.selected_group = None
        self.selected_templates = []
        self.thread = None
        self.tmp_list = []

        self.title = QLabel("<b><font color='green' size='+2'>Импорт групп шаблонов МС на UserGate Management Center</font></b>")
        self.title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.title.setFixedHeight(22)

        frame_nodeinfo = QFrame()
        frame_nodeinfo.setFixedHeight(22)
        frame_nodeinfo.setStyleSheet(
            'background-color: #2690c8; '
            'color: white; font-size: 12px; font-weight: bold; '
            'border-radius: 4px; padding: 0px; margin: 0px;'
        )
        self.label_node_name = QLabel()
        self.label_node_name.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.label_version = QLabel()
        self.label_version.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.label_config_path = QLabel(f'  Input: ./{self.parent.mc_base_path}')
        self.label_config_path.setAlignment(Qt.AlignmentFlag.AlignLeft)
        hbox_info = QHBoxLayout()
        hbox_info.addWidget(self.label_config_path)
        hbox_info.addWidget(self.label_version)
        hbox_info.addWidget(self.label_node_name)
        hbox_info.setContentsMargins(0, 2, 0, 2)
        frame_nodeinfo.setLayout(hbox_info)

        self.log_list = QListWidget()
        self.tree = TreeGroupTemplates(child_disabled=False)
        splitter = QSplitter()
        splitter.addWidget(self.tree)
        splitter.addWidget(self.log_list)
        hbox_splitter = QHBoxLayout()
        hbox_splitter.addWidget(splitter)

        self.btn1 = QPushButton('Назад')
        self.btn1.setFixedWidth(100)
        self.btn1.setStyleSheet('color: steelblue; background: white;')
        self.btn1.clicked.connect(self.run_page_0)

        self.btn2 = QPushButton("Импорт выбранной позиции")
        self.btn2.setFixedWidth(200)
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn2.clicked.connect(self.import_selected_templates)

        self.btn3 = QPushButton("Импортировать все группы раздела")
        self.btn3.setFixedWidth(240)
        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
        self.btn3.setEnabled(False)
        self.btn3.clicked.connect(self.import_all)

        self.btn4 = QPushButton("Сохранить лог")
        self.btn4.setFixedWidth(120)
        self.btn4.setStyleSheet('color: gray; background: gainsboro;')
        self.btn4.setEnabled(False)
        self.btn4.clicked.connect(lambda: self._save_logs('import.log'))

        self.btn_ngfw = QRadioButton('NGFW')
        self.btn_ngfw.setChecked(True)
        self.btn_dcfw = QRadioButton('DCFW')
        self.btn_dcfw.setEnabled(False)
        self.button_group = QButtonGroup()
        self.button_group.addButton(self.btn_ngfw)
        self.button_group.addButton(self.btn_dcfw)
        self.button_group.buttonClicked.connect(self._radio_button_clicked)

        hbox_btn = QHBoxLayout()
        hbox_btn.addWidget(self.btn1)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn_ngfw)
        hbox_btn.addWidget(self.btn_dcfw)
        hbox_btn.addStretch()
        hbox_btn.addWidget(self.btn2)
        hbox_btn.addStretch()
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
        self.parent.stacklayout.currentChanged.connect(self.init_import_widget)
        self.tree.itemSelected.connect(self.get_selected_item)


    def disable_buttons(self):
        self.btn2.setStyleSheet('color: gray; background: gainsboro;')
        self.btn2.setEnabled(False)
        self.btn3.setStyleSheet('color: gray; background: gainsboro;')
        self.btn3.setEnabled(False)
        self.btn4.setStyleSheet('color: gray; background: gainsboro;')
        self.btn4.setEnabled(False)


    def enable_buttons(self):
        self.btn2.setStyleSheet('color: forestgreen; background: white;')
        self.btn2.setEnabled(True)
        self.btn3.setStyleSheet('color: forestgreen; background: white;')
        self.btn3.setEnabled(True)


    def get_auth(self):
        """Вызываем окно авторизации, если авторизация не прошла, возвращаемся в начальный экран."""
        if self.utm:
            self.utm.logout()
            self.utm = None
        dialog = LoginWindow(self, mode='mc')
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self.utm = dialog.utm
            return True
        else:
            return False


    def init_import_widget(self, e):
        """
        При открытии этой вкладки выбираем каталог с конфигурацией для импорта.
        """
        if e == 5:
            self.parent.resize(980, 750)
            dialog = SelectDirectoryAndRealm(self.parent)
            result = dialog.exec()
            if result == QDialog.DialogCode.Accepted:
                self.list_tree_groups()
                self.tree.init_tree(self.groups)
                self.tree.setHidden(False)
                if self.get_auth():
                    self.current_realm_name = self.utm._login.split('/')[1]
                    self.label_version.setText(f'MC (версия {self.utm.version})')
                    if self.utm.float_version < 7.1:
                        message = f'Импорт на Management Center версии менее чем 7.1 не поддерживается. Ваша версия: {self.utm.version}'
                        self.add_item_log(message, color='RED')
                        func.message_inform(self, 'Внимание!', message)
                        self.run_page_0()
                        return
                else:
                    self.run_page_0()
            else:
                self.run_page_0()


    def list_tree_groups(self):
        """Из каталога области получаем дерево групп и шаблонов в группах"""
        for device in ('NGFW', 'DCFW', 'EndPoint', 'LogAn'):
            self.base_path[device] = os.path.join(self.parent.get_config_path(), device)
            self.groups[device] = {}
            templates = []
            for item in os.walk(self.base_path[device]):
                for group in sorted(item[1]):
                    for templates in os.walk(os.path.join(self.base_path[device], group)):
                        self.groups[device][group] = templates[1]
                        break
                break


    def get_selected_item(self, selected_item):
        """Получаем из дерева каталогов группу шаблонов и шаблоны в этой группе"""
        self.device = selected_item
        if self.device in ('EndPoint', 'LogAn'):
            self.new_device = self.device
            self.btn_ngfw.setEnabled(False)
            self.btn_dcfw.setEnabled(False)
        else:
            self.new_device = 'NGFW' if self.btn_ngfw.isChecked() else 'DCFW'
            self.btn_ngfw.setEnabled(True)
            self.btn_dcfw.setEnabled(True)
        if self.utm:
            if self.tree.selected_path:
                self.selected_group = self.tree.selected_path['group']
                self.selected_templates = self.tree.selected_path['points']
                self.label_config_path.setText(f'  Input: ./{self.base_path[self.device]}/{self.selected_group}')
                self.label_node_name.setText(f'Output: {self.utm.node_name}/{self.current_realm_name}/{self.new_device}  ')
                title, title1, color = self.prepare_records()
                self.enable_buttons()
            else:
                self.selected_group = None
                self.selected_templates = []
                self.label_config_path.setText(f'  Input: ./{self.parent.get_config_path()}/{self.device}')
                self.label_node_name.setText(f'Output: {self.utm.node_name}/{self.current_realm_name}/{self.new_device}  ')
                title = 'Выберите шаблон или группу шаблонов для импорта.'
                title1 = ''
                color = 'BLUE'
                self.disable_buttons()
            self.log_list.clear()
            self.add_item_log(f'{title:>100}', color=color)
            self.add_item_log(f'{title1:>100}', color=color)
            self.add_item_log(f'{"="*100}', color='ORANGE')
#        print(self.selected_group, self.selected_templates)


    def _radio_button_clicked(self, button):
        self.new_device = button.text()
        self.label_node_name.setText(f'Output: {self.utm.node_name}/{self.current_realm_name}/{self.new_device}  ')
        if self.tree.selected_path:
            title, title1, color = self.prepare_records()
            self.log_list.clear()
            self.add_item_log(f'{title:>100}', color=color)
            self.add_item_log(f'{title1:>100}', color=color)
            self.add_item_log(f'{"="*100}', color='ORANGE')


    def prepare_records(self):
        if self.selected_templates:
            tmp_string = 'шаблонов' if len(self.selected_templates) > 1 else 'шаблона'
            title = f'Импорт {tmp_string} "{'", "'.join(self.selected_templates)}" группы шаблонов "{self.device}/{self.selected_group}"'
            title1 = f'на МС в раздел "{self.new_device}" области "{self.current_realm_name}".'
            color = 'GREEN'
        else:
            title = f'В группе "{self.device}/{self.selected_group}" нет шаблонов для импорта.'
            title1 = f'На МС в разделе "{self.new_device}" области "{self.current_realm_name}" будет создана пустая группа шаблонов.'
            color = 'RED'
        return title, title1, color


    def import_selected_templates(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт выбранной группы шаблонов (все шаблоны группы) или отдельного шаблона группы.
        """
        if self.new_device in ('EndPoint', 'LogAn'):
            message = f'Импорт раздела "{self.new_device}" пока не реализован.'
            func.message_inform(self, 'Внимание!', message)
        elif self.new_device == 'DCFW' and self.utm.float_version < 7.4:
            message = f'Импорт раздела "{self.new_device}" не возможен для вашей версии МС.'
            func.message_inform(self, 'Внимание!', message)
        else:
            if not func.check_auth(self):
                self.run_page_0()
            if self.thread is None:
                self.disable_buttons()
                if self.new_device == 'NGFW':
#                    print('\nself.device: ', self.device)
#                    print('new_device: ', self.new_device)
#                    print('base_path: ', self.base_path[self.device])
#                    print('selected_group: ', self.selected_group)
#                    print('selected_templates: ', self.selected_templates)
                    self.thread = ImportMcNgfwTemplates(
                        self.utm,
                        base_path = self.base_path[self.device],
                        selected_group = self.selected_group,
                        selected_templates = self.selected_templates
                    )
                elif self.new_device == 'DCFW':
#                    print('\nself.device: ', self.device)
#                    print('new_device: ', self.new_device)
#                    print('base_path: ', self.base_path[self.device])
#                    print('selected_group: ', self.selected_group)
#                    print('selected_templates: ', self.selected_templates)
                    self.thread = ImportMcDcfwTemplates(
                        self.utm,
                        base_path = self.base_path[self.device],
                        selected_group = self.selected_group,
                        selected_templates = self.selected_templates
                    )
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')


    def import_all(self):
        """
        Проверяем что авторизация не протухла. Если протухла, логинимся заново.
        Затем запускаем импорт всех групп выбранного раздела конфигурации.
        """
        if self.new_device in ('EndPoint', 'LogAn', 'DCFW'):
            message = f'Импорт раздела "{self.new_device}" пока не реализован.'
            func.message_inform(self, 'Внимание!', message)
        elif self.new_device == 'DCFW' and self.utm.float_version < 7.4:
            message = f'Импорт раздела "{self.new_device}" не возможен для вашей версии МС.'
            func.message_inform(self, 'Внимание!', message)
        else:
            if not func.check_auth(self):
                self.run_page_0()
            if self.thread is None:
                self.disable_buttons()
                self.thread = ImportMcNgfwTemplates(
                    self.utm,
                        device_type = self.new_device,
                        base_path = self.base_path[self.device],
                        device_groups = self.groups[self.device],
                        selected_group = self.selected_group,
                        selected_templates = self.selected_templates
                )
                self.thread.stepChanged.connect(self.on_step_changed)
                self.thread.finished.connect(self.on_finished)
                self.thread.start()
            else:
                func.message_inform(self, 'Ошибка', f'Произошла ошибка при запуске процесса импорта! {self.thread}')


    def run_page_0(self):
        """Возвращаемся на стартовое окно"""
        if self.utm:
            self.utm.logout()
        self.utm = None
        self.device = 'NGFW'
        self.base_path.clear()
        self.groups.clear()
        self.selected_group = None
        self.selected_templates = []
        self.label_config_path.setText(f'  Input: ./{self.parent.mc_base_path}')
        self.label_node_name.setText('')
        self.label_version.setText('')
        self.log_list.clear()
        self.tree.clear()
        self.tree.setHidden(True)
        if os.path.isfile('temporary_data.bin'):
            os.remove('temporary_data.bin')
        self.parent.stacklayout.setCurrentIndex(0)


    def add_item_log(self, message, color='BLACK'):
        """Добавляем запись лога в log_list."""
        i = QListWidgetItem(message)
        i.setForeground(QColor(cs.color.get(color, 'RED')))
        self.log_list.addItem(i)


    def _save_logs(self, log_file):
        """Сохраняем лог из log_list в файл "log_file" в текущей директории"""
        today = dt.now()
        path_logfile = os.path.join(self.group_path, f'{today:%Y-%m-%d_%M:%S}-{log_file}')
        list_items = [self.log_list.item(row).text() for row in range(self.log_list.count())]
        with open(path_logfile, 'w') as fh:
            print(*list_items, sep='\n', file=fh)
            fh.write('\n')
        func.message_inform(self, 'Сохранение лога', f'Лог сохранён в файл "{path_logfile}".')


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
        self.thread = None
        self.enable_buttons()
        self.tree.setEnabled(True)


class SelectMcGroupTemplates(QDialog):
    """Базовый класс для выбора группы шаблонов MC."""
    def __init__(self, parent, main_window):
        super().__init__(main_window)
        self.main_window = main_window
        self.parent = parent
        self.device = None
        self.groups = {}
        self.current_group_name = None
        self.templates = None
        self.setWindowTitle("Выбор группы шаблонов MC")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
#        self.setFixedHeight(200)

        self.label = QLabel("<b><font color='green'>Выберите раздел и<br>группу шаблонов Management Center.</font></b><br>")
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

        self.btn_ngfw = QRadioButton('NGFW')
        self.btn_dcfw = QRadioButton('DCFW')
        self.button_group = QButtonGroup()
        self.button_group.addButton(self.btn_ngfw)
        self.button_group.addButton(self.btn_dcfw)
        self.button_group.buttonClicked.connect(self._radio_button_clicked)

        self.btn_hbox = QHBoxLayout()
        self.btn_hbox.addWidget(self.btn_enter)
        self.btn_hbox.addStretch()
        self.btn_hbox.addWidget(self.btn_ngfw)
        self.btn_hbox.addWidget(self.btn_dcfw)
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

    def disable_buttons(self):
        self.btn_enter.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_enter.setEnabled(False)
        if self.parent.utm.float_version < 7.4:
            self.btn_dcfw.setEnabled(False)
            self.btn_ngfw.setChecked(True)
            self._radio_button_clicked(self.btn_ngfw)

    def _radio_button_clicked(self, button):
        self.device = button.text()
        self.add_groups_items()

    def _send_accept(self):
        self.accept()

    def add_groups_items(self):
        """При открытии этого диалога получаем с МС список групп шаблонов и заполняем список выбора групп."""
        if self.device == 'NGFW':
            err, result = self.parent.utm.get_device_templates_groups()
        else:
            err, result = self.parent.utm.get_dcfw_device_templates_groups()
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
    """Диалоговое окно для выбора шаблона MC для импорта."""
    def __init__(self, utm, main_window, group_name, device, templates=None):
        super().__init__(main_window)
        self.main_window = main_window
        self.utm = utm
        self.group_name = group_name
        self.device = device
        self.group_templates = templates
        self.templates = {}
        self.current_template_name = None
        self.setWindowTitle("Выбор шаблона MC для импорта")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        self.label = QLabel(f'<b><font color="green">Выберите шаблон для импорта конфигурации.</font></b><br>Шаблоны группы: <font color="blue">"{self.group_name}"</font>')
        self.label.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.templates_list = QListWidget()

        self.btn_enter = QPushButton("Ввод")
        self.btn_enter.setStyleSheet('color: steelblue; background: white;')
        self.btn_enter.setFixedWidth(80)
        self.btn_enter.clicked.connect(self._send_accept)

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
        self.vbox.addWidget(self.templates_list)
        self.vbox.addSpacerItem(QSpacerItem(3, 5))
        self.vbox.addLayout(self.btn_hbox)
        self.setLayout(self.vbox)

        self.templates_list.currentTextChanged.connect(self.select_dest_template)
        self.disable_buttons()
        self.add_device_template_items()

    def disable_buttons(self):
        self.btn_enter.setStyleSheet('color: gray; background: gainsboro;')
        self.btn_enter.setEnabled(False)

    def _send_accept(self):
        self.accept()

    def add_device_template_items(self):
        """При открытии этого диалога получаем с МС список шаблонов устройств и заполняем список выбора шаблонов."""
        self.templates_list.clear()
        for template_id in self.group_templates:
            if self.device == 'NGFW':
                err, result = self.utm.fetch_device_template(template_id)
            else:
                err, result = self.utm.fetch_dcfw_device_template(template_id)
            if err:
                func.message_alert(self, f'Не удалось получить список шаблонов группы "{self.group_name}".', result)
            else:
                self.templates_list.addItem(result['name'])
                self.templates[result['name']] = result['id']
            self.templates_list.setCurrentRow(0)

    def select_dest_template(self, item_text):
        self.current_template_name = item_text
        self.btn_enter.setStyleSheet('color: steelblue; background: white;')
        self.btn_enter.setEnabled(True)


class SelectConfigDirectoryWindow(QDialog):
    """Диалоговое окно выбора каталога для экспорта/импорта конфигурации"""
    def __init__(self, parent, mode, device_type='NGFW'):
        super().__init__(parent)
        self.main_window = parent
        self.mode = mode
        self.device_type = device_type
        self.setWindowTitle("Выбор каталога")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)
        self.base_path = None

        match self.device_type:
            case 'NGFW':
                self.base_path = self.main_window.ngfw_base_path
            case 'MC':
                self.base_path = self.main_window.mc_base_path
        list_dir = os.listdir(self.base_path)
        self.config_directory = QComboBox()
        self.config_directory.addItems(sorted(list_dir))
        if self.mode == 'export':
            self.setFixedHeight(160)
            self.config_directory.setEditable(True)
            text = (
                '<b><font color="green">Введите название каталога для экспорта конфигурации.<br> '
                f'Каталог будет создан в текущей директории в каталоге {self.base_path}.<br>Или выберите из уже существующих.</font></b>'
            )
        else:
            self.setFixedHeight(120)
            self.config_directory.setEditable(False)
            text = "<b><font color='green'>Выберите каталог с импортируемой конфигурацией.</b><br>"

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
            self.main_window.set_config_path(self.base_path, self.config_directory.currentText())
            if self.mode == 'import':
                if not os.listdir(self.main_window.get_config_path()):
                    message = f'Каталог {self.main_window.get_config_path()} пуст. Выберите другой каталог.'
                    func.message_inform(self, 'Внимание!', message)
                    return
            else:
                err, msg = func.create_dir(self.main_window.get_config_path(), delete='no')
                if err:
                    self.main_window.del_config_path()
                    func.message_alert(self, msg, '')
                    return
            self.accept()


class SelectDirectoryAndRealm(QDialog):
    """
    Диалоговое окно выбора каталога и области в каталоге для импорта групп шаблонов в МС.
    Используется в SelectMcTemplateGroupImport.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.main_window = parent
        self.setWindowTitle("Выбор каталога и области")
        self.setWindowFlags(Qt.WindowType.WindowTitleHint|Qt.WindowType.CustomizeWindowHint|Qt.WindowType.Dialog|Qt.WindowType.Window)

        title = QLabel("<b><font color='green'>Выберите каталог и область МС в каталоге.")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)

        list_dir = os.listdir(self.main_window.mc_base_path)
        self.config_dir = QComboBox()
        self.config_dir.addItems(sorted(list_dir))
        self.config_dir.setEditable(False)
        self.config_dir.currentTextChanged.connect(self._set_config_realm)

        self.config_realm = QComboBox()
        self.config_realm.setEditable(False)
        if self.config_dir.currentText():
            for i in os.walk(os.path.join(self.main_window.mc_base_path, self.config_dir.currentText())):
                self.config_realm.addItems(sorted(i[1]))
                break
        
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
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addWidget(self.config_dir)
        layout.addWidget(self.config_realm)
        layout.addSpacerItem(QSpacerItem(1, 8))
        layout.addLayout(btn_hbox)
        self.setLayout(layout)

    def _send_accept(self):
        if self.config_dir.currentText() and self.config_realm.currentText():
            self.config_path = os.path.join(self.config_dir.currentText(), self.config_realm.currentText())
            self.main_window.set_config_path(self.main_window.mc_base_path, self.config_path)
            self.accept()


    def _set_config_realm(self, string):
        self.config_realm.clear()
        for i in os.walk(os.path.join(self.main_window.mc_base_path, string)):
            self.config_realm.addItems(sorted(i[1]))
            break


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
#        self.vlans = {item: {'port': '', 'zone': ''} for item in vlans}
        self.vlans = vlans
        self.combo_vlans = {item: {'port': '', 'zone': ''} for item in sorted(vlans)}
        title = QLabel(f"<b><font color='green'>Настройка добавляемых интерфейсов VLAN</font></b>")
        title.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        text1 = QLabel(
            "Для импортируемых VLAN установите порт и зону. Если порт не будет "
            "назначен, VLAN не будет импортирован. Если вы используете интерфейс "
            "bond который в данный момент не существует, он будет создан."
        )
        text1.setWordWrap(True)

        grid_title_hbox = QHBoxLayout()
        grid_title_hbox.addStretch(1)
        grid_title_hbox.addWidget(ColorLabel(f'Vlan', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel(f'Порт', 'blue'))
        grid_title_hbox.addStretch(5)
        grid_title_hbox.addWidget(ColorLabel(f'Зона', 'blue'))
        grid_title_hbox.addStretch(10)

        for key, value in self.vlans.items():
            if value['port'] not in ports and value['port'].startswith('bond'):
                ports.append(value['port'])

        grid_layout = QGridLayout()
        for i, vlan in enumerate(self.vlans.keys()):
            self.combo_vlans[vlan]['port'] = QComboBox()
            self.combo_vlans[vlan]['port'].addItems(ports)

            if self.vlans[vlan]['port'] in ports:
                self.combo_vlans[vlan]['port'].setCurrentText(self.vlans[vlan]['port'])

            self.combo_vlans[vlan]['zone'] = QComboBox()
            self.combo_vlans[vlan]['zone'].addItems(zones)
            if self.vlans[vlan]['zone'] in zones:
                self.combo_vlans[vlan]['zone'].setCurrentText(self.vlans[vlan]['zone'])
            grid_layout.addWidget(QLabel(f'VLAN {vlan}'), i, 0)
            grid_layout.addWidget(self.combo_vlans[vlan]['port'], i, 1)
            grid_layout.addWidget(self.combo_vlans[vlan]['zone'], i, 2)

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


class TreeGroupTemplates(QTreeWidget):
    itemSelected = pyqtSignal(str)
    def __init__(self, child_disabled=True):
        super().__init__()
        self.setStyleSheet(cs.Style.MainTree)
        self.setHeaderHidden(True)
        self.setIndentation(10)
        self.setHidden(True)
        self.child_status = child_disabled
        self.child_color = QColor('#556682') if self.child_status else QColor('#2f4f4f')
        self.selected_path = {}
        self.itemSelectionChanged.connect(self.select_item)

    def init_tree(self, data):
        tree_head_font = QFont("Noto Sans", pointSize=10, weight=300)
        items = []
        for key, values in data.items():
            item = QTreeWidgetItem([key])
            item.setForeground(0, Qt.GlobalColor.darkRed)
            item.setFont(0, tree_head_font)
            for key1, val1 in values.items():
                child1 = QTreeWidgetItem([key1])
                child1.setForeground(0, Qt.GlobalColor.darkBlue)
                item.addChild(child1)
                for val2 in val1:
                    child2 = QTreeWidgetItem([val2])
                    child2.setDisabled(self.child_status)
                    child2.setForeground(0, self.child_color)
                    child1.addChild(child2)
            items.append(item)
        self.insertTopLevelItems(0, items)
        self.expandAll()
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Expanding)
        self.setCurrentItem(self.topLevelItem(0))

    def select_item(self):
        if self.selectedItems():
            selected_item = self.selectedItems()[0]
            if selected_item.parent():
                parent = selected_item.parent().text(0)
                if parent in {'NGFW', 'DCFW', 'EndPoint', 'LogAn'}:
                    device = parent
                else:
                    device = selected_item.parent().parent().text(0)
                item_childs = []
                for i in range(selected_item.childCount()):
                    try:
                        if not selected_item.child(i).isHidden():
                            child_text = selected_item.child(i).text(0)
                            item_childs.append(child_text)
                    except KeyError:
                        pass
                if parent == device:
                    self.selected_path = {'group': selected_item.text(0), 'points': item_childs}
                else:
                    item_childs.append(selected_item.text(0))
                    self.selected_path = {'group': parent, 'points': item_childs}
            else:
                device = selected_item.text(0)
                self.selected_path.clear()
            self.itemSelected.emit(device)


class MainTree(QTreeWidget):
    itemSelected = pyqtSignal(dict)
    def __init__(self):
        super().__init__()
        self.setStyleSheet(cs.Style.MainTree)
        self.version = None     # Версия NGFW
        self.product = None     # Тип продукта (ngfw, dcfw, mc)
        self.waf_license = False

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
                "WCCP", "Маршруты", "OSPF", "BGP", 'WAF', "Системные WAF-правила", 'WAF-профили', 'Персональные WAF-слои', "Политики BYOD",
                "Политики безопасности", "Фильтрация контента", "Веб-безопасность", "Инспектирование туннелей", "Инспектирование SSL", 
                "Инспектирование SSH", "СОВ", "Правила АСУ ТП", "Защита почтового трафика", "ICAP-серверы", "ICAP-правила", "Профили DoS",
                "Правила защиты DoS", "Глобальный портал", "Веб-портал", "Серверы reverse-прокси", "Правила reverse-прокси",
                "Профили безопасности VPN", "Профили АСУ ТП", "Морфология", "Useragent браузеров", "Типы контента", "HID объекты",
                "HID профили", "Сценарии", "Тэги",
#                "Категории URL", "Изменённые категории URL"
            },
            7.4: {
                "Маршруты", "OSPF", "BGP", "WAF", "Персональные WAF-слои", "Системные WAF-правила", "WAF-профили",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.3: {
                "Маршруты", "OSPF", "BGP", "WAF", "Персональные WAF-слои", "Системные WAF-правила", "WAF-профили",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.2: {
                "Маршруты", "OSPF", "BGP", "Системные WAF-правила", "Tags",
                "Политики BYOD", "СОВ", "Правила АСУ ТП", "Профили безопасности VPN", "Профили АСУ ТП"},
            7.1: {
                "Маршруты", "OSPF", "BGP", "Системные WAF-правила", "Tags",
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
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента", "Tags",
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
                "HID объекты", "HID профили", "Профили BFD", "Syslog фильтры UserID агента", "Tags",
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
                "Сигнатуры СОВ", "Профили LLDP", "Профили SSL", "Профили пересылки SSL", "Tags",
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

    def change_items_status_for_export(self):
        """Скрываем пункты меню отсутствующие в данной версии NGFW и активируем остальные."""
#        item = self.findItems(self.compliances[name], Qt.MatchFlag.MatchRecursive)[0]
        if self.product == 'dcfw':
            key = f'dcfw-{self.version}'
        else:
            key = self.version
            if not self.waf_license and key >= 7.1:
                self.restricted_items[key].update({'WAF', 'WAF-профили', 'Персональные WAF-слои'})
        for item in self.findItems('*', Qt.MatchFlag.MatchWrap|Qt.MatchFlag.MatchWildcard|Qt.MatchFlag.MatchRecursive):
            if item.text(0) in self.restricted_items[key]:
                item.setHidden(True)
            else:
                item.setHidden(False)
                item.setDisabled(False)

    def change_items_status_for_import(self, current_path):
        """Скрываем пункты меню отсутствующие в данной версии NGFW и активируем те, для которых есть конфигурация."""
        if self.product == 'dcfw':
            key = f'dcfw-{self.version}'
        else:
            key = self.version
            if not self.waf_license and key >= 7.1:
                self.restricted_items[key].update({'WAF', 'WAF-профили', 'Персональные WAF-слои'})
        for i in range(self.topLevelItemCount()):
            item = self.topLevelItem(i)
            if item.text(0) in self.restricted_items[key]:
                item.setHidden(True)
            else:
                item_dir = self.over_compliances[item.text(0)]
                item_config_path = os.path.join(current_path, item_dir)
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
                    try:
                        if not selected_item.child(i).isHidden():
                            child_text = selected_item.child(i).text(0)
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
                try:
                    if not item.child(i).isHidden():
                        child_text = item.child(i).text(0)
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

#----------------------------------------------------------------------------------------------------------------------------
def main(args):
    return 0

if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
