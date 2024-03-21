#!/usr/bin/python3
#
from enum import Enum


color = {
    'BLACK': "#000000",
    'RED': "#8b0000",
    'iRED': "#8b0000",
    'bRED': "#b5675a",
    'ORANGE': "#cf6e30",
    'iORANGE': "#cf6e30",
    'LBLUE': "#1e90ff",
    'BLUE': "#00008b",
    'GRAY': "#696969",
    'dGRAY': "#5d7581",
    'GREEN': "#006400",
    'iGREEN': "#006400",
    'rNOTE': "#7a5b47",
    'NOTE': "#556682",
}

class Style(str, Enum):
    Test = ("""
        * {
            background-color: #2690c8;
            color: white;
            font-size: 14px;
            font-weight: bold;
        }
    """)
    GroupBox = ("""
        QGroupBox {
            color: grey;
            font-weight: bold;
        }
        Qwidget {
            background-color: #ffffff;
        }
    """)
    MainTree = ("""
        QTreeWidget::item:hover {
            background: lightblue;
        }
        QTreeWidget::item:hover:selected {
            background: #349AD9;
        }
    """)
    ListTree = ("""
        QTreeWidget::item {
            padding-top: 3px;
            padding-bottom: 3px;
        }
        QTreeWidget::item:hover {
            background: lightblue;
            color: black;
        }
        QTreeWidget::item:hover:selected {
            background: #349AD9;
        }
    """)
    ListTreeEnabledItems = ("""
        QTreeWidget::item {
            color: #1f5e82;
            padding-top: 3px;
            padding-bottom: 3px;
        }
        QTreeWidget::item:hover {
            background: lightblue;
            color: black;
        }
        QTreeWidget::item:hover:selected {
            background: #349AD9;
        }
    """)
    LineEdit = ("""
        QLineEdit {
            background-color: white;
            color: black;
            min-width: 170px;
        }
        QLineEdit:hover {
            background-color: lightblue;
            color: black;
        }
    """)
