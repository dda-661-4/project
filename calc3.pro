#-------------------------------------------------
#
# Project created by QtCreator 2017-10-06T20:46:29
#
#-------------------------------------------------

QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

TARGET = calc3
TEMPLATE = app


SOURCES += main.cpp\
        dribl.cpp \
    mainwindow.cpp \
    sniffer.cpp

HEADERS  += dribl.h \
    mainwindow.h \
    sniffer.h

FORMS    += dribl.ui \
    mainwindow.ui \
    sniffer.ui
