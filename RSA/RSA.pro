TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        RSAFunc.c \
        main.c \
        modFunc.c \
        printFunc.c

HEADERS += \
    RSAFunc.h \
    modFunc.h \
    printFunc.h \
    stdafx.h

unix:!macx: LIBS += -L$$PWD/../../../../../../usr/lib/x86_64-linux-gnu/ -lcrypto

INCLUDEPATH += $$PWD/../../../../../../usr/lib/x86_64-linux-gnu
DEPENDPATH += $$PWD/../../../../../../usr/lib/x86_64-linux-gnu
