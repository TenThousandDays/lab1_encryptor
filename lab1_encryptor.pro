QT       -= gui

CONFIG   += console c++17
CONFIG   -= app_bundle

TARGET = folder_protector
TEMPLATE = app

SOURCES += \
    src/main.cpp \
    src/LabUtils.cpp \
    src/DirectoryProcessor.cpp \
    src/FileCryptor.cpp

INCLUDEPATH += include

HEADERS += \
    include/CryptoException.h \
    include/DirectoryProcessor.h \
    include/FileCryptor.h \
    include/LabUtils.h \
    include/ProcessingResult.h

# ======================
# OpenSSL (кроссплатформа)
# ======================

win32 {
    # Ожидаем, что OPENSSL_ROOT_DIR задан (например, через переменные среды)
    OPENSSL_ROOT_DIR = C:/Program Files/OpenSSL-Win64
    message("OPENSSL_ROOT_DIR = $$OPENSSL_ROOT_DIR")
    isEmpty(OPENSSL_ROOT_DIR) {
        error("Set OPENSSL_ROOT_DIR to your OpenSSL installation path")
    }

    INCLUDEPATH += "$$OPENSSL_ROOT_DIR/include"
    LIBS += -L"$$OPENSSL_ROOT_DIR/lib" -lcrypto

    # Для MinGW
    gcc {
        LIBS += -lcrypto
    }

    # Для MSVC
    msvc {
        # Обычно имена такие:
        # libcrypto.lib или libcrypto-3-x64.lib (зависит от версии)
        LIBS += -llibcrypto
    }
}

unix:!macx {
    # Linux
    LIBS += -lcrypto
}

macx {
    # macOS (через brew)
    INCLUDEPATH += /usr/local/opt/openssl/include
    LIBS += -L/usr/local/opt/openssl/lib -lcrypto

    # Для Apple Silicon может быть:
    # /opt/homebrew/opt/openssl
}

# ======================
# Компиляторные флаги
# ======================

msvc {
    QMAKE_CXXFLAGS += /W4 /permissive-
} else {
    QMAKE_CXXFLAGS += \
        -Wall \
        -Wextra \
        -Wpedantic \
        -Wconversion \
        -Wshadow \
        -Wnon-virtual-dtor \
        -Wold-style-cast \
        -Woverloaded-virtual \
        -Wnull-dereference \
        -Wformat=2
}

# ======================
# Санитайзеры
# ======================

!msvc:equals(ENABLE_SANITIZERS, ON) {
    QMAKE_CXXFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
    QMAKE_LFLAGS += -fsanitize=address,undefined
}