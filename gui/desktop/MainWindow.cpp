#include "MainWindow.h"
#include "../../core/crypto/Crypto.h"
#include "../../core/serialization/Serialization.h"

#include <QApplication>
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <string>
#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

bool MainWindow::fileExists(const std::string &filename) {
    return fs::exists(filename);
}

void MainWindow::showInfo(const QString &title, const QString &message) {
    QMessageBox::information(this, title, message);
}

MainWindow::MainWindow(QWidget *parent) : QWidget(parent) {
    setWindowTitle("Velosiped - Вход");
    resize(1024, 768); // Увеличиваем размер окна
    setMinimumSize(800, 600); // Минимальный размер окна

    // Создание заголовка
    titleLabel = new QLabel("Velosiped", this);
    titleLabel->setAlignment(Qt::AlignCenter);
    titleLabel->setStyleSheet("font-size: 36px; font-weight: bold; color: white;");

    // Создание информационного поля
    infoLabel = new QLabel("Введите 6-значный PIN-код:", this);
    infoLabel->setAlignment(Qt::AlignCenter);
    infoLabel->setStyleSheet("font-size: 24px; color: rgba(255, 255, 255, 0.7);");

    // Поле ввода PIN-кода
    pinEdit = new QLineEdit(this);
    pinEdit->setEchoMode(QLineEdit::Password);
    pinEdit->setMaxLength(6);
    pinEdit->setPlaceholderText("XXXXXX");
    pinEdit->setStyleSheet(
        "height: 50px; font-size: 24px; padding: 10px; border: none; border-radius: 8px; background: rgba(255, 255, 255, 0.1);"
    );

    // Кнопка подтверждения
    submitButton = new QPushButton("Подтвердить", this);
    submitButton->setStyleSheet(
        "height: 50px; font-size: 24px; color: white; background: #1e3c72; border: none; border-radius: 8px;"
    );
    connect(submitButton, &QPushButton::clicked, this, &MainWindow::onSubmit);

    // Кнопка полноэкранного режима
    fullScreenButton = new QPushButton("Переключить полноэкранный режим", this);
    fullScreenButton->setStyleSheet(
        "height: 30px; font-size: 14px; color: white; background: #2a5298; border: none; border-radius: 8px;"
    );
    connect(fullScreenButton, &QPushButton::clicked, this, &MainWindow::toggleFullScreen);

    // Метки для отображения Node Reputation ID и Node Session ID
    reputationIDLabel = new QLabel(this);
    reputationIDLabel->setAlignment(Qt::AlignCenter);
    reputationIDLabel->setStyleSheet("font-size: 24px; color: white;");
    reputationIDLabel->setVisible(false); // Скрываем по умолчанию

    sessionIDLabel = new QLabel(this);
    sessionIDLabel->setAlignment(Qt::AlignCenter);
    sessionIDLabel->setStyleSheet("font-size: 24px; color: white;");
    sessionIDLabel->setVisible(false); // Скрываем по умолчанию

    // Центральный блок
    centerBox = new QWidget(this);
    centerBox->setStyleSheet(
        "background: rgba(0, 0, 0, 0.6); border-radius: 15px; padding: 30px;"
    );
    QVBoxLayout *centerLayout = new QVBoxLayout(centerBox);
    centerLayout->addWidget(titleLabel);
    centerLayout->addWidget(infoLabel);
    centerLayout->addWidget(pinEdit);
    centerLayout->addWidget(submitButton);
    centerLayout->addWidget(fullScreenButton);
    centerLayout->addWidget(reputationIDLabel); // Добавляем метку для Reputation ID
    centerLayout->addWidget(sessionIDLabel);   // Добавляем метку для Session ID
    centerLayout->setSpacing(20);

    // Главный макет
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->addStretch();
    mainLayout->addWidget(centerBox, 0, Qt::AlignCenter);
    mainLayout->addStretch();

    // Фон окна
    setStyleSheet(
        "QWidget { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e3c72, stop:1 #2a5298); }"
    );
}

MainWindow::~MainWindow() {}

void MainWindow::onSubmit() {
    QString pin = pinEdit->text();
    if (pin.length() == 6 && pin.toStdString().find_first_not_of("0123456789") == std::string::npos) {
        processPIN(pin.toStdString());
    } else {
        QMessageBox::warning(this, "Ошибка", "PIN-код должен состоять из 6 цифр.");
    }
}

void MainWindow::toggleFullScreen() {
    if (isFullScreen()) {
        showNormal();
    } else {
        showFullScreen();
    }
}

void MainWindow::switchToDisplayMode() {
    // Скрываем элементы, связанные с вводом PIN-кода
    infoLabel->setVisible(false);
    pinEdit->setVisible(false);
    submitButton->setVisible(false);

    // Показываем метки с ID
    reputationIDLabel->setVisible(true);
    sessionIDLabel->setVisible(true);

    // Увеличиваем размер окна
    resize(1280, 800);
}

void MainWindow::processPIN(const std::string &pin) {
    const std::string privateKeyFilename = "private_key_encrypted.txt";
    const std::string publicKeyFilename = "public_key.txt";
    const std::string pinHashFilename = "pin_hash.txt";

    bool keysExist = fileExists(privateKeyFilename) && fileExists(publicKeyFilename);
    std::string pinHash;

    if (keysExist) {
        // Проверка существования файла с хешем PIN-кода
        if (!fileExists(pinHashFilename)) {
            QMessageBox::critical(this, "Ошибка", "Файл с хешем PIN-кода не найден. Пожалуйста, удалите ключи и повторите попытку.");
            return;
        }
        std::ifstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            QMessageBox::critical(this, "Ошибка", "Ошибка открытия файла с хешем PIN-кода.");
            return;
        }
        std::getline(pinHashFile, pinHash);
        if (CryptoUtils::hashPIN(pin) != pinHash) {
            QMessageBox::warning(this, "Ошибка", "Неверный PIN-код. Попробуйте снова.");
            return;
        }

        // Загрузка зашифрованного приватного ключа
        std::ifstream privateKeyFile(privateKeyFilename);
        if (!privateKeyFile.is_open()) {
            QMessageBox::critical(this, "Ошибка", "Ошибка открытия файла с приватным ключом.");
            return;
        }
        std::stringstream privateKeyBuffer;
        privateKeyBuffer << privateKeyFile.rdbuf();
        std::string encryptedPrivateKey = privateKeyBuffer.str();
        privateKeyFile.close();

        // Загрузка публичного ключа
        std::ifstream publicKeyFile(publicKeyFilename);
        if (!publicKeyFile.is_open()) {
            QMessageBox::critical(this, "Ошибка", "Ошибка открытия файла с публичным ключом.");
            return;
        }
        std::stringstream publicKeyBuffer;
        publicKeyBuffer << publicKeyFile.rdbuf();
        std::string hexPublicKey = publicKeyBuffer.str();
        publicKeyFile.close();

        try {
            // Расшифровка приватного ключа
            std::string decryptedPrivateKey = CryptoUtils::decryptPrivateKey(encryptedPrivateKey, pin);

            // Генерация Node Reputation ID из публичного ключа
            std::string reputationID = CryptoUtils::generateIDFromPublicKey(hexPublicKey);

            // Генерация новой сессии
            auto sessionKeys = CryptoUtils::generateECDSAKeys();
            const unsigned char *sessionPublicKeyData = reinterpret_cast<const unsigned char *>(sessionKeys.first.data());
            std::string hexSessionPublicKey = Serialization::bytesToHex(sessionPublicKeyData, sessionKeys.first.size());
            std::string sessionID = CryptoUtils::generateIDFromPublicKey(hexSessionPublicKey);

            // Обновление меток
            reputationIDLabel->setText(QString("Node Reputation ID: %1").arg(QString::fromStdString(reputationID)));
            sessionIDLabel->setText(QString("Node Session ID: %1").arg(QString::fromStdString(sessionID)));

            // Переключаем интерфейс в режим отображения данных
            switchToDisplayMode();
        } catch (const std::exception &e) {
            QMessageBox::critical(this, "Ошибка", "Ошибка расшифровки приватного ключа: " + QString::fromStdString(e.what()));
        }
    } else {
        // Генерация новых ключей
        auto keys = CryptoUtils::generateECDSAKeys();
        const unsigned char *publicKeyData = reinterpret_cast<const unsigned char *>(keys.first.data());
        const unsigned char *privateKeyData = reinterpret_cast<const unsigned char *>(keys.second.data());
        std::string hexPublicKey = Serialization::bytesToHex(publicKeyData, keys.first.size());
        std::string hexPrivateKey = Serialization::bytesToHex(privateKeyData, keys.second.size());

        // Генерация Node Reputation ID из публичного ключа
        std::string reputationID = CryptoUtils::generateIDFromPublicKey(hexPublicKey);

        // Шифрование приватного ключа
        std::string encryptedPrivateKey = CryptoUtils::encryptPrivateKey(hexPrivateKey, pin);

        // Сохранение ключей
        std::ofstream privateKeyFile(privateKeyFilename);
        if (privateKeyFile.is_open()) {
            privateKeyFile << encryptedPrivateKey;
            privateKeyFile.close();
        }
        std::ofstream publicKeyFile(publicKeyFilename);
        if (publicKeyFile.is_open()) {
            publicKeyFile << hexPublicKey;
            publicKeyFile.close();
        }

        // Генерация новой сессии
        auto sessionKeys = CryptoUtils::generateECDSAKeys();
        const unsigned char *sessionPublicKeyData = reinterpret_cast<const unsigned char *>(sessionKeys.first.data());
        std::string hexSessionPublicKey = Serialization::bytesToHex(sessionPublicKeyData, sessionKeys.first.size());
        std::string sessionID = CryptoUtils::generateIDFromPublicKey(hexSessionPublicKey);

        // Обновление меток
        reputationIDLabel->setText(QString("Node Reputation ID: %1").arg(QString::fromStdString(reputationID)));
        sessionIDLabel->setText(QString("Node Session ID: %1").arg(QString::fromStdString(sessionID)));

        // Переключаем интерфейс в режим отображения данных
        switchToDisplayMode();

        // Сохранение хеша PIN-кода
        pinHash = CryptoUtils::hashPIN(pin);
        std::ofstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            QMessageBox::critical(this, "Ошибка", "Ошибка создания файла с хешем PIN-кода.");
            return;
        }
        pinHashFile << pinHash;
    }
}

