#include "./MainWindow.h"


// MainWindow::~MainWindow() { }

bool MainWindow::fileExists(const std::string& filename) {
    return fs::exists(filename);
}

void MainWindow::showInfo(const QString& title, const QString& message) {
    QMessageBox::information(this, title, message);
}

MainWindow::MainWindow(QWidget *parent) : QWidget(parent) {
    setWindowTitle("Вход в систему");
    setFixedSize(400, 200);

    QLabel *label = new QLabel("Введите 6-значный PIN-код:", this);
    pinEdit = new QLineEdit(this);
    pinEdit->setEchoMode(QLineEdit::Password);
    QPushButton *submitButton = new QPushButton("Подтвердить", this);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->addWidget(label);
    layout->addWidget(pinEdit);
    layout->addWidget(submitButton);
    setLayout(layout);

    connect(submitButton, &QPushButton::clicked, this, &MainWindow::onSubmit);
}

void MainWindow::onSubmit() {
    QString pin = pinEdit->text();
    if (pin.length() == 6 && pin.toStdString().find_first_not_of("0123456789") == std::string::npos) {
        processPIN(pin.toStdString());
    } else {
        QMessageBox::warning(this, "Ошибка", "PIN-код должен состоять из 6 цифр.");
    }
}

void MainWindow::processPIN(const std::string& pin) {
    const std::string privateKeyFilename = "private_key_encrypted.txt";
    const std::string publicKeyFilename = "public_key.txt";
    const std::string pinHashFilename = "pin_hash.txt";

    bool keysExist = fileExists(privateKeyFilename) && fileExists(publicKeyFilename);
    std::string pinHash;

    if (keysExist) {
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
    } else {
        pinHash = CryptoUtils::hashPIN(pin);

        std::ofstream pinHashFile(pinHashFilename);
        if (!pinHashFile.is_open()) {
            QMessageBox::critical(this, "Ошибка", "Ошибка создания файла с хешем PIN-кода.");
            return;
        }

        pinHashFile << pinHash;
    }

    if (keysExist) {
        std::ifstream privateKeyFile(privateKeyFilename);
        if (!privateKeyFile.is_open()) {
            QMessageBox::critical(this, "Ошибка", "Ошибка открытия файла с приватным ключом.");
            return;
        }

        std::stringstream privateKeyBuffer;
        privateKeyBuffer << privateKeyFile.rdbuf();
        std::string encryptedPrivateKey = privateKeyBuffer.str();
        privateKeyFile.close();

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
            std::string decryptedPrivateKey = CryptoUtils::decryptPrivateKey(encryptedPrivateKey, pin);
            showInfo("Успех", "Приватный ключ успешно расшифрован.\nПубличный ключ: " + QString::fromStdString(hexPublicKey));
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "Ошибка", "Ошибка расшифровки приватного ключа: " + QString::fromStdString(e.what()));
        }
    } else {
        auto keys = CryptoUtils::generateECDSAKeys();
        const unsigned char* publicKeyData = reinterpret_cast<const unsigned char*>(keys.first.data());
        const unsigned char* privateKeyData = reinterpret_cast<const unsigned char*>(keys.second.data());

        std::string hexPublicKey = Serialization::bytesToHex(publicKeyData, keys.first.size());
        std::string hexPrivateKey = Serialization::bytesToHex(privateKeyData, keys.second.size());

        std::string nodeID = CryptoUtils::generateIDFromPublicKey(hexPublicKey);

        std::string encryptedPrivateKey = CryptoUtils::encryptPrivateKey(hexPrivateKey, pin);

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

        showInfo("Успех", "Новые ключи сгенерированы и сохранены.\nNode ID: " + QString::fromStdString(nodeID));
    }
}