#ifndef MAINWINDOW_H
#define MAINWINDOW_H

// Защита от конфликтов имён GLib
#ifdef __cplusplus
#define signals signals_
#endif

#include <gio/gio.h>

#ifdef __cplusplus
#undef signals
#endif

// Включение заголовочных файлов Qt6
#include <QApplication>
#include <QWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QTextEdit>
#include <QFile>
#include <QTextStream>
#include <string>
#include <filesystem>
#include <fstream> // Убедитесь, что этот заголовочный файл включен

// Включение ваших собственных заголовочных файлов
#include "../../core/Crypto.h"
#include "../../core/Serialization.h"
#include "../../core/NetworkManager.h"
#include "../../core/Node.h"

namespace fs = std::filesystem;

class MainWindow : public QWidget {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    // ~MainWindow(); // Деструктор должен быть объявлен

private slots:
    void onSubmit();

private:
    QLineEdit *pinEdit;
    void processPIN(const std::string& pin);
    bool fileExists(const std::string& filename);
    void showInfo(const QString& title, const QString& message);
};

#endif // MAINWINDOW_H