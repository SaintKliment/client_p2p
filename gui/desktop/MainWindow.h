#ifndef MAINWINDOW_H
#define MAINWINDOW_H

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
#include <fstream> 
namespace fs = std::filesystem;

class MainWindow : public QWidget {
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override;

private slots:
    void onSubmit();
    void toggleFullScreen();

private:
    QLineEdit *pinEdit;
    QPushButton *submitButton;
    QPushButton *fullScreenButton; // Кнопка для переключения полноэкранного режима
    QLabel *titleLabel;            // Заголовок
    QLabel *infoLabel;             // Информационное поле
    QWidget *centerBox;            // Центральный блок
    

    QLabel *reputationIDLabel;
    QLabel *sessionIDLabel;

    void processPIN(const std::string &pin);
    bool fileExists(const std::string &filename);
    void showInfo(const QString &title, const QString &message);

    // Метод для переключения интерфейса
    void switchToDisplayMode();
};

#endif // MAINWINDOW_H