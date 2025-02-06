#ifndef USERINPUTCOLLECTOR_H
#define USERINPUTCOLLECTOR_H

#include <string>

class UserInputCollector {
public:
    // Метод для получения PIN-кода от пользователя
    static std::string getPINFromUser(bool isFirstTime);
};

#endif // USERINPUTCOLLECTOR_H