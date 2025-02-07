#include "ThreadPool.h"
#include <iostream>

// Добавить задачу в пул потоков с указанием имени
void ThreadPool::add_task(const std::string& name, const std::function<void()>& task) {
    std::lock_guard<std::mutex> lock(mutex); // Блокируем мьютекс для потокобезопасности

    if (threads.find(name) != threads.end()) {
        throw std::runtime_error("Поток с именем '" + name + "' уже существует.");
    }

    auto thread_ptr = std::make_shared<std::thread>(task);
    threads[name] = thread_ptr;
    std::cout << "Задача добавлена в пул потоков. Имя потока: " << name << std::endl;
}

// Остановить конкретный поток по имени
void ThreadPool::stop_thread(const std::string& name) {
    std::lock_guard<std::mutex> lock(mutex); // Блокируем мьютекс для потокобезопасности

    auto it = threads.find(name);
    if (it == threads.end()) {
        std::cerr << "Поток с именем '" << name << "' не найден." << std::endl;
        return;
    }

    if (it->second->joinable()) {
        it->second->join(); // Ждём завершения потока
    }
    threads.erase(it);
    std::cout << "Поток '" << name << "' остановлен." << std::endl;
}

// Остановить все потоки
void ThreadPool::stop_all() {
    std::lock_guard<std::mutex> lock(mutex); // Блокируем мьютекс для потокобезопасности

    for (auto& [name, thread_ptr] : threads) {
        if (thread_ptr->joinable()) {
            thread_ptr->join(); // Ждём завершения потока
        }
    }
    threads.clear();
    std::cout << "Все потоки остановлены." << std::endl;
}

// Проверить, работает ли конкретный поток
bool ThreadPool::is_thread_running(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mutex); // Блокируем мьютекс для потокобезопасности

    auto it = threads.find(name);
    if (it == threads.end()) {
        return false;
    }

    return it->second->joinable();
}

// Проверить, работают ли какие-либо потоки
bool ThreadPool::are_threads_running() const {
    std::lock_guard<std::mutex> lock(mutex); // Блокируем мьютекс для потокобезопасности

    for (const auto& [name, thread_ptr] : threads) {
        if (thread_ptr->joinable()) {
            return true;
        }
    }
    return false;
}

// Деструктор для корректной остановки потоков
ThreadPool::~ThreadPool() {
    stop_all(); // Убедимся, что все потоки остановлены при уничтожении объекта
}