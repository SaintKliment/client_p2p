#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <thread>
#include <unordered_map>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <stdexcept>

class ThreadPool {
public:
    // Добавить задачу в пул потоков с указанием имени
    void add_task(const std::string& name, const std::function<void()>& task);

    // Остановить конкретный поток по имени
    void stop_thread(const std::string& name);

    // Остановить все потоки
    void stop_all();

    // Проверить, работает ли конкретный поток
    bool is_thread_running(const std::string& name) const;

    // Проверить, работают ли какие-либо потоки
    bool are_threads_running() const;

    // Деструктор для корректной остановки потоков
    ~ThreadPool();

private:
    std::unordered_map<std::string, std::shared_ptr<std::thread>> threads; // Храним именованные потоки
    mutable std::mutex mutex; // Мьютекс для синхронизации доступа к словарю потоков
};

#endif // THREADPOOL_H