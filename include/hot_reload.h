#pragma once
#include "rule_manager.h"
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <functional>
#include <cstdint>

// HotReloader watches a rules file on disk.
// When the file's last-modified timestamp changes,
// it reloads rules and calls the provided callback.
//
// Usage:
//   HotReloader reloader("rules/rules.txt", 2000, [&](){
//       rules.loadFromFile("rules/rules.txt");
//   });
//   reloader.start();
//   ... run engine ...
//   reloader.stop();

class HotReloader {
public:
    // file_path    — path to rules file to watch
    // interval_ms  — how often to check for changes (milliseconds)
    // on_reload    — callback called when file changes
    HotReloader(const std::string&       file_path,
                uint32_t                 interval_ms,
                std::function<void()>    on_reload);

    // Start the background watcher thread
    void start();

    // Stop the watcher thread — blocks until stopped
    void stop();

    ~HotReloader();

private:
    void watchLoop();

    // Returns last modified time of file as uint64
    // Returns 0 if file cannot be accessed
    uint64_t getLastModifiedTime() const;

    std::string            file_path_;
    uint32_t               interval_ms_;
    std::function<void()>  on_reload_;
    std::atomic<bool>      running_{false};
    std::thread            thread_;
};