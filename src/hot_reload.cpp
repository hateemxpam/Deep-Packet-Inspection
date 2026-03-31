#include "hot_reload.h"
#include <iostream>
#include <sys/stat.h>

HotReloader::HotReloader(const std::string&    file_path,
                          uint32_t              interval_ms,
                          std::function<void()> on_reload)
    : file_path_(file_path)
    , interval_ms_(interval_ms)
    , on_reload_(std::move(on_reload))
{}

HotReloader::~HotReloader() {
    stop();
}

void HotReloader::start() {
    running_ = true;
    thread_  = std::thread(&HotReloader::watchLoop, this);
    std::cout << "[HotReload] Watching: " << file_path_
              << " (checking every "
              << interval_ms_ << "ms)\n";
}

void HotReloader::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
}

uint64_t HotReloader::getLastModifiedTime() const {
    struct stat st{};
    if (stat(file_path_.c_str(), &st) != 0) {
        return 0; // File not found or inaccessible
    }
    return static_cast<uint64_t>(st.st_mtime);
}

void HotReloader::watchLoop() {
    uint64_t last_mtime = getLastModifiedTime();

    while (running_) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds(interval_ms_)
        );

        uint64_t current_mtime = getLastModifiedTime();

        if (current_mtime != 0 && current_mtime != last_mtime) {
            last_mtime = current_mtime;
            std::cout << "\n[HotReload] Rules file changed — reloading...\n";
            try {
                on_reload_();
                std::cout << "[HotReload] Rules reloaded successfully.\n";
            } catch (const std::exception& e) {
                std::cerr << "[HotReload] Reload failed: "
                          << e.what() << "\n";
            }
        }
    }
}