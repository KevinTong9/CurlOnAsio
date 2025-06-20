module;
#include <iostream>
#include <format>
#include <mutex>
export module utils;

export namespace utils
{
    std::mutex cerr_mutex;

    template<typename... Args>
    void log_error(std::string_view what, Args&&... args) { std::scoped_lock lock{ cerr_mutex }; std::cerr << std::vformat(what, std::make_format_args(args...)) << std::endl; }

    template<typename... Args>
    void log_output(std::string_view what, Args&&... args) { std::scoped_lock lock{ cerr_mutex }; std::cout << std::vformat(what, std::make_format_args(args...)) << std::endl; }
}
