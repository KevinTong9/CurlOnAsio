module;
#include <boost/asio.hpp>
#include <wil/result.h>
#include <array>
#include <format>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>
export module utils;

namespace std
{
    template<>
    struct formatter<std::thread::id> : formatter<string>
    {
        template<class FmtContext>
        FmtContext::iterator format(thread::id s, FmtContext& ctx) const
        {
            ostringstream out;
            out << s;
            return formatter<string>::format(move(out).str(), ctx);
        }
    };

    template<>
    struct formatter<boost::asio::ip::address> : formatter<string>
    {
        template<class FmtContext>
        FmtContext::iterator format(boost::asio::ip::address s, FmtContext& ctx) const
        {
            return formatter<string>::format(s.to_string(), ctx);
        }
    };

    template<>
    struct formatter<boost::asio::ip::tcp::endpoint> : formatter<string>
    {
        template<class FmtContext>
        FmtContext::iterator format(boost::asio::ip::tcp::endpoint s, FmtContext& ctx) const
        {
            formatter<string>::format(s.address().to_string(), ctx);
            formatter<string>::format(":", ctx);
            return formatter<string>::format(std::to_string(s.port()), ctx);
        }
    };
}


export namespace utils
{
    std::mutex cerr_mutex;

    template<typename... Args>
    void log_info(std::string_view what, Args&&... args) { std::scoped_lock lock{ cerr_mutex }; std::cout << std::vformat(what, std::make_format_args(args...)) << std::endl; }

    template<typename... Args>
    void log_error(std::string_view what, Args&&... args) { std::scoped_lock lock{ cerr_mutex }; std::cerr << std::vformat(what, std::make_format_args(args...)) << std::endl; }

    template<typename... Args>
    void log_output(std::string_view what, Args&&... args) { std::scoped_lock lock{ cerr_mutex }; std::cout << std::vformat(what, std::make_format_args(args...)) << std::endl; }

    template<typename... Args>
    void log_debug(std::string_view what, Args&&... args) { std::scoped_lock lock{ cerr_mutex }; std::cerr << std::vformat(what, std::make_format_args(args...)) << std::endl; }

    void init()
    {
        wil::SetResultLoggingCallback([](wil::FailureInfo const& f) noexcept
        {
            std::array<wchar_t, 1024> buffer = { 0 };
            HRESULT result = wil::GetFailureLogString(buffer.data(), buffer.size() - 1, f);
            if (SUCCEEDED(result))
            {
                std::array<char, 4096> char_buffer = { 0 };
                WideCharToMultiByte(CP_ACP, 0, buffer.data(), -1, char_buffer.data(), char_buffer.size(), nullptr, nullptr);
                log_error("wil: {}", char_buffer.data());
            }
            else
            {
                log_error("<Error message generation failed>");
            }
        });
    }
}
