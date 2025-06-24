// CurlOnAsio.cpp : Defines the entry point for the application.
//

#include "CurlOnAsio.h"
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <curl/multi.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <map>
#include <regex>

import utils;
import common_io_context;
import http_beast;
import http_curl;

boost::asio::awaitable<void> async_main()
{
    using namespace http_curl;
    while (true)
    {
        utils::log_output("type url then press enter");

        std::string url;
        std::getline(std::cin, url);
        if (url.empty())
        {
            break;
        }

        Response response;
        try
        {
            utils::log_output("coroutine invoking curl on thread {}", std::this_thread::get_id());
            auto begin = std::chrono::high_resolution_clock::now();
            response = co_await http_curl::async_http_request(
                Request{
                    .url = url,
                    .request_headers = { "Content-Type: text/plain" },
                    .user_agent = "MyCurlClient/1.0",
                    .timeout = 10L
                },
                boost::asio::use_awaitable,
                co_await boost::asio::this_coro::executor
            );
            auto end = std::chrono::high_resolution_clock::now();
            utils::log_output("coroutine invoked curl on thread {}", std::this_thread::get_id());
            auto data = response.response_data;
            if (data.size() > 2048)
            {
                auto size = data.size();
                data.resize(2048);
                data += std::format("\r\n...[total size {}]", size);
            }
            utils::log_output("response:\r\n{}", data);
            {
                std::scoped_lock lock{ utils::cerr_mutex };
                std::cout << "response headers:" << std::endl;
                for (const auto& header : response.response_headers)
                {
                    std::cout << std::format("[{}] -> [{}]", header.first, header.second) << std::endl;
                }
            }
            utils::log_output("total time {} ms", std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count());

        }
        catch (std::exception const& e)
        {
            utils::log_error("Error: {}", e.what());
        }
    }
}


int main()
{
    utils::init();

    http_curl::start_curl_thread();

    http_beast::ServerData data;
    data.preferred_endpoint = boost::asio::ip::tcp::endpoint{ boost::asio::ip::address_v4::loopback(), 0 };
    data.on_get(std::regex{ ".*" }, [](http_beast::Request const& request, http_beast::Response& response) -> boost::asio::awaitable<bool>
    {
        response.result(boost::beast::http::status::ok);
        response.body() = std::format("Hello {}", std::string_view{ request.target() });
        response.set(boost::beast::http::field::content_type, "text/html");
        response.prepare_payload();
        co_return true;
    });
    data.logger = [](std::string_view message, http_beast::Request const* request, std::exception_ptr e)
    {
        if (request)
        {
            utils::log_output("{} {} -> {}", std::string_view{ request->method_string() }, std::string_view{ request->target() }, message);
        }
        else
        {
            utils::log_output("http server -> {}", message);
        }
        if (e)
        {
            try
            {
                std::rethrow_exception(e);
            }
            catch (std::exception const& e)
            {
                utils::log_error("Error in http server: {}", e.what());
            }
        }
    };
    http_beast::HttpServer server = http_beast::start_http_server(data);
    utils::log_output("Server running on {}", server.local_endpoint);

    auto task = boost::asio::co_spawn(common_io_context::get_io_context(), async_main, boost::asio::use_future);
    common_io_context::blocking_run_io_context();
    task.get();

    std::cout << "program finished" << std::endl;

}
