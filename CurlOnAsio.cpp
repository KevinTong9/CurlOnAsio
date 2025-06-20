// CurlOnAsio.cpp : Defines the entry point for the application.
//

#include "CurlOnAsio.h"
#include <boost/asio.hpp>
#include <curl/multi.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
#include <map>

import utils;
import http_curl;

boost::asio::awaitable<void> async_main()
{
    using namespace http_curl;
    while (true)
    {
        utils::log_output("url");

        std::string url;
        std::getline(std::cin, url);
        if (url.empty())
        {
            break;
        }

        Response response;
        try
        {
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
    http_curl::start_curl_thread();

    boost::asio::io_context context;
    auto task = boost::asio::co_spawn(context, async_main, boost::asio::use_future);
    context.run();
    task.get();

    std::cout << "program finished" << std::endl;

}
