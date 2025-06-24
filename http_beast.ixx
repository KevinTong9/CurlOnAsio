module;
#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <wil/result_macros.h>
#include <regex>
export module http_beast;

export namespace http_beast
{
    using Request = boost::beast::http::request<boost::beast::http::string_body>;
    using Response = boost::beast::http::response<boost::beast::http::string_body>;

    struct ServerData
    {
        using Handler = boost::asio::awaitable<bool>(Request const& request, Response& response);

        boost::asio::ip::tcp::endpoint preferred_endpoint;
        std::chrono::steady_clock::duration timeout = std::chrono::seconds{ 1 };
        std::vector<std::pair<std::regex, std::function<Handler>>> get_handlers;
        std::vector<std::pair<std::regex, std::function<Handler>>> post_handlers;
        std::function<void(std::string_view message, Request const* request, std::exception_ptr e)> logger;

        void on_get(std::regex pattern, std::function<Handler> handler);
        void on_post(std::regex pattern, std::function<Handler> handler);

        void try_log(std::string_view message, Request const* request, std::exception_ptr e) const;
    };

    struct HttpServer
    {
        std::shared_ptr<ServerData const> data;

        boost::asio::ip::tcp::endpoint local_endpoint;
    };

    HttpServer start_http_server(ServerData data);
}

module: private;
import common_io_context;
import utils;

namespace
{
    boost::asio::awaitable<void> run_server
    (
        http_beast::HttpServer server,
        boost::asio::ip::tcp::acceptor acceptor
    );
    boost::asio::awaitable<void> handle_connection
    (
        http_beast::HttpServer server,
        boost::beast::tcp_stream connection
    );
    boost::asio::awaitable<http_beast::Response> handle_request
    (
        http_beast::ServerData const& server,
        http_beast::Request request
    );
    http_beast::Response simple_response
    (
        http_beast::Request const& request,
        boost::beast::http::status status_code,
        std::string_view body,
        std::string_view content_type
    );
}

void http_beast::ServerData::on_get(std::regex pattern, std::function<Handler> handler)
{
    get_handlers.emplace_back(std::move(pattern), std::move(handler));
}

void http_beast::ServerData::on_post(std::regex pattern, std::function<Handler> handler)
{
    post_handlers.emplace_back(std::move(pattern), std::move(handler));
}

void http_beast::ServerData::try_log(std::string_view message, Request const* request, std::exception_ptr e) const
{
    if (logger)
    {
        try
        {
            logger(message, request, e);
        }
        catch (...) {}
    }
}

http_beast::HttpServer http_beast::start_http_server(http_beast::ServerData data)
{
    boost::asio::io_context& io_context = common_io_context::get_io_context();
    boost::asio::ip::tcp::acceptor acceptor{ io_context, data.preferred_endpoint.protocol() };
    acceptor.bind(data.preferred_endpoint);
    acceptor.listen();
    
    http_beast::HttpServer server
    {
        .data = std::make_shared<http_beast::ServerData>(std::move(data)),
        .local_endpoint = acceptor.local_endpoint()
    };
    boost::asio::co_spawn(common_io_context::get_io_context(), run_server(server, std::move(acceptor)), boost::asio::detached);
    return server;
}

namespace
{
    boost::asio::awaitable<void> run_server
    (
        http_beast::HttpServer server,
        boost::asio::ip::tcp::acceptor acceptor
    )
    {
        auto executor = co_await boost::asio::this_coro::executor;

        while (true)
        {
            try
            {
                utils::log_debug("http server accepting on {}", acceptor.local_endpoint());
                boost::asio::ip::tcp::socket socket = co_await acceptor.async_accept(boost::asio::use_awaitable);
                utils::log_debug("http server accepted new connection");
                boost::beast::tcp_stream connection{ std::move(socket) };
                boost::asio::co_spawn(executor, handle_connection(server, std::move(connection)), [d = server.data](std::exception_ptr e)
                {
                    if (e == nullptr)
                    {
                        return;
                    }
                    d->try_log("exception in handle_connection", nullptr, e);
                    try
                    {
                        std::rethrow_exception(e);
                    }
                    CATCH_LOG_MSG("exception in handle_connection");
                });
            }
            CATCH_LOG_MSG("exception when accepting connection");
        }
    }

    boost::asio::awaitable<void> handle_connection
    (
        http_beast::HttpServer server,
        boost::beast::tcp_stream connection
    )
    {
        // This buffer is required to persist across reads
        boost::beast::flat_buffer buffer;

        while (true)
        {
            // Set the timeout.
            connection.expires_after(server.data->timeout);

            // Read a request
            http_beast::Request request;
            co_await boost::beast::http::async_read(connection, buffer, request);

            // Handle the request
            bool is_head = request.method() == boost::beast::http::verb::head;
            http_beast::Response response = co_await handle_request(*server.data, std::move(request));
            if (is_head)
            {
                response.body().clear();
            }
            boost::beast::http::message_generator message{ std::move(response) };

            // Determine if we should close the connection
            bool keep_alive = message.keep_alive();

            // Send the response
            co_await boost::beast::async_write(connection, std::move(message));

            if (!keep_alive)
            {
                // This means we should close the connection, usually because
                // the response indicated the "Connection: close" semantic.
                break;
            }
        }

        // Send a TCP shutdown
        connection.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send);

        // At this point the connection is closed gracefully
        // we ignore the error because the client might have
        // dropped the connection already.
    }

    boost::asio::awaitable<http_beast::Response> handle_request
    (
        http_beast::ServerData const& server,
        http_beast::Request request
    )
    {
        // Returns a bad request response
        auto const bad_request = [&request](std::string_view why)
        {
            return simple_response
            (
                request,
                boost::beast::http::status::bad_request,
                why,
                "text/html"
            );
        };

        // Returns a not found response
        auto const not_found = [&request](std::string_view target)
        {
            return simple_response
            (
                request,
                boost::beast::http::status::not_found,
                std::format("The resource '{}' was not found", target),
                "text/html"
            );
        };

        std::string_view target{ request.target() };

        http_beast::Response response = bad_request("request not handled");
        try
        {
            switch (request.method())
            {
            case boost::beast::http::verb::get:
            case boost::beast::http::verb::head:
                for (auto const& [pattern, handler] : server.get_handlers)
                {
                    if (not std::regex_match(target.begin(), target.end(), pattern))
                    {
                        continue;
                    }
                    if (co_await handler(request, response))
                    {
                        co_return response;
                    }
                }
                server.try_log("not found", &request, nullptr);
                co_return not_found(request.target());
            case boost::beast::http::verb::post:
                for (auto const& [pattern, handler] : server.post_handlers)
                {
                    if (not std::regex_match(target.begin(), target.end(), pattern))
                    {
                        continue;
                    }
                    if (co_await handler(request, response))
                    {
                        co_return response;
                    }
                }
                server.try_log("not found", &request, nullptr);
                co_return not_found(request.target());
            default:
                server.try_log("bad request", &request, nullptr);
                co_return bad_request("Unknown HTTP-method");
            }
        }
        catch (...)
        {
            server.try_log("exception in http server request handling", &request, std::current_exception());
            LOG_CAUGHT_EXCEPTION_MSG("exception in http server request handling");
        }
        co_return simple_response
        (
            request,
            boost::beast::http::status::internal_server_error,
            "Internal Server Error",
            "text/html"
        );
    }

    http_beast::Response simple_response
    (
        http_beast::Request const& request,
        boost::beast::http::status status_code,
        std::string_view body,
        std::string_view content_type
    )
    {
        http_beast::Response response
        {
            status_code,
            request.version()
        };
        response.set(boost::beast::http::field::server, BOOST_BEAST_VERSION_STRING);
        response.set(boost::beast::http::field::content_type, content_type);
        response.keep_alive(request.keep_alive());
        response.body().assign(body);
        response.prepare_payload();
        return response;
    };
}