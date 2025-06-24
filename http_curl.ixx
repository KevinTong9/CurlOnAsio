module;
#include <boost/asio.hpp>
#include <curl/multi.h>
#include <wil/resource.h>
#include <wil/result_macros.h>
export module http_curl;

export namespace http_curl
{
    struct Request
    {
        std::string url;
        std::string body;
        std::vector<std::string> request_headers;
        std::string user_agent;
        long timeout = 15L;
    };

    struct Response
    {
        // TODO:
        // support status code; filter out trailers and Content-Encoding
        long status_code = 0;
        std::string response_data;
        std::vector<std::pair<std::string, std::string>> response_headers;
    };

    using ResultSignature = void(std::exception_ptr, Response);

    template<typename T>
    concept CompletionToken = boost::asio::completion_token_for<ResultSignature>;

    template<CompletionToken T>
    using DeducedAsyncReturnType = typename boost::asio::async_result<std::decay_t<T>, ResultSignature>::return_type;

    void start_curl_thread();

    template<CompletionToken T, boost::asio::execution::executor Executor>
    auto async_http_request
    (
        Request request,
        T&& completion_token,
        Executor&& executor
    ) -> DeducedAsyncReturnType<T>;
}

namespace http_curl::detail
{
    void queue_http_request
    (
        boost::asio::any_completion_handler<ResultSignature> completion_handler,
        http_curl::Request request,
        boost::asio::any_completion_executor executor
    );

    void wake_up_curl_thread();
}

template<http_curl::CompletionToken T, boost::asio::execution::executor Executor>
auto http_curl::async_http_request
(
    http_curl::Request request,
    T&& completion_token,
    Executor&& executor
) -> http_curl::DeducedAsyncReturnType<T>
{
    auto on_exit = wil::scope_exit([]
    {
        // curl_multi_wakeup is also called in the initiation lambda
        // but since we don't know if initiation will be called immediately
        // we call it here to ensure that the multi handle is woken up
        detail::wake_up_curl_thread();
    });
    using RS = ResultSignature;
    return boost::asio::async_initiate<T, RS>(detail::queue_http_request, completion_token, std::move(request), std::move(executor));
}

module: private;
import utils;

namespace
{
    using CurlMultiHandle = wil::unique_any<CURLM*, decltype(&curl_multi_cleanup), &curl_multi_cleanup>;
    using CurlEasyHandle = wil::unique_any<CURL*, decltype(&curl_easy_cleanup), &curl_easy_cleanup>;
    using CurlStringList = wil::unique_any<curl_slist*, decltype(&curl_slist_free_all), &curl_slist_free_all>;

    struct Task
    {
        using Handler = boost::asio::any_completion_handler<http_curl::ResultSignature>;

        Handler handler;
        boost::asio::any_completion_executor executor;

        std::vector<char> curl_error;
        CurlStringList request_headers;
        CurlEasyHandle curl;
        CURLM* multi = nullptr;

        http_curl::Response response;

        ~Task() noexcept;
        void initialize_request(http_curl::Request const& request);

        void add_to_multi(CURLM* destination);
        void remove_from_multi();
        void cancel() noexcept;
        void invoke_completion_handler(std::exception_ptr e);

        static std::size_t body_reader(char* ptr, std::size_t size, std::size_t nmemb, void* userdata);
        static std::size_t response_header_reader(char* ptr, std::size_t size, std::size_t nmemb, void* userdata);
    };

    struct CurlDataStructure
    {
        CurlMultiHandle multi_handle;
        std::unordered_map<CURL*, std::unique_ptr<Task>> executing_tasks;
        std::mutex new_tasks_mutex;
        std::vector<std::pair<http_curl::Request, std::unique_ptr<Task>>> new_tasks;

        CurlDataStructure();
        void queue_task
        (
            http_curl::Request request,
            Task::Handler completion_handler,
            boost::asio::any_completion_executor executor
        );
        void run();

        void process_pending_new_tasks();
        void process_finished_task(CURL* curl, CURLcode result);
    };

    template<typename E, typename F>
    void handle_error(E e, char const* code, std::source_location const& l, F&& action, char const* error_buffer = nullptr);
    std::string curl_error_to_string(char const* error, char const* code, std::source_location const& l);
    void log_curl_error_to_string(char const* error, char const* code, std::source_location const& l);
    void throw_curl_error_to_string(char const* error, char const* code, std::source_location const& l);
#define LOG_IF_CURL_ERROR(action) handle_error(action, #action, std::source_location::current(), log_curl_error_to_string)
#define THROW_IF_CURL_ERROR(action) handle_error(action, #action, std::source_location::current(), throw_curl_error_to_string)
#define THROW_IF_CURL_ERROR_DETAILED(action, error_buffer) handle_error(action, #action, std::source_location::current(), throw_curl_error_to_string, error_buffer.data())

    auto constexpr curl_poll_wait_time_milliseconds = 1000;

    std::shared_ptr<CurlDataStructure> curl_data_structure;
}

void http_curl::start_curl_thread()
{
    FAIL_FAST_IF_MSG(curl_data_structure != nullptr, "CurlDataStructure already initialized");
    auto pointer = std::make_shared<CurlDataStructure>();
    curl_data_structure = pointer;
    auto runner = [pointer]
    {
        try
        {
            pointer->run();
        }
        CATCH_FAIL_FAST_MSG("exception in start_curl_thread runner");
    };
    std::jthread{ std::move(runner) }.detach();
}

void http_curl::detail::queue_http_request
(
    boost::asio::any_completion_handler<http_curl::ResultSignature> completion_handler,
    http_curl::Request request,
    boost::asio::any_completion_executor executor
)
{
    FAIL_FAST_IF_MSG(curl_data_structure == nullptr, "CurlDataStructure not initialized");
    try
    {
        curl_data_structure->queue_task
        (
            std::move(request),
            std::move(completion_handler),
            std::move(executor)
        );
    }
    CATCH_FAIL_FAST_MSG("exception in async initiation");
}

void http_curl::detail::wake_up_curl_thread()
{
    FAIL_FAST_IF_MSG(curl_data_structure == nullptr, "CurlDataStructure not initialized");
    // This will wake up the curl thread to process new tasks
    curl_multi_wakeup(curl_data_structure->multi_handle.get());
}

namespace
{
    Task::~Task() noexcept
    {
        cancel();
    }

    void Task::initialize_request(http_curl::Request const& request)
    {
        FAIL_FAST_IF_MSG(curl, "Task already has a CURL handle");
        curl = CurlEasyHandle{ curl_easy_init() };
        THROW_HR_IF_NULL_MSG(E_UNEXPECTED, curl.get(), "Failed to initialize CURL");
        curl_error.resize(CURL_ERROR_SIZE);
        THROW_IF_CURL_ERROR(curl_easy_setopt(curl.get(), CURLOPT_ERRORBUFFER, curl_error.data()));

        CURL* c = curl.get();
        auto& e = curl_error;

        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_URL, request.url.c_str()), e);
        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L), e);
        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_TIMEOUT, request.timeout), e);
        // accept all compression encoding
        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_ACCEPT_ENCODING, ""), e);

        if (not request.request_headers.empty())
        {
            auto& headers_list = request_headers;
            headers_list.reset();
            for (auto const& header : request.request_headers)
            {
                headers_list.reset(curl_slist_append(headers_list.get(), header.c_str()));
            }
            THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers_list.get()), e);
        }
        if (not request.user_agent.empty())
        {
            THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_USERAGENT, request.user_agent.c_str()), e);
        }
        if (not request.body.empty())
        {
            curl_off_t size = request.body.size();
            THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_POSTFIELDS, request.body.c_str()), e);
            THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE_LARGE, size), e);
        }

        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, &body_reader), e);
        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_WRITEDATA, &response), e);

        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_HEADERFUNCTION, &response_header_reader), e);
        THROW_IF_CURL_ERROR_DETAILED(curl_easy_setopt(c, CURLOPT_HEADERDATA, &response), e);

        utils::log_output("curl initializing on thread {}", std::this_thread::get_id());
    }

    void Task::add_to_multi(CURLM* destination)
    {
        FAIL_FAST_IF_MSG(curl == nullptr, "no curl handle in task");
        FAIL_FAST_IF_MSG(multi != nullptr, "task already running");
        multi = destination;
        THROW_IF_CURL_ERROR(curl_multi_add_handle(multi, curl.get()));
    }

    void Task::remove_from_multi()
    {
        // curl == nullptr and multi != nullptr can happen: moved from
        if (curl == nullptr or multi == nullptr)
        {
            return;
        }
        LOG_IF_CURL_ERROR(curl_multi_remove_handle(multi, curl.get()));
        multi = nullptr;
    }

    void Task::cancel() noexcept
    {
        try
        {
            if (multi)
            {
                remove_from_multi();
            }
            if (handler)
            {
                invoke_completion_handler(std::make_exception_ptr(std::system_error{ ECANCELED, std::generic_category() }));
            }
        }
        CATCH_LOG_MSG("exception when cancel task");
    }

    void Task::invoke_completion_handler(std::exception_ptr e)
    {
        utils::log_output("curl finishing on thread {}", std::this_thread::get_id());

        FAIL_FAST_IF_MSG(executor == nullptr, "executor not set");
        FAIL_FAST_IF_MSG(handler == nullptr, "handler not set");
        boost::asio::dispatch(executor, [h = std::move(handler), e = std::move(e), r = std::move(response)]() mutable
        {
            utils::log_output("curl dispatched handler on thread {}", std::this_thread::get_id());
            h(std::move(e), std::move(r));
        });
        e = nullptr;
        response = {};
    }

    std::size_t Task::body_reader(char* ptr, std::size_t size, std::size_t nmemb, void* userdata)
    {
        auto* response = static_cast<http_curl::Response*>(userdata);
        response->response_data.append(ptr, size * nmemb);
        return size * nmemb;
    }

    std::size_t Task::response_header_reader(char* ptr, std::size_t size, std::size_t nmemb, void* userdata)
    {
        auto* response = static_cast<http_curl::Response*>(userdata);
        std::string_view header{ ptr, size * nmemb };
        auto delimiter_pos = header.find(':');
        if (delimiter_pos == std::string_view::npos)
        {
            // Could be an empty line or a HTTP status line
            // ignore it
            return size * nmemb;
        }
        auto key = header.substr(0, delimiter_pos);
        auto value = header.substr(delimiter_pos + 1);
        // trim whitespace for value
        std::size_t value_start = value.find_first_not_of(" \t");
        if (value_start == std::string_view::npos)
        {
            utils::log_error("Invalid header value: {}", header);
            return size * nmemb; // Not a valid header, ignore it
        }
        value = value.substr(value_start);
        // trim trailing newline
        std::size_t value_end = value.find_last_not_of(" \r\n");
        if (value_end != std::string_view::npos)
        {
            value = value.substr(0, value_end + 1);
        }
        response->response_headers.emplace_back(std::string{ key }, std::string{ value });
        return size * nmemb;
    }

    CurlDataStructure::CurlDataStructure()
    {
        multi_handle = CurlMultiHandle{ curl_multi_init() };
        THROW_HR_IF_NULL_MSG(E_UNEXPECTED, multi_handle.get(), "Failed to initialize CURL multi");
    }

    void CurlDataStructure::queue_task
    (
        http_curl::Request request,
        Task::Handler completion_handler,
        boost::asio::any_completion_executor executor
    )
    {
        auto new_task = std::make_unique<Task>();
        new_task->executor = std::move(executor);
        new_task->handler = std::move(completion_handler);
        {
            std::scoped_lock lock{ new_tasks_mutex };
            new_tasks.emplace_back(std::move(request), std::move(new_task));
        }
        // wake up the multi handle to process the new task
        curl_multi_wakeup(multi_handle.get());
    }

    void CurlDataStructure::run()
    {
        while (true)
        {
            process_pending_new_tasks();
            int running_handles = 0;
            CURLMcode result = curl_multi_perform(multi_handle.get(), &running_handles);
            if (result != CURLM_OK)
            {
                utils::log_error("curl_multi_perform failed, cancel everything, error: {}", curl_multi_strerror(result));
                // cancel everything
                for (auto& [p, task] : executing_tasks)
                {
                    task->cancel();
                }
                executing_tasks.clear();
                continue;
            }
            while (true)
            {
                int messages_in_queue = 0;
                CURLMsg* message = curl_multi_info_read(multi_handle.get(), &messages_in_queue);
                if (message == nullptr)
                {
                    break;
                }
                if (message->msg != CURLMSG_DONE)
                {
                    continue;
                }
                process_finished_task(message->easy_handle, message->data.result);
            }
            LOG_IF_CURL_ERROR(curl_multi_poll(multi_handle.get(), nullptr, 0, curl_poll_wait_time_milliseconds, nullptr));
        }
    }

    void CurlDataStructure::process_pending_new_tasks()
    {
        std::decay_t<decltype(new_tasks)> current_pending_tasks;
        {
            std::scoped_lock lock{ new_tasks_mutex };
            current_pending_tasks.swap(new_tasks);
        }
        for (auto& [request, task] : current_pending_tasks)
        {
            try
            {
                task->initialize_request(request);
                task->add_to_multi(multi_handle.get());
                CURL* handle = task->curl.get();
                executing_tasks[handle] = std::move(task);
            }
            catch (...)
            {
                task->invoke_completion_handler(std::current_exception());
            }
        }
    }

    void CurlDataStructure::process_finished_task(CURL* curl, CURLcode result)
    {
        auto iterator = executing_tasks.find(curl);
        if (iterator == executing_tasks.end())
        {
            utils::log_error("invalid curl handle when processing finished task: {}", curl);
            return;
        }
        std::unique_ptr task = std::move(iterator->second);
        executing_tasks.erase(iterator);
        if (task == nullptr)
        {
            utils::log_error("unexpected null task from curl handle: {}", curl);
            return;
        }
        task->remove_from_multi();
        try
        {
            THROW_IF_CURL_ERROR_DETAILED(result, task->curl_error);
        }
        catch (...)
        {
            task->invoke_completion_handler(std::current_exception());
            return;
        }
        task->invoke_completion_handler(nullptr);
    }

    template<typename E, typename F>
    void handle_error(E e, char const* code, std::source_location const& l, F&& action, char const* error_buffer)
    {
        std::string detailed_error;
        char const* error = nullptr;
        if constexpr (std::same_as<E, CURLcode>)
        {
            if (e != CURLcode::CURLE_OK)
            {
                error = curl_easy_strerror(e);
            }
        }
        else
        {
            static_assert(std::same_as<E, CURLMcode>);
            if (e != CURLMcode::CURLM_OK)
            {
                error = curl_multi_strerror(e);
            }
        }
        if (error != nullptr)
        {
            std::string_view buffer_view;
            if (error_buffer != nullptr)
            {
                buffer_view = error_buffer;
            }
            if (not buffer_view.empty())
            {
                detailed_error = std::format("{} -> {}", error, buffer_view);
                error = detailed_error.c_str();
            }
            action(error, code, l);
        }
    }

    std::string curl_error_to_string(char const* error, char const* code, std::source_location const& l)
    {
        return std::format("curl error: {}; code: {}; in {}:{} {}", error, code, l.file_name(), l.line(), l.function_name());
    }

    void log_curl_error_to_string(char const* error, char const* code, std::source_location const& l)
    {
        utils::log_error("{}", curl_error_to_string(error, code, l));
    }

    void throw_curl_error_to_string(char const* error, char const* code, std::source_location const& l)
    {
        throw std::runtime_error{ curl_error_to_string(error, code, l) };
    }
}
