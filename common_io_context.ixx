module;
#include <boost/asio/io_context.hpp>
#include <wil/result_macros.h>
export module common_io_context;

export namespace common_io_context
{
    // The common io context is a shared io context which should be used for
    // all asynchronous operations, except local relay.
    // Local relay uses its own io context to avoid being interfered by other
    // asynchronous operations.
    boost::asio::io_context& get_io_context();
    // Start and run the common io context.
    // This function will block and should run forever.
    // It's recommended to call this function in a separate thread.
    void blocking_run_io_context();
}

module: private;
import utils;

boost::asio::io_context& common_io_context::get_io_context()
{
    static boost::asio::io_context io;
    return io;
}

void common_io_context::blocking_run_io_context()
{
    utils::log_info("running common io context");
    try
    {
        auto& io = get_io_context();
        auto guard = boost::asio::make_work_guard(io);
        io.run();
    }
    CATCH_LOG_MSG("common io context exception");
    utils::log_error("common io context stopped");
}
