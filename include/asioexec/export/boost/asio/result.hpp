template < class... types > 
class async_result<asioexec::use_sender_t,void(types...)>
{
    public: // Interface
        static auto initiate ( auto&&, asioexec::use_sender_t, auto&&... );

    public: // Typedef
        using return_type = decltype(initiate([] (auto&&...) {}, std::declval<asioexec::use_sender_t>()));
};

template < class... types >
auto async_result<asioexec::use_sender_t,void(types...)>::initiate ( auto&& start_func, asioexec::use_sender_t, auto&&... start_args )
{
    auto sched_sender = std::execution::read_env(std::execution::get_scheduler);
    auto value_sender = std::execution::just(std::forward<decltype(start_func)>(start_func), std::forward<decltype(start_args)>(start_args)...);
    return std::execution::when_all(std::move(sched_sender), std::move(value_sender))
            | std::execution::let_value([] (auto&& sched, auto&&... args)
                {
                    if constexpr ( std::same_as<std::decay_t<types...[0]>,boost::system::error_code> )
                        return asioexec::sender<types...>(std::forward<decltype(args)>(args)...)
                            | std::execution::let_value([] (boost::system::error_code ec, auto&&... args)
                                {
                                    if ( ec )
                                        throw boost::system::system_error(ec);
                                    return std::execution::just(std::forward<decltype(args)>(args)...);
                                })
                            | std::execution::continues_on(std::forward<decltype(sched)>(sched));
                    else
                        return asioexec::sender<types...>(std::forward<decltype(args)>(args)...)
                            | std::execution::continues_on(std::forward<decltype(sched)>(sched));
                });
                
}