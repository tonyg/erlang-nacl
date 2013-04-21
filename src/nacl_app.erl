-module(nacl_app).

-behaviour(application).

-export([priv_dir/0]).
-export([start/2, stop/1]).

priv_dir() ->
    case code:priv_dir(scrypt) of
        {error, bad_name} ->
            filename:join(filename:dirname(filename:dirname(code:which(?MODULE))), "priv");
        D ->
            D
    end.

start(_StartType, _StartArgs) -> nacl_sup:start_link().
stop(_State) -> ok.
