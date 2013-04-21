-module(nacl_nif).

-export([randombytes/1]).

-on_load(init/0).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

init() -> erlang:load_nif(filename:join(nacl_app:priv_dir(), ?MODULE), 0).

randombytes(_Count) -> erlang:nif_error(not_loaded).

-ifdef(TEST).

basic_test() ->
    ?assertEqual(<<>>, randombytes(0)).

-endif.
