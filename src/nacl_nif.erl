-module(nacl_nif).

-export([randombytes/1,
         hash/1,
         box_keypair/0,
         box_random_nonce/0]).

-on_load(init/0).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-include("nacl.hrl").
-endif.

init() -> erlang:load_nif(filename:join(nacl_app:priv_dir(), ?MODULE), 0).

randombytes(_Count) -> erlang:nif_error(not_loaded).
hash(_Bytes) -> erlang:nif_error(not_loaded).
box_keypair() -> erlang:nif_error(not_loaded).
box_random_nonce() -> erlang:nif_error(not_loaded).

-ifdef(TEST).

%% Super weird that this isn't in the standard library. Perhaps it is
%% and I've overlooked or forgotten about it.
b2h(B) -> lists:flatten([io_lib:format("~2.16.0b",[N]) || <<N>> <= B]).

basic_test() ->
    ?assertEqual(<<>>, randombytes(0)).

hash_test() ->
    ?assertEqual("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ++
                     "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
                 b2h(hash(<<>>))),
    ?assertEqual("07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64" ++
                     "2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6",
                 b2h(hash(<<"The quick brown fox jumps over the lazy dog">>))),
    ?assertEqual("91ea1245f20d46ae9a037a989f54f1f790f0a47607eeb8a14d12890cea77a1bb" ++
                     "c6c7ed9cf205e67b7f2b8fd4c7dfd3a7a8617e45f3c463d481c7e586c39ac1ed",
                 b2h(hash(<<"The quick brown fox jumps over the lazy dog.">>))).

box_keypair_test() ->
    #nacl_box_keypair{pk = PK, sk = SK} = box_keypair(),
    ?assertEqual(true, is_binary(PK)),
    ?assertEqual(true, is_binary(SK)).

box_random_nonce_test() ->
    ?assertEqual(true, is_binary(box_random_nonce())).

-endif.
