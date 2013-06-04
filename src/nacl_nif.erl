-module(nacl_nif).

-export([randombytes/1,
         hash/1,
         box_keypair/0,
         box_random_nonce/0,
         box_ZEROBYTES/0,
         box_BOXZEROBYTES/0,
         box_padded/4,
         box_open_padded/4,
         secretbox/3,
         secretbox/2,
         secretbox_random_nonce/0,
         secretbox_new_key/0,
         secretbox_open/3,
         secretbox_open/2,
         secretbox_ZEROBYTES/0,
         secretbox_BOXZEROBYTES/0,
         secretbox_NONCEBYTES/0,
         secretbox_KEYBYTES/0
        ]).

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
box_ZEROBYTES() -> erlang:nif_error(not_loaded).
box_BOXZEROBYTES() -> erlang:nif_error(not_loaded).
box_padded(_PaddedMsg, _Nonce, _Pk, _Sk) -> erlang:nif_error(not_loaded).
box_open_padded(_PaddedCipher, _Nonce, _Pk, _Sk) -> erlang:nif_error(not_loaded).
secretbox(_Msg, _Nonce, _Key) -> erlang:nif_error(not_loaded).
secretbox_open(_Ciphertext, _Nonce, _Key) -> erlang:nif_error(not_loaded).
secretbox_ZEROBYTES() -> erlang:nif_error(not_loaded).
secretbox_BOXZEROBYTES() -> erlang:nif_error(not_loaded).
secretbox_NONCEBYTES() -> erlang:nif_error(not_loaded).
secretbox_KEYBYTES() -> erlang:nif_error(not_loaded).


secretbox_new_key() -> 
    randombytes(secretbox_KEYBYTES()).
secretbox_random_nonce() ->
    randombytes(secretbox_NONCEBYTES()).

secretbox(Msg, Key) ->
    Nonce = secretbox_random_nonce(),
    Enc = secretbox([binary:copy(<<0>>, secretbox_ZEROBYTES()), Msg], Nonce, Key),
    {enc, Nonce, Enc}.
    
secretbox_open({enc, Nonce, Enc}, Key) ->
    secretbox_open([binary:copy(<<0>>, secretbox_BOXZEROBYTES()), Enc], Nonce, Key).
    

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

pk1() -> <<16#de1042928b74e9f96cf3f3e290c16cb4eba9c696e9a1e15c7f4d0514ddce1154:256>>.
sk1() -> <<16#d54ff4b666a43070ab20937a92c49ecf65503583f8942350fc197c5023b015c3:256>>.

box_test() ->
    Nonce = <<16#065114ca5a687e0544a88e6fc757b30afc70a0355854fd54:192>>,
    Msg = <<"hello">>,
    Boxed = box_padded([binary:copy(<<0>>, box_ZEROBYTES()), Msg], Nonce, pk1(), sk1()),
    ?assertEqual("3bc95b7983622e8afb763723703e17c6739be9c316", b2h(Boxed)),
    Unboxed = box_open_padded([binary:copy(<<0>>, box_BOXZEROBYTES()), Boxed], Nonce, pk1(), sk1()),
    ?assertEqual(<<"hello">>, Unboxed).

secretbox_test() ->
    K       = secretbox_new_key(),
    Msg     = <<"hello">>,
    Enc     = secretbox(Msg, K),
    {ok, M} = secretbox_open(Enc, K),
    ?assertEqual(Msg, M).

-endif.
