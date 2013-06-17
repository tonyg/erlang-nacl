-module(nacl).

-export([randombytes/1,
         hash/1,
         box_keypair/0,
         box_random_nonce/0,
         box/4,
         box/3,
         box_open/4,
         box_open/3,
         secretbox_key/0,
         secretbox_random_nonce/0,
         secretbox/3,
         secretbox/2,
         secretbox_open/3,
         secretbox_open/2]).

-include("nacl.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

randombytes(Count) -> nacl_nif:randombytes(Count).
hash(Bytes) -> nacl_nif:hash(Bytes).
box_keypair() -> nacl_nif:box_keypair().
box_random_nonce() -> randombytes(nacl_nif:box_NONCEBYTES()).

box(Msg, Nonce, Pk, Sk) ->
    #nacl_envelope{nonce = Nonce,
                   ciphertext = nacl_nif:box_padded([binary:copy(<<0>>, nacl_nif:box_ZEROBYTES()),
                                                     Msg],
                                                    Nonce, Pk, Sk)}.

box(Msg, Pk, Sk) ->
    box(Msg, box_random_nonce(), Pk, Sk).

box_open(Ciph, Nonce, Pk, Sk) ->
    case nacl_nif:box_open_padded([binary:copy(<<0>>, nacl_nif:box_BOXZEROBYTES()), Ciph],
                                  Nonce, Pk, Sk) of
        {error, Error} ->
            {error, Error};
        Bin when is_binary(Bin) ->
            {ok, Bin}
    end.

box_open(#nacl_envelope{nonce = Nonce, ciphertext = Ciph}, Pk, Sk) ->
    box_open(Ciph, Nonce, Pk, Sk).

secretbox_key() -> randombytes(nacl_nif:secretbox_KEYBYTES()).
secretbox_random_nonce() -> randombytes(nacl_nif:secretbox_NONCEBYTES()).

secretbox(Msg, Nonce, Key) ->
    PaddedMsg = [binary:copy(<<0>>, nacl_nif:secretbox_ZEROBYTES()), Msg],
    #nacl_envelope{nonce = Nonce,
                   ciphertext = nacl_nif:secretbox_padded(PaddedMsg, Nonce, Key)}.

secretbox(Msg, Key) ->
    secretbox(Msg, secretbox_random_nonce(), Key).

secretbox_open(Ciph, Nonce, Key) ->
    PaddedCiph = [binary:copy(<<0>>, nacl_nif:secretbox_BOXZEROBYTES()), Ciph],
    case nacl_nif:secretbox_open_padded(PaddedCiph, Nonce, Key) of
        {error, Error} ->
            {error, Error};
        Bin when is_binary(Bin) ->
            {ok, Bin}
    end.

secretbox_open(#nacl_envelope{nonce = Nonce, ciphertext = Ciph}, Key) ->
    secretbox_open(Ciph, Nonce, Key).

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
    Boxed = box(Msg, Nonce, pk1(), sk1()),
    ?assertEqual(Nonce, Boxed#nacl_envelope.nonce),
    ?assertEqual("3bc95b7983622e8afb763723703e17c6739be9c316", b2h(Boxed#nacl_envelope.ciphertext)),
    {ok, Unboxed} = box_open(Boxed, pk1(), sk1()),
    ?assertEqual(<<"hello">>, Unboxed).

box_freshnonce_test() ->
    ?assertEqual({ok, <<"hello">>}, box_open(box(<<"hello">>, pk1(), sk1()), pk1(), sk1())).

box_open_fail_test() ->
    GoodEnvelope =
        #nacl_envelope{nonce = <<16#065114ca5a687e0544a88e6fc757b30afc70a0355854fd54:192>>,
                       ciphertext = <<16#3bc95b7983622e8afb763723703e17c6739be9c316:168>>},
    BadEnvelope =
        #nacl_envelope{nonce = <<16#065114ca5a687e0544a88e6fc757b30afc70a0355854fd54:192>>,
                       ciphertext = <<16#3bc95b7983622e8afb763723703e17c6739be9c317:168>>},
    ?assertEqual({ok, <<"hello">>}, box_open(GoodEnvelope, pk1(), sk1())),
    ?assertEqual({error, crypto_failed}, box_open(BadEnvelope, pk1(), sk1())).

secretbox_test() ->
    K       = secretbox_key(),
    Msg     = <<"hello">>,
    Enc     = secretbox(Msg, K),
    {ok, M} = secretbox_open(Enc, K),
    ?assertEqual(Msg, M).

secretbox_unauth_test() ->
    K       = secretbox_key(),
    Msg     = <<"hello">>,
    #nacl_envelope{nonce = Non, ciphertext = Cip} = secretbox(Msg, K),
    CipBad  = randombytes(size(Cip)),
    {error, Err} = secretbox_open(#nacl_envelope{nonce = Non, ciphertext = CipBad}, K),
    ?assertEqual(Err, crypto_failed).

-endif.
