#include "erl_nif.h"

#include <sodium.h>

static ERL_NIF_TERM nacl_error_tuple(ErlNifEnv *env, char *error_atom) {
  return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error_atom));
}

static ERL_NIF_TERM nacl_randombytes(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  unsigned int requested_size;
  ErlNifBinary result;

  if (!enif_get_uint(env, argv[0], &requested_size))
    return enif_make_badarg(env);

  if (!enif_alloc_binary(requested_size, &result))
    return nacl_error_tuple(env, "alloc_failed");

  randombytes(result.data, result.size);

  return enif_make_binary(env, &result);
}

static ERL_NIF_TERM nacl_hash(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary input;
  ErlNifBinary result;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &input))
    return enif_make_badarg(env);

  if (!enif_alloc_binary(crypto_hash_BYTES, &result))
    return nacl_error_tuple(env, "alloc_failed");

  crypto_hash(result.data, input.data, input.size);

  return enif_make_binary(env, &result);
}

static ERL_NIF_TERM nacl_box_keypair(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary pk, sk;

  if (!enif_alloc_binary(crypto_box_PUBLICKEYBYTES, &pk))
    return nacl_error_tuple(env, "alloc_failed");

  if (!enif_alloc_binary(crypto_box_SECRETKEYBYTES, &sk))
    return nacl_error_tuple(env, "alloc_failed");

  crypto_box_keypair(pk.data, sk.data);

  return enif_make_tuple3(env,
			  enif_make_atom(env, "nacl_box_keypair"),
			  enif_make_binary(env, &pk),
			  enif_make_binary(env, &sk));
}

static ERL_NIF_TERM nacl_box_random_nonce(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary result;

  if (!enif_alloc_binary(crypto_box_NONCEBYTES, &result))
    return nacl_error_tuple(env, "alloc_failed");

  randombytes(result.data, result.size);

  return enif_make_binary(env, &result);
}

static ERL_NIF_TERM nacl_box_ZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  return enif_make_int64(env, crypto_box_ZEROBYTES);
}

static ERL_NIF_TERM nacl_box_BOXZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  return enif_make_int64(env, crypto_box_BOXZEROBYTES);
}

static ERL_NIF_TERM nacl_box_padded(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary padded_msg;
  ErlNifBinary nonce;
  ErlNifBinary pk;
  ErlNifBinary sk;
  ErlNifBinary result;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &padded_msg))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[1], &nonce))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[2], &pk))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[3], &sk))
    return enif_make_badarg(env);

  if (nonce.size != crypto_box_NONCEBYTES) return enif_make_badarg(env);
  if (pk.size != crypto_box_PUBLICKEYBYTES) return enif_make_badarg(env);
  if (sk.size != crypto_box_SECRETKEYBYTES) return enif_make_badarg(env);
  if (padded_msg.size < crypto_box_ZEROBYTES) return enif_make_badarg(env);

  if (!enif_alloc_binary(padded_msg.size, &result))
    return nacl_error_tuple(env, "alloc_failed");

  crypto_box(result.data, padded_msg.data, padded_msg.size, nonce.data, pk.data, sk.data);

  return enif_make_sub_binary(env,
			      enif_make_binary(env, &result),
			      crypto_box_BOXZEROBYTES,
			      padded_msg.size - crypto_box_BOXZEROBYTES);
}

static ERL_NIF_TERM nacl_box_open_padded(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary padded_ciphertext;
  ErlNifBinary nonce;
  ErlNifBinary pk;
  ErlNifBinary sk;
  ErlNifBinary result;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &padded_ciphertext))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[1], &nonce))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[2], &pk))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[3], &sk))
    return enif_make_badarg(env);

  if (nonce.size != crypto_box_NONCEBYTES) return enif_make_badarg(env);
  if (pk.size != crypto_box_PUBLICKEYBYTES) return enif_make_badarg(env);
  if (sk.size != crypto_box_SECRETKEYBYTES) return enif_make_badarg(env);
  if (padded_ciphertext.size < crypto_box_BOXZEROBYTES) return enif_make_badarg(env);

  if (!enif_alloc_binary(padded_ciphertext.size, &result))
    return nacl_error_tuple(env, "alloc_failed");

  crypto_box_open(result.data, padded_ciphertext.data, padded_ciphertext.size,
		  nonce.data, pk.data, sk.data);

  return enif_make_sub_binary(env,
			      enif_make_binary(env, &result),
			      crypto_box_ZEROBYTES,
			      padded_ciphertext.size - crypto_box_ZEROBYTES);
}


static ERL_NIF_TERM nacl_secretbox(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary key;
  ErlNifBinary nonce;
  ErlNifBinary padded_message;
  ErlNifBinary padded_ciphertext;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &padded_message))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[1], &nonce))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[2], &key))
    return enif_make_badarg(env);

  if (key.size != crypto_secretbox_KEYBYTES) return enif_make_badarg(env);
  if (nonce.size !=  crypto_secretbox_NONCEBYTES) return enif_make_badarg(env);
  if (padded_message.size < crypto_secretbox_ZEROBYTES) return enif_make_badarg(env);

  if (!enif_alloc_binary(padded_message.size, &padded_ciphertext))
    return nacl_error_tuple(env, "alloc_failed");

  crypto_secretbox(
      padded_ciphertext.data, 
      padded_message.data,
      padded_message.size,
      nonce.data,
      key.data
  );

  return enif_make_sub_binary(env,
			      enif_make_binary(env, &padded_ciphertext),
			      crypto_secretbox_BOXZEROBYTES,
			      padded_message.size - crypto_secretbox_BOXZEROBYTES);
}

static ERL_NIF_TERM nacl_secretbox_open(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary key;
  ErlNifBinary nonce;
  ErlNifBinary padded_ciphertext;
  ErlNifBinary padded_message;
  
  int err;

  if (!enif_inspect_iolist_as_binary(env, argv[0], &padded_ciphertext))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[1], &nonce))
    return enif_make_badarg(env);

  if (!enif_inspect_iolist_as_binary(env, argv[2], &key))
    return enif_make_badarg(env);

  if (key.size != crypto_secretbox_KEYBYTES) return enif_make_badarg(env);
  if (nonce.size !=  crypto_secretbox_NONCEBYTES) return enif_make_badarg(env);
  if (padded_ciphertext.size < crypto_secretbox_BOXZEROBYTES) return enif_make_badarg(env);

  if (!enif_alloc_binary(padded_ciphertext.size, &padded_message))
    return nacl_error_tuple(env, "alloc_failed");

  err = crypto_secretbox_open(
      padded_message.data, 
      padded_ciphertext.data,
      padded_ciphertext.size,
      nonce.data,
      key.data
  );

  if (err != 0) {
    // Authentication of ciphertext failed
    return enif_make_tuple2(
      env,
      enif_make_atom_len(env, "error", 5),
      enif_make_atom_len(env, "bad_signature", 13)
    );

  } else {

    // Successful decryption
    return enif_make_tuple2(
      env,
      enif_make_atom_len(env, "ok", 2),
      enif_make_sub_binary(
        env,
        enif_make_binary(env, &padded_message),
        crypto_secretbox_ZEROBYTES,
        padded_ciphertext.size - crypto_secretbox_ZEROBYTES
      )
    );

  }

}

static ERL_NIF_TERM nacl_secretbox_ZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  return enif_make_int64(env, crypto_secretbox_ZEROBYTES);
}

static ERL_NIF_TERM nacl_secretbox_BOXZEROBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  return enif_make_int64(env, crypto_secretbox_BOXZEROBYTES);
}

static ERL_NIF_TERM nacl_secretbox_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  return enif_make_int64(env, crypto_secretbox_KEYBYTES);
}

static ERL_NIF_TERM nacl_secretbox_NONCEBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
  return enif_make_int64(env, crypto_secretbox_NONCEBYTES);
}


static ErlNifFunc nif_funcs[] = {
  {"randombytes", 1, nacl_randombytes},
  {"hash", 1, nacl_hash},
  {"box_keypair", 0, nacl_box_keypair},
  {"box_random_nonce", 0, nacl_box_random_nonce},
  {"box_ZEROBYTES", 0, nacl_box_ZEROBYTES},
  {"box_BOXZEROBYTES", 0, nacl_box_BOXZEROBYTES},
  {"box_padded", 4, nacl_box_padded},
  {"box_open_padded", 4, nacl_box_open_padded},
  {"secretbox", 3, nacl_secretbox},
  {"secretbox_open", 3, nacl_secretbox_open},
  {"secretbox_ZEROBYTES", 0, nacl_secretbox_ZEROBYTES},
  {"secretbox_BOXZEROBYTES", 0, nacl_secretbox_BOXZEROBYTES},
  {"secretbox_NONCEBYTES", 0, nacl_secretbox_NONCEBYTES},
  {"secretbox_KEYBYTES", 0, nacl_secretbox_KEYBYTES}
};

ERL_NIF_INIT(nacl_nif, nif_funcs, NULL, NULL, NULL, NULL);
