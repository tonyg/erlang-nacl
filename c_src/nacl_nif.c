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

static ErlNifFunc nif_funcs[] = {
  {"randombytes", 1, nacl_randombytes},
  {"hash", 1, nacl_hash}
};

ERL_NIF_INIT(nacl_nif, nif_funcs, NULL, NULL, NULL, NULL);
