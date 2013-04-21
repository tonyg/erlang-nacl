#include "erl_nif.h"

#include <sodium.h>

static ERL_NIF_TERM nacl_randombytes(ErlNifEnv* env, int argc, ERL_NIF_TERM const argv[])
{
  unsigned int requested_size;
  ErlNifBinary result;

  if (!enif_get_uint(env, argv[0], &requested_size))
    return enif_make_badarg(env);

  if (!enif_alloc_binary(requested_size, &result))
    return enif_make_badarg(env); /* TODO: distinguish from other badarg? */

  randombytes(result.data, result.size);

  return enif_make_binary(env, &result);
}

static ErlNifFunc nif_funcs[] = {
  {"randombytes", 1, nacl_randombytes}
};

ERL_NIF_INIT(nacl_nif, nif_funcs, NULL, NULL, NULL, NULL);
