import bearssl, strutils
from os import DirSep

const
  bearPath = currentSourcePath.rsplit(DirSep, 1)[0] & DirSep &
             "bearssl_pkey_decoder" & DirSep & "csources"

{.passC: "-I" & bearPath.}

{.compile: bearPath & DirSep & "bearssl_pkey_decoder.c".}

# This pragma should be the same as in nim-bearssl/decls.nim
{.pragma: bearSslFunc, cdecl, gcsafe, noSideEffect, raises: [].}

type
  INNER_C_UNION_KEY* {.importc: "no_name", header: "bearssl_x509.h", bycopy, union.} = object
    rsa* {.importc: "rsa".}: RsaPublicKey
    ec* {.importc: "ec".}: EcPublicKey

  INNER_C_STRUCT_CPU* {.importc: "no_name", header: "bearssl_x509.h", bycopy.} = object
    dp* {.importc: "dp".}: ptr uint32
    rp* {.importc: "rp".}: ptr uint32
    ip* {.importc: "ip".}: ptr cuchar

  PkeyDecoderContext* {.importc: "br_pkey_decoder_context", header: "bearssl_pkey_decoder.h", bycopy.} = object
    key* {.importc: "key".}: INNER_C_UNION_KEY
    cpu* {.importc: "cpu".}: INNER_C_STRUCT_CPU
    dpStack* {.importc: "dp_stack".}: array[32, uint32]
    rpStack* {.importc: "rp_stack".}: array[32, uint32]
    err* {.importc: "err".}: cint
    hbuf* {.importc: "hbuf".}: pointer
    pad*: array[256, byte]
    key_type*: uint8
    key_data*: array[3 * X509_BUFSIZE_SIG, byte]

proc pkeyDecoderInit*(ctx: ptr PkeyDecoderContext) {.bearSslFunc,
    importc: "br_pkey_decoder_init", header: "bearssl_pkey_decoder.h".}

proc pkeyDecoderPush*(ctx: ptr PkeyDecoderContext; data: pointer; len: uint) {.bearSslFunc,
    importc: "br_pkey_decoder_push", header: "bearssl_pkey_decoder.h".}


proc pkeyDecoderLastError*(ctx: ptr PkeyDecoderContext): cint =
  if ctx.err != 0: return ctx.err
  if ctx.key_type == 0: return ERR_X509_TRUNCATED

proc pkeyDecoderKeyType*(ctx: ptr PkeyDecoderContext): cint =
  if ctx.err == 0:
    return cast[cint](ctx.key_type)
  else:
    return 0

proc pkeyDecoderGetRsa*(ctx: ptr PkeyDecoderContext): ptr RsaPublicKey =
  if ctx.err == 0 and ctx.key_type == KEYTYPE_RSA:
    return addr ctx.key.rsa

proc pkeyDecoderGetEc*(ctx: ptr PkeyDecoderContext): ptr EcPublicKey =
  if ctx.err == 0 and ctx.key_type == KEYTYPE_EC:
    return addr ctx.key.ec
