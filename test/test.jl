using GnuTLS
using Base.Test

h = HMACState(MD5,"")
update(h,"")
@test join(map(x->hex(x,2),digest!(h)),"") == "74e6f7298a9c2d168935f58c001bad88"
h = HMACState(SHA1,"")
update(h,"")
@test join(map(x->hex(x,2),digest!(h)),"") == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
h = HMACState(SHA256,"")
update(h,"")
@test join(map(x->hex(x,2),digest!(h)),"") == "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
h = HMACState(MD5,"key")
update(h,"The quick brown fox jumps over the lazy dog")
@test join(map(x->hex(x,2),digest!(h)),"") == "80070713463e7749b90c2dc24911e275"
h = HMACState(SHA1,"key")
update(h,"The quick brown fox jumps over the lazy dog")
@test join(map(x->hex(x,2),digest!(h)),"") == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
h = HMACState(SHA256,"key")
update(h,"The quick brown fox jumps over the lazy dog")
@test join(map(x->hex(x,2),digest!(h)),"") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

