using GnuTLS
using Base.Test

h = initHMAC(MD5,"")
update(h,"")
@test join(map(x->hex(x,2),takeresult!(h)),"") == "74e6f7298a9c2d168935f58c001bad88"
h = initHMAC(SHA1,"")
update(h,"")
@test join(map(x->hex(x,2),takeresult!(h)),"") == "fbdb1d1b18aa6c08324b7d64b71fb76370690e1d"
h = initHMAC(SHA256,"")
update(h,"")
@test join(map(x->hex(x,2),takeresult!(h)),"") == "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
h = initHMAC(MD5,"key")
update(h,"The quick brown fox jumps over the lazy dog")
@test join(map(x->hex(x,2),takeresult!(h)),"") == "80070713463e7749b90c2dc24911e275"
h = initHMAC(SHA1,"key")
update(h,"The quick brown fox jumps over the lazy dog")
@test join(map(x->hex(x,2),takeresult!(h)),"") == "de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9"
h = initHMAC(SHA256,"key")
update(h,"The quick brown fox jumps over the lazy dog")
@test join(map(x->hex(x,2),takeresult!(h)),"") == "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"

