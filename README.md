GnuTLS.jl
=========

Add transport layer security (TLS) to any Julia Stream

[![Build Status](https://travis-ci.org/JuliaWeb/GnuTLS.jl.svg?branch=master)](https://travis-ci.org/JuliaWeb/GnuTLS.jl)
[![Coverage Status](https://coveralls.io/repos/JuliaWeb/GnuTLS.jl/badge.svg?branch=master&service=github)](https://coveralls.io/github/JuliaWeb/GnuTLS.jl?branch=master)

**Installation**: `Pkg.add("GnuTLS")`

# API

GnuTLS.jl can add TLS support to any transport layer implementing the Julia `IO`interface (e.g. IOStream, TcpSocket, NamedPipe, TTY, ...)

The following functions are currently provided:

* `GnuTLS.Session()`

	Create a new SSL/TLS session. After initialization this object becomes a valid Julia `IO` object and may be used as such. 

	NOTE: This method is not exported by default and should be used as `GnuTLS.Session`

* `GnuTLS.CertificateStore()`

	Initialize an empty certificate store. Support for authentication is incomplete in the current version.

	NOTE: This method is not exported by default and should be used as `GnuTLS.CertificateStore`

* `set_credentials!(s::Session,c::CertificateStore)`

	Associates the CertificateStore `c` with the session `s`. The certificate from the server will be stored here and may later be validated before processing further requests. 

* `set_priority_string!(s::Session,priority::ASCIIString="NORMAL")`

	Set the GnuTLS priority string, used to determine which protocol versions to support. For a full list of supported options, see the [GnuTLS manual](http://www.gnutls.org/manual/gnutls.html#Priority-Strings). 

* `associate_stream{S<:IO,T<:IO}(s::Session, read::S, write::T=read)`

	Set the transport layer for the current session. 

* `handshake!(s::Session)`

	Perform the SSL/TLS handshake. On success the Session becomes active and may be used like any other streaming `IO` object. 

* `init()` 
	
	Initialize the GnuTLS library. This function is automatically called when the package is loaded and thus you should rarely have to call it yourself. 

* `deinit()`

	Undo `init` and free all associated resources. 

# Usage

The following code snippet demonstrates how the GnuTLS.jl package may be used to query an HTTPS resource:

```julia
	using GnuTLS
	sess = GnuTLS.Session()
	set_priority_string!(sess)
	set_credentials!(sess,GnuTLS.CertificateStore())
	associate_stream(sess,connect("github.com",443))
	handshake!(sess)
	write(sess,"GET / HTTP/1.1\r\n\r\n")
	print(readall(sess))
```
