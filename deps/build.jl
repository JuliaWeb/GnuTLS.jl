using BinDeps

@BinDeps.setup

nettle = library_dependency("nettle", aliases = ["libnettle"], runtime = false)
gnutls = library_dependency("gnutls", aliases = ["libgnutls","libgnutls28"], depends = [nettle])

#@BinDeps.if_install begin

provides(Sources,{
	URI("http://www.lysator.liu.se/~nisse/archive/nettle-2.7.tar.gz") => nettle,
	URI("ftp://ftp.gnutls.org/gcrypt/gnutls/v3.2/gnutls-3.2.1.tar.xz") => gnutls})

provides(Binaries,URI("ftp://ftp.gnutls.org/gcrypt/gnutls/w32/gnutls-3.2.1-w32.zip"),gnutls,os = :Windows)

provides(Homebrew,"gnutls",gnutls)
provides(AptGet,"libgnutls28",gnutls)
provides(Yum,"libgnutls",gnutls)

libdirs = String["/Users/keno/Documents/src/julia/usr/lib"]
includedirs = String["/Users/keno/Documents/src/julia/usr/include"]

ENV["LD_LIBRARY_PATH"]="/Users/keno/Documents/src/julia/usr/lib"
provides(BuildProcess,
	{
		Autotools(lib_dirs = libdirs, include_dirs = includedirs, env = {"LIBS" => "-lgmp "}) => nettle,
		Autotools(libtarget = "lib/libgnutls.la", lib_dirs = libdirs, include_dirs = includedirs, env = {"LIBS" => "-lgmp "}) => gnutls
	})

@BinDeps.install

#end