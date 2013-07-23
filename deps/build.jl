using BinDeps

@BinDeps.setup

nettle = library_dependency("nettle", aliases = ["libnettle"], runtime = false)
gnutls = library_dependency("gnutls", aliases = ["libgnutls","libgnutls28"], depends = [nettle], validate = function(p,h)
	dlsym_e(h,:gnutls_certificate_set_x509_system_trust) != C_NULL
end)

provides(Sources,{
	URI("http://www.lysator.liu.se/~nisse/archive/nettle-2.7.tar.gz") => nettle,
	URI("ftp://ftp.gnutls.org/gcrypt/gnutls/v3.2/gnutls-3.2.1.tar.xz") => gnutls})

provides(Binaries,URI("ftp://ftp.gnutls.org/gcrypt/gnutls/w32/gnutls-3.2.1-w32.zip"),gnutls,os = :Windows)

provides(Homebrew,"gnutls",gnutls)
provides(AptGet,"libgnutls28",gnutls) # Yes, this is the most current version, I guess they broke binary compatibility in v2.8?
provides(Yum,"libgnutls",gnutls)

julia_usrdir = normpath(JULIA_HOME*"/../") # This is a stopgap, we need a better builtin solution to get the included libraries
libdirs = String["$(julia_usrdir)/lib"]
includedirs = String["$(julia_usrdir)/include"]

env = {"HOGWEED_LIBS" => "-L$(libdirs[1]) -L$(BinDeps.libdir(nettle)) -lhogweed -lgmp",
		"NETTLE_LIBS" => "-L$(libdirs[1]) -L$(BinDeps.libdir(nettle)) -lnettle -lgmp", "LIBS" => "-lgmp ","LD_LIBRARY_PATH"=>join([libdirs[1];BinDeps.libdir(nettle)],":")}

provides(BuildProcess,
	{
		Autotools(lib_dirs = libdirs, include_dirs = includedirs, env = env) => nettle,
		Autotools(libtarget = "lib/libgnutls.la", lib_dirs = libdirs, include_dirs = includedirs, env = env) => gnutls
	})

@BinDeps.install