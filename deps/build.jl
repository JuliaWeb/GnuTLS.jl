using BinDeps

@BinDeps.setup

nettle = library_dependency("nettle", aliases = ["libnettle"], runtime = false)
gnutls = library_dependency("gnutls", aliases = ["libgnutls.so.28","libgnutls","libgnutls28", "libgnutls-28"], depends = [nettle], validate = function(p,h)
	if !haskey(ENV,"GNUTLS_VERSION")
		return true
	end
	ccall(dlsym(h,:gnutls_check_version),Ptr{Uint8},(Ptr{Uint8},),ENV["GNUTLS_VERSION"]) != C_NULL
end)

provides(Sources,{
	URI("http://www.lysator.liu.se/~nisse/archive/nettle-2.7.tar.gz") => nettle,
	URI("ftp://ftp.gnutls.org/gcrypt/gnutls/v3.2/gnutls-3.2.14.tar.xz") => gnutls})

#provides(Binaries,URI("ftp://ftp.gnutls.org/gcrypt/gnutls/w32/gnutls-3.2.1-w32.zip"),gnutls,os = :Windows)

@windows_only begin
    using WinRPM
    provides(WinRPM.RPM,"nettle",nettle,os = :Windows)
    provides(WinRPM.RPM,"gnutls",gnutls,os = :Windows)
end

if haskey(ENV,"GNUTLS_VERSION")
	requested_version = convert(VersionNumber,ENV["GNUTLS_VERSION"])
	pkgmanager_validate	= (p,dep)->available_version(p) >= requested_version
else
	pkgmanager_validate = true
end

@osx_only begin
	if Pkg.installed("Homebrew") === nothing
		error("Homebrew package not installed, please run Pkg.add(\"Homebrew\")")
	end
	using Homebrew
	provides( Homebrew.HB, "gnutls", gnutls, os = :Darwin )
end

provides(AptGet,["libgnutls28", "libgnutls-deb0-28"],gnutls,validate = pkgmanager_validate) # Yes, this is the most current version, I guess they broke binary compatibility in v2.8?
provides(Yum,["gnutls", "libgnutls"],gnutls,validate = pkgmanager_validate)

julia_usrdir = normpath(JULIA_HOME*"/../") # This is a stopgap, we need a better builtin solution to get the included libraries
libdirs = String["$(julia_usrdir)/lib"]
includedirs = String["$(julia_usrdir)/include"]

env = {"HOGWEED_LIBS" => "-L$(libdirs[1]) -L$(BinDeps.libdir(nettle)) -lhogweed -lgmp",
		"NETTLE_LIBS" => "-L$(libdirs[1]) -L$(BinDeps.libdir(nettle)) -lnettle -lgmp", "LIBS" => "-lgmp ","LD_LIBRARY_PATH"=>join([libdirs[1];BinDeps.libdir(nettle)],":")}

provides(BuildProcess,Autotools(lib_dirs = libdirs, include_dirs = includedirs, env = env),nettle)

# If we're installing gnutls from source we better also installl nettle from source, otherwise we end up with a giant mess.
provides(BuildProcess,Autotools(libtarget = "lib/libgnutls.la", lib_dirs = libdirs, include_dirs = includedirs, env = env),gnutls,force_depends = {BuildProcess => nettle})

@BinDeps.install [:gnutls => :gnutls]
