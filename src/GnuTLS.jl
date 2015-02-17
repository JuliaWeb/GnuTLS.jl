module GnuTLS

using Base.Meta
using BinDeps

include("../deps/deps.jl")

import Base: isopen, write, read, readall, readavailable, close, show, nb_available, eof


const gnutls_version = convert(VersionNumber,bytestring(ccall((:gnutls_check_version,gnutls),Ptr{Uint8},(Ptr{Uint8},),C_NULL)))

macro gnutls_since(v,f)
	if isexpr(v,:macrocall) && v.args[1] == symbol("@v_str")
		v = convert(VersionNumber,v.args[2])
	end
	if gnutls_version < v
		msg = """This function is only supported in GnuTLS versions > $v. 
				 To force GnuTLS.jl to build a more recent version, you may set 
				 ENV[\"GNUTLS_VERSION\"] and run Pkg.fixup()"""
		body = quote
			error($msg)
		end
		if isexpr(f,:function) || isexpr(f,:(=))
			@assert isexpr(f.args[1],:call)
			return esc(Expr(f.head,f.args[1],body))
		else
			return nothing
		end
	end
	esc(f)
end

# GnuTLS Error handling

include("errormap.jl")

immutable GnuTLSException
	msg::ASCIIString
	code::Int32
end

GnuTLSException(code::Integer) = GnuTLSException("",code)

show(io::IO,err::GnuTLSException) = print(io,"GnuTLS Exception: ",err.msg,error_codes[int(err.code)][1],"(",string(err.code),"): ",error_codes[int(err.code)][2])

gnutls_error(msg::ASCIIString,err::Int32) = err < 0 ? throw(GnuTLSException(err)) : nothing
gnutls_error(err::Int32) = err < 0 ? throw(GnuTLSException(err)) : nothing

# Chrome does not Handle EOF properly, but instead just shuts down the transport. This function
# is a heuristic to determine whether that's what we're dealing with. Using this functions
# to ignore errors in HTTPS is allowed by RFC2818.
function is_premature_eof(err::GnuTLSException)
	if gnutls_version < v"3.0"
		# GNUTLS_E_UNEXPECTED_PACKAGE_LENGTH
		return err.code == -9
	else
		# GNUTLS_E_PREMATURE_TERMINATION
		return err.code == -110
	end
end

# GnuTLS Session support

const GNUTLS_SERVER = 1
const GNUTLS_CLIENT = 1<<1
const GNUTLS_DATAGRAM = 1<<2
const GNUTLS_NONBLOCK = 1<<3
const GNUTLS_NO_EXTENSIONS = 1<<4

type Session <: IO
	handle::Ptr{Void}
	open::Bool 
	# For rooting purposes
	read::IO
	write::IO
	function Session(isserver::Bool = false)
		x = Array(Ptr{Void},1)
		gnutls_error(ccall((:gnutls_init,gnutls),Int32,(Ptr{Ptr{Void}},Uint32),x,isserver?GNUTLS_SERVER:GNUTLS_CLIENT))
		ret = new(x[1],false)
		finalizer(ret,free_session)
		ret
	end
end

const GNUTLS_SHUT_RDWR = 0
const GNUTLS_SHUT_WR = 1


free_session(s::Session) = ccall((:gnutls_deinit,gnutls),Void,(Ptr{Void},),s.handle)
isopen(s::Session) = (isopen(s.read) || isopen(s.write))

function close(s::Session)
	ret::Int32 = 0
	try # The remote might very well simply shut the stream rather than acknowledge the closure
		ret = ccall((:gnutls_bye,gnutls), Int32, (Ptr{Void},Int32), s.handle, GNUTLS_SHUT_RDWR)
	catch e
		if !isa(e,EOFError)
			rethrow()
		end
	end
	gnutls_error(ret)
	s.open=false
	nothing
end

const GNUTLS_PK_UNKNOWN = 0
const GNUTLS_PK_RSA = 1
const GNUTLS_PK_DSA = 2
const GNUTLS_PK_DH = 3
const GNUTLS_PK_EC = 4

const GNUTLS_SEC_PARAM_INSECURE = -20
const GNUTLS_SEC_PARAM_EXPORT = -15
const GNUTLS_SEC_PARAM_VERY_WEAK = -12
const GNUTLS_SEC_PARAM_WEAK = -10
const GNUTLS_SEC_PARAM_UNKNOWN = 0
const GNUTLS_SEC_PARAM_LOW = 1
const GNUTLS_SEC_PARAM_LEGACY = 2
const GNUTLS_SEC_PARAM_NORMAL = 3
const GNUTLS_SEC_PARAM_HIGH = 4
const GNUTLS_SEC_PARAM_ULTRA = 5

type DHParameters
	handle::Ptr{Void}
	function DHParameters(handle)
		ret = new(handle)
		finalizer(ret,free_dh_parameters)
		ret
	end
end

free_dh_parameters(dh::DHParameters) = ccall((:gnutls_dh_params_deinit,gnutls),Void,(Ptr{Void},),dh.handle)

function generate_dh_parameters(;sec_level=GNUTLS_SEC_PARAM_NORMAL)
	x = Array(Ptr{Void},1)
	ccall((:gnutls_dh_params_generate2,gnutls),Int32,(Ptr{Void},Uint32),x,
		ccall((:gnutls_sec_param_to_pk_bits,gnutls),Uint32,(Int32,Uint32),GNUTLS_PK_DH,GNUTLS_SEC_PARAM_NORMAL))
	DHParameters(x[1])
end

type CertificateStore
	handle::Ptr{Void}
	# for rooting purposes
	dh_parameters::DHParameters
	function CertificateStore() 
		x = Array(Ptr{Void},1)
		gnutls_error(ccall((:gnutls_certificate_allocate_credentials,gnutls),Int32,(Ptr{Ptr{Void}},),x))
		ret = new(x[1])
		finalizer(ret,free_certificate_store)
		ret
	end
end

function set_dh_parameters(c::CertificateStore,dh::DHParameters)
	c.dh_parameters = dh
	ccall((:gnutls_certificate_set_dh_params,gnutls),Void,(Ptr{Void},Ptr{Void}),c.handle,dh.handle)
end

free_certificate_store(x::CertificateStore) = ccall((:gnutls_certificate_free_credentials,gnutls),Void,(Ptr{Void},),x.handle)
@gnutls_since v"3.0" function set_system_trust!(c::CertificateStore) 
	ret = ccall((:gnutls_certificate_set_x509_system_trust,gnutls),Int32,(Ptr{Void},),c.handle)
	if ret == -1250
		return false
	end
	gnutls_error(ret)
	true
end

function add_trusted_ca(c::CertificateStore,file,isPEM=false)
	gnutls_error(ccall((:gnutls_certificate_set_x509_trust_file,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Int32),c.handle,file,isPEM?1:0))
end

function load_certificate(c::CertificateStore,certfile::String,keyfile::String,isPEM=false)
	gnutls_error(ccall((:gnutls_certificate_set_x509_key_file,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Ptr{Uint8},Int32),c.handle,certfile,keyfile,isPEM?1:0))
end

@gnutls_since v"3.0" begin
	const system_certificate_store = CertificateStore()
end

@gnutls_since v"3.0" system_trust() = system_certificate_store()

type Certificate
	handle::Ptr{Void}
	function Certificate()
		x = Array(Ptr{Void},1)
		gnutls_error(ccall((:gnutls_x509_crt_init,gnutls),Int32,(Ptr{Void},),x))
		ret = new(x[1])
		finalizer(ret,free_certificate)
		ret
	end
end
free_certificate(x::Certificate) = ccall((:gnutls_x509_crt_deinit,gnutls),Void,(Ptr{Void},),x.handle)

function import_certificate(p)
	c = Certificate()
	gnutls_error(ccall((:gnutls_x509_crt_import,gnutls),Int32,(Ptr{Void},Ptr{Void},Int32),c.handle,p,0))
	c
end

immutable DistinguishedName
	handle::Ptr{Void}
	cert::Certificate
end

immutable Datum
	data::Ptr{Uint8}
	size::Uint32
end

immutable AvaSt
	oid::Datum
	value::Datum
	value_tag::Culong
end

immutable Ava
	ava::AvaSt
	dn::DistinguishedName
end

function subject(c::Certificate)
	x = Array(Ptr{Void},1)
	gnutls_error(ccall((:gnutls_x509_crt_get_subject,gnutls),Int32,(Ptr{Void},Ptr{Ptr{Void}}),c.handle,x))
	DistinguishedName(x[1],c)
end

import Base: getindex

#(gnutls_x509_dn_t dn, int irdn, int iava, gnutls_x509_ava_st * ava)
function getindex(dn::DistinguishedName,irdn::Integer,iava::Integer)
	x = Array(AvaSt,1)
	gnutls_error(ccall((:gnutls_x509_dn_get_rdn_ava,gnutls),Int32,(Ptr{Void},Int32,Int32,Ptr{AvaSt}),dn.handle,irdn,iava,x))
	Ava(x[1],dn)
end


function subject_alt_name(c::Certificate,seq = 0)
	s = Array(Csize_t,1)
	err = ccall((:gnutls_x509_crt_get_subject_alt_name,gnutls),Int32,(Ptr{Void},Cuint,Ptr{Uint8},Ptr{Csize_t},Ptr{Cuint}),c.handle,seq,C_NULL,s,C_NULL)
	@assert error_codes[int(err)][1] == "GNUTLS_E_SHORT_MEMORY_BUFFER"
	a = Array(Uint8,s[1])
	gnutls_error(ccall((:gnutls_x509_crt_get_subject_alt_name,gnutls),Int32,(Ptr{Void},Cuint,Ptr{Uint8},Ptr{Csize_t},Ptr{Cuint}),c.handle,seq,a,s,C_NULL))
	bytestring(a[1:(end-1)])
end

gnutls_free(d::Datum) = ccall(:jl_gc_counted_free,Void,(Ptr{Uint8},),d.data)

const GNUTLS_CRT_PRINT_FULL 			= 0
const GNUTLS_CRT_PRINT_ONELINE 			= 1
const GNUTLS_CRT_PRINT_UNSIGNED_FULL	= 2
const GNUTLS_CRT_PRINT_COMPACT 			= 3
const GNUTLS_CRT_PRINT_FULL_NUMBERS 	= 4

function show(io::IO,c::Certificate)
	a = Array(Datum,1)
	gnutls_error(ccall((:gnutls_x509_crt_print,gnutls),Int32,(Ptr{Void},Int32,Ptr{Datum}),c.handle,GNUTLS_CRT_PRINT_FULL,a))
	print(io,bytestring(a[1].data,a[1].size))
	gnutls_free(a[1])
end

import Base: bytestring

function bytestring(d::Datum)
	bytestring(d.data,d.size)
end

function poll_readable{S<:IO}(io::S,ms::Uint32)
	c = Condition()
	@async begin
		sleep(ms/1000)
		notify(c,int32(0))
	end
	@async begin
		err = wait(readnotify(io))
		notify(c,err.code == 0 ? 1 : 0)
	end
	wait(c)::Int32
end

function read_ptr{S<:IO}(io::S,ptr::Ptr{Uint8},size::Csize_t) 
	Base.wait_readnb(io,1)
	n = min(nb_available(io.buffer),size)
	read!(io,pointer_to_array(ptr,int(n)))
	return signed(n)
end

# Store Base.write() return type here, so we work on Julia v0.4+ as well as older
const write_return_type = VERSION >= v"0.4-" ? typeof(uint64(1)) : typeof(int64(1))

function associate_stream{S<:IO,T<:IO}(s::Session, read::S, write::T=read)
	s.read = read
	s.write = write
	if write == read
		ccall((:gnutls_transport_set_ptr,gnutls),Void,(Ptr{Void},Any),s.handle,read)
	else 
		ccall((:gnutls_transport_set_ptr2,gnutls),Void,(Ptr{Void},Any,Any),s.handle,read,write)
	end
	@gnutls_since v"3.0" ccall((:gnutls_transport_set_pull_timeout_function,gnutls),Void,(Ptr{Void},Ptr{Void}),s.handle,cfunction(poll_readable,Int32,(S,Uint32)))
	ccall((:gnutls_transport_set_pull_function,gnutls),Void,(Ptr{Void},Ptr{Void}),s.handle,cfunction(read_ptr,Cssize_t,(S,Ptr{Uint8},Csize_t)))
	ccall((:gnutls_transport_set_push_function,gnutls),Void,(Ptr{Void},Ptr{Void}),s.handle,cfunction(Base.write,write_return_type,(T,Ptr{Uint8},Csize_t)))
end

handshake!(s::Session) = (gnutls_error(ccall((:gnutls_handshake,gnutls),Int32,(Ptr{Void},),s.handle));s.open = true; nothing)
function set_priority_string!(s::Session,priority::ASCIIString="NORMAL") 
	x = Array(Ptr{Uint8},1)
	old_ptr = convert(Ptr{Uint8},priority)
	ret = ccall((:gnutls_priority_set_direct,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Ptr{Ptr{Uint8}}),s.handle,old_ptr,x)
	offset = x[1] - old_ptr	
	gnutls_error("At priority string offset $offset: ",ret)
end

function get_peer_certificate(s::Session)
	a = Array(Uint32,1)
	p = ccall((:gnutls_certificate_get_peers,gnutls),Ptr{Void},(Ptr{Void},Ptr{Uint32}),s.handle,a)
	p != C_NULL ? import_certificate(p) : nothing
end

const GNUTLS_CRD_CERTIFICATE = 1
const GNUTLS_CRD_ANON 		 = 2
const GNUTLS_CRD_SRP		 = 3
const GNUTLS_CRD_PSK 		 = 4
const GNUTLS_CRD_IA 		 = 5

set_credentials!(s::Session,c::CertificateStore) = gnutls_error(ccall((:gnutls_credentials_set,gnutls),Int32,(Ptr{Void},Int32,Ptr{Void}),s.handle,GNUTLS_CRD_CERTIFICATE,c.handle))


const GNUTLS_CERT_IGNORE = 0
const GNUTLS_CERT_REQUEST = 1
const GNUTLS_CERT_REQUIRE = 2

function set_prompt_client_certificate!(s::Session,required::Bool = true)
	ccall((:gnutls_certificate_server_set_request,gnutls),Void,(Ptr{Void},Int32),s.handle,required?GNUTLS_CERT_REQUIRE:GNUTLS_CERT_REQUEST)
end

function write(io::Session, data::Ptr{Uint8}, size::Integer) 
	total = 0
	while total < length(data)
		ret = ccall((:gnutls_record_send,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, data+total, size-total)
		if ret < 0
			gnutls_error(int32(ret))
		end
		total += ret
	end
	total
end

function write(io::Session, data::Array{Uint8,1})  
	total = 0
	while total < length(data)
		ret = ccall((:gnutls_record_send,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, pointer(data,total+1), length(data)-total)
		if ret < 0
			gnutls_error(int32(ret))
		end
		total += ret
	end
	total
end

function read(io::Session, data::Array{Uint8,1})
	total = 0
	while total < length(data)
		ret = ccall((:gnutls_record_recv,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, data, length(data))
		if ret < 0
			gnutls_error(int32(ret))
		elseif ret == 0
			throw(EOFError())
		end
		total += ret
	end
	data
end

function readtobuf(io::Session,buf::IOBuffer,nb)
	Base.ensureroom(buf,int(nb))
	ret = ccall((:gnutls_record_recv,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, pointer(buf.data,buf.size+1), nb)
	if ret < 0
		gnutls_error(int32(ret))
	elseif ret == 0
		close(io)
		return false
	end
	buf.size += ret
	return true
end

const TLS_CHUNK_SIZE = 4096
function readall(io::Session)
	buf = IOBuffer(Array(Uint8,TLS_CHUNK_SIZE),true,true,true,true,typemax(Int))
	buf.size = 0
	while readtobuf(io,buf,TLS_CHUNK_SIZE); end
	readall(buf)
end


nb_available(s::Session) = ccall((:gnutls_record_check_pending,gnutls), Csize_t, (Ptr{Void},), s.handle)
eof(s::Session) = (nb_available(s) == 0 && eof(s.read))

function readavailable(io::Session)
	buf = IOBuffer(Array(Uint8,0),true,true,true,true,typemax(Int))
	n = nb_available(io)
	if n == 0
		readtobuf(io,buf,1)
		n = nb_available(io)
	end
	while n>0
		if !readtobuf(io,buf,n)
			break
		end
		n = nb_available(io)
	end
	takebuf_array(buf)
end

function write{T}(s::Session, a::Array{T})
    if isbits(T)
        write(s,reinterpret(Uint8,a))
    else
        invoke(write, (IO, Array), s, a)
    end
end

# GnuTLS initialization

function logging_func(level::Int32,msg::Ptr{Uint8})
	println(bytestring(msg))
	nothing
end

function init()
	ccall((:gnutls_global_set_mem_functions,gnutls),Void,
		(Ptr{Void},Ptr{Void},Ptr{Void},Ptr{Void},Ptr{Void}),
		  cglobal(:jl_gc_counted_malloc),   # Malloc
		  cglobal(:jl_gc_counted_malloc),   # Secure Malloc
		  C_NULL,							# is_secure (may be NULL)
          cglobal(:realloc),  				# Realloc
          cglobal(:jl_gc_counted_free))		# Free
	ccall((:gnutls_global_set_log_function,gnutls),Void,
		(Ptr{Void},),cfunction(logging_func,Void,(Int32,Ptr{Uint8})))
	ccall((:gnutls_global_init,gnutls),Int32,())
    @gnutls_since v"3.0" begin
        global const has_system_trust = set_system_trust!(system_certificate_store)
    end
end
deinit() = ccall((:gnutls_global_deinit,gnutls),Void,())

read(io::Session, ::Type{Uint8}) = (x=Array(Uint8,1);read(io,x);x[1])

export  handshake!, associate_stream, set_priority_string!, set_credentials!, CertificateStore, Certificate

end

GnuTLS.init()
