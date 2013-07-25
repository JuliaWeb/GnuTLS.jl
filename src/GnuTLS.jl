module GnuTLS

using BinDeps
@BinDeps.load_dependencies [:gnutls]

import Base: isopen, write, read, readall, readavailable, close, show, nb_available

# GnuTLS initialization

function init() 
	ccall((:gnutls_global_set_mem_functions,gnutls),Void,
		(Ptr{Void},Ptr{Void},Ptr{Void},Ptr{Void},Ptr{Void}),
		  cglobal(:jl_gc_counted_malloc),   # Malloc
		  cglobal(:jl_gc_counted_malloc),   # Secure Malloc
		  C_NULL,							# is_secure (may be NULL)
          cglobal(:realloc),  				# Realloc
          cglobal(:jl_gc_counted_free))		# Free
	ccall((:gnutls_global_init,gnutls),Int32,())
end
deinit() = ccall((:gnutls_global_deinit,gnutls),Void,())

# GnuTLS Error handling

include("errormap.jl")

immutable GnuTLSException
	msg::ASCIIString
	code::Int32
end

GnuTLSException(code::Integer) = GnuTLSException("",code)

show(io::IO,err::GnuTLSException) = print(io,"GnuTLS Exception: ",err.msg,error_codes[err.code][1],"(",string(err.code),"): ",error_codes[err.code][2])

gnutls_error(msg::ASCIIString,err::Int32) = err != 0 ? throw(GnuTLSException(err)) : nothing
gnutls_error(err::Int32) = err != 0 ? throw(GnuTLSException(err)) : nothing

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
isopen(s::Session) = (isopen(s.read) || isopen(s.write)) && s.open

function close(s::Session) 
	if !isopen(s.read) 
		return 
	end
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

type CertificateStore
	handle::Ptr{Void}
	function CertificateStore() 
		x = Array(Ptr{Void},1)
		gnutls_error(ccall((:gnutls_certificate_allocate_credentials,gnutls),Int32,(Ptr{Ptr{Void}},),x))
		ret = new(x[1])
		finalizer(ret,free_certificate_store)
		ret
	end
end

free_certificate_store(x::CertificateStore) = ccall((:gnutls_certificate_free_credentials,gnutls),Void,(Ptr{Void},),x.handle)
function set_system_trust!(c::CertificateStore) 
	ret = ccall((:gnutls_certificate_set_x509_system_trust,gnutls),Int32,(Ptr{Void},),c.handle)
	if ret == -1250
		return false
	end
	gnutls_error(ret)
	true
end

function load_certificate(c::CertificateStore,certfile::String,keyfile::String,isPEM=false)
	gnutls_error(ccall((:gnutls_certificate_set_x509_key_file,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Ptr{Uint8},Int32),c.handle,certfile,keyfile,isPEM?1:0))
end

const system_certificate_store = CertificateStore()
const has_system_trust = set_system_trust!(system_certificate_store)

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
	read(io,pointer_to_array(ptr,int(n)))
	return signed(n)
end

function associate_stream{S<:IO,T<:IO}(s::Session, read::S, write::T=read)
	s.read = read
	s.write = write
	if write == read
		ccall((:gnutls_transport_set_ptr,gnutls),Void,(Ptr{Void},Any),s.handle,read)
	else 
		ccall((:gnutls_transport_set_ptr2,gnutls),Void,(Ptr{Void},Any,Any),s.handle,read,write)
	end
	ccall((:gnutls_transport_set_pull_timeout_function,gnutls),Void,(Ptr{Void},Ptr{Void}),s.handle,cfunction(poll_readable,Int32,(S,Uint32)))
	ccall((:gnutls_transport_set_pull_function,gnutls),Void,(Ptr{Void},Ptr{Void}),s.handle,cfunction(read_ptr,Cssize_t,(S,Ptr{Uint8},Csize_t)))
	ccall((:gnutls_transport_set_push_function,gnutls),Void,(Ptr{Void},Ptr{Void}),s.handle,cfunction(Base.write,Int64,(T,Ptr{Uint8},Csize_t)))
end

handshake!(s::Session) = (gnutls_error(ccall((:gnutls_handshake,gnutls),Int32,(Ptr{Void},),s.handle));s.open = true; nothing)
function set_priority_string!(s::Session,priority::ASCIIString="NORMAL") 
	x = Array(Ptr{Uint8},1)
	old_ptr = convert(Ptr{Uint8},priority)
	ret = ccall((:gnutls_priority_set_direct,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Ptr{Ptr{Uint8}}),s.handle,old_ptr,x)
	offset = x[1] - old_ptr	
	gnutls_error("At priority string offset $offset: ",ret)
end

const GNUTLS_CRD_CERTIFICATE = 1
const GNUTLS_CRD_ANON 		 = 2
const GNUTLS_CRD_SRP		 = 3
const GNUTLS_CRD_PSK 		 = 4
const GNUTLS_CRD_IA 		 = 5

set_credentials!(s::Session,c::CertificateStore) = gnutls_error(ccall((:gnutls_credentials_set,gnutls),Int32,(Ptr{Void},Int32,Ptr{Void}),s.handle,GNUTLS_CRD_CERTIFICATE,c.handle))

function write(io::Session, data::Ptr{Uint8}, size::Integer) 
	ret = ccall((:gnutls_record_send,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, data, size)
	if ret < 0
		gnutls_error(ret)
	end
	ret
end

function write(io::Session, data::Array{Uint8,1}) 
	ret = ccall((:gnutls_record_send,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, data, length(data))
	if ret < 0
		gnutls_error(ret)
	end
	ret
end

function read(io::Session, data::Array{Uint8,1})
	total = 0
	while total < length(data)
		ret = ccall((:gnutls_record_recv,gnutls), Int, (Ptr{Void},Ptr{Uint8},Csize_t), io.handle, data, length(data))
		if ret < 0
			gnutls_error(ret)
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

function readavailable(io::Session)
	buf = IOBuffer(Array(Uint8,0),true,true,true,true,typemax(Int))
	n = nb_available(io)
	if n == 0
		readtobuf(io,buf,1)
	end
	while (n = nb_available(io))>0
		if !readtobuf(io,buf,n)
			break
		end
	end
	readall(buf)
end

function write{T}(s::Session, a::Array{T})
    if isbits(T)
        write(s,reinterpret(Uint8,a))
    else
        invoke(write, (IO, Array), s, a)
    end
end

read(io::Session, ::Type{Uint8}) = (x=Array(Uint8,1);read(io,x);x[1])

export  handshake!, associate_stream, set_priority_string!, set_credentials!



export SHA1, MD5, RMD160, SHA256, SHA384, SHA512, SHA224, initHMAC, initHash, update, takeresult!, hash
abstract HashAlgorithm


immutable SHA1 <: HashAlgorithm; end
immutable MD5 <: HashAlgorithm; end
immutable RMD160 <: HashAlgorithm; end
immutable MD2 <: HashAlgorithm; end
immutable SHA256 <: HashAlgorithm; end
immutable SHA384 <: HashAlgorithm; end
immutable SHA512 <: HashAlgorithm; end
immutable SHA224 <: HashAlgorithm; end

# Output size of the algorithm in Bytes
output_size(::Type{SHA1}) 	= 20
output_size(::Type{MD5}) 	= 16
output_size(::Type{RMD160}) = 20
output_size(::Type{MD2}) 	= 16
output_size(::Type{SHA256}) = 32
output_size(::Type{SHA384}) = 48
output_size(::Type{SHA512}) = 64
output_size(::Type{SHA224}) = 28

# Gnutls algorithm id 
gnutls_id(::Type{SHA1})	 	= 3
gnutls_id(::Type{MD5}) 		= 2
gnutls_id(::Type{RMD160}) 	= 4
gnutls_id(::Type{MD2}) 		= 5
gnutls_id(::Type{SHA256}) 	= 6
gnutls_id(::Type{SHA384}) 	= 7
gnutls_id(::Type{SHA512}) 	= 8
gnutls_id(::Type{SHA224}) 	= 9


function deinit_state(state)
	if state.handle != C_NULL
		takeresult!(state)
	end
end

# HMAC
type HMACState{T<:HashAlgorithm}
	handle::Ptr{Void}
end

function initHMAC{T<:HashAlgorithm}(::Type{T},key)
	x = Array(Ptr{Void},1)
	gnutls_error(ccall((:gnutls_hmac_init,gnutls),Int32,(Ptr{Ptr{Void}},Int32,Ptr{Uint8},Csize_t),x,gnutls_id(T),key,sizeof(key)))
	ret = HMACState{T}(x[1])
	finalizer(ret,deinit_state)
	ret
end

function update{T}(state::HMACState{T},data) 
	state.handle == C_NULL && error("Cannot update an HMAC that was freed.")
	gnutls_error(ccall((:gnutls_hmac,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Csize_t),state.handle,data,sizeof(data)))
end

function takeresult!{T}(state::HMACState{T})
	ret = Array(Uint8,output_size(T)); 
	ccall((:gnutls_hmac_deinit,gnutls),Void,(Ptr{Void},Ptr{Uint8}),state.handle,ret)
	state.handle = C_NULL
	ret
end

# Hashing
type HashState{T<:HashAlgorithm}
	handle::Ptr{Void}
end

function initHash{T<:HashAlgorithm}(::Type{T})
	x = Array(Ptr{Void},1)
	gnutls_error(ccall((:gnutls_hash_init,gnutls),Int32,(Ptr{Ptr{Void}},Int32),x,gnutls_id(T)))
	ret = HashState{T}(x[1])
	finalizer(ret,deinit_state)
	ret
end

function update{T}(state::HashState{T},data)
	state.handle == C_NULL && error("Cannot update a Hash that was freed.")
	gnutls_error(ccall((:gnutls_hash,gnutls),Int32,(Ptr{Void},Ptr{Uint8},Csize_t),state.handle,data,sizeof(data)))
end

function takeresult!{T}(state::HashState{T})
	ret = Array(Uint8,output_size(T)); 
	ccall((:gnutls_hash_deinit,gnutls),Void,(Ptr{Void},Ptr{Uint8}),state.handle,ret)
	state.handle = C_NULL
	ret
end


hash{T<:HashAlgorithm}(::Type{T},data) = (ret = Array(Uint8,output_size(T)); 
	ccall((:gnutls_hash_fast,gnutls),Void,(Int32,Ptr{Uint8},Ptr{Uint8},Ptr{Uint8}),gnutls_id(T),data,sizeof(data),ret);ret)


end

GnuTLS.init()
