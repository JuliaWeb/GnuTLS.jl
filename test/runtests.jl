using GnuTLS

println("Connecting...")
sock = Base.connect("github.com", 443)
@show sock
sess = GnuTLS.Session()
set_priority_string!(sess)
set_credentials!(sess, GnuTLS.CertificateStore())
associate_stream(sess, sock)
handshake!(sess)
println("Completed handshake, sending request")
@show sock
write(sess,"GET / HTTP/1.1\r\n\r\n")
println("Response...")
print(readall(sess))
@show sock