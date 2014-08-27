using GnuTLS

sess = GnuTLS.Session()
set_priority_string!(sess)
set_credentials!(sess,GnuTLS.CertificateStore())
associate_stream(sess,connect("github.com",443))
handshake!(sess)
write(sess,"GET / HTTP/1.1\r\n\r\n")
print(readall(sess))