#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

import sys, os

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    basedir = os.path.abspath(os.path.join(os.path.dirname(__file__),"../"))
    sys.path.append(basedir)
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *
    
import socket

tls_version = TLSVersion.TLS_1_2

def tls_hello(sock) :
    # create TLS1.2 Handhsake / Client Hello packet / TLS Extension for RSA-MD5 SignatureAndHashAlgorithm
    # select CipherSuites corresponding to TLS Extension
    RSA_MD5_CipherSuites = [ TLSCipherSuite.RSA_WITH_NULL_MD5, TLSCipherSuite.RSA_EXPORT_WITH_RC4_40_MD5, TLSCipherSuite.RSA_WITH_RC4_128_MD5, \
        TLSCipherSuite.RSA_EXPORT_WITH_RC2_CBC_40_MD5 ]
    RSA_SHA1_CipherSuites = [ TLSCipherSuite.RSA_WITH_NULL_SHA, TLSCipherSuite.RSA_WITH_RC4_128_SHA, TLSCipherSuite.RSA_WITH_IDEA_CBC_SHA, \
        TLSCipherSuite.RSA_EXPORT_WITH_DES40_CBC_SHA, TLSCipherSuite.RSA_WITH_DES_CBC_SHA, TLSCipherSuite.RSA_WITH_3DES_EDE_CBC_SHA, \
        TLSCipherSuite.RSA_PSK_WITH_NULL_SHA, TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA, TLSCipherSuite.RSA_WITH_CAMELLIA_128_CBC_SHA, \
        TLSCipherSuite.RSA_WITH_CAMELLIA_256_CBC_SHA, TLSCipherSuite.RSA_PSK_WITH_RC4_128_SHA, TLSCipherSuite.RSA_PSK_WITH_3DES_EDE_CBC_SHA, \
        TLSCipherSuite.RSA_PSK_WITH_AES_128_CBC_SHA, TLSCipherSuite.RSA_PSK_WITH_AES_256_CBC_SHA, TLSCipherSuite.RSA_WITH_SEED_CBC_SHA ]

    client_hello = TLSRecord(version=tls_version) \
        /TLSHandshake() \
        /TLSClientHello(version=tls_version, cipher_suites=RSA_MD5_CipherSuites, \
            extensions=TLSExtension(type='signature_algorithms') \
                        /TLSExtSignatureAndHashAlgorithm(algorithms=TLSSignatureHashAlgorithm(hash_algorithm='md5', signature_algorithm='rsa')))
    sock.sendall(client_hello)
    server_hello = sock.recvall()
    client_hello.show()
    server_hello.show()

if __name__=="__main__":
    if len(sys.argv)<=2:
        print "USAGE: <host> <port>"
        exit(1)
        
    target = (sys.argv[1],int(sys.argv[2]))
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    try:
        sock.connect(target)
        sock = TLSSocket(sock, client=True)
        print "Connected to server: %s:%i" % target
    except socket.timeout as te:
        print "Failed to open connection to server: %s:%i" % target
    else:
        tls_hello(sock)
        '''tls_client_key_exchange(sock)
        print("Finished handshake. Sending application data (GET request)")
        sock.sendall(to_raw(TLSPlaintext(data="GET / HTTP/1.1\r\nHOST: localhost\r\n\r\n"), sock.tls_ctx))
        resp = sock.recvall()
        print("Got response from server")
        resp.show()
        print(sock.tls_ctx)'''
    finally:
        sock.close()
