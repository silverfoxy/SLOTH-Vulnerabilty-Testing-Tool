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

if __name__=="__main__":
    if len(sys.argv)<=2:
        print "USAGE: <host> <port>"
        exit(1)
        
    target = (sys.argv[1],int(sys.argv[2]))
    
    # create tcp socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect(target)
    
    
    # create TLS1.2 Handhsake / Client Hello packet / TLS Extension for RSA-MD5 SignatureAndHashAlgorithm
    # select CipherSuites corresponding to TLS Extension
    p = TLSRecord(version='TLS_1_2') \
        /TLSHandshake() \
        /TLSClientHello(version='TLS_1_2', cipher_suites=0x0004, \
            extensions=TLSExtension(type='signature_algorithms') \
                        /TLSExtSignatureAndHashAlgorithm(algorithms=TLSSignatureHashAlgorithm(hash_algorithm='md5', signature_algorithm='rsa')))
    #p.show()

    SSL(str(p)).show()
    
    print "sending TLS payload"
    s.sendall(str(p))
    resp = s.recv(8*1024)
    print "received, %s"%repr(resp)
    SSL(resp).show()
    
    s.close()