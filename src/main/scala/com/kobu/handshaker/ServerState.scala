package com.kobu.handshaker

import java.security.{PrivateKey, PublicKey}

import scodec.bits.ByteVector

case class ServerState(privateKey: PrivateKey,
                       publicKey: PublicKey,
                       nonce: Option[ByteVector] = None,
                       severNonce: Option[ByteVector] = None,
                       newNonce: Option[ByteVector] = None,
                       pq: Option[ByteVector] = None,
                       p: Option[ByteVector] = None,
                       q: Option[ByteVector] = None)
