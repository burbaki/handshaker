package com.kobu.handshaker

import scodec.bits.ByteVector

sealed trait Message {

}


trait Request extends Message

trait Response extends Message

case class ReqPqBody(nonce: ByteVector) extends Request with EncodeDecodable

case class RespPqBody(nonce: ByteVector,
                      serverNonce: ByteVector,
                      pq: Pq,
                      fingerprints: Vector[ByteVector]
                     ) extends Response with EncodeDecodable

case class ReqDHParamsBody(nonce: ByteVector,
                           serverNonce: ByteVector,
                           p: ByteVector,
                           q: ByteVector,
                           fingerprint: ByteVector,
                           encryptedData: ByteVector) extends Request with EncodeDecodable

case class Pq(size: Byte, bytes: ByteVector, totalSize: Byte = 12) {
  val paddingBytes: Int = totalSize - size - 1
  val resultingByteVector: ByteVector = ByteVector(size) ++ bytes ++ ByteVector.fill(paddingBytes)(0)
}

case class PQInnerData(pq: Pq,
                       p: ByteVector,
                       q: ByteVector,
                       nonce: ByteVector,
                       serverNonce: ByteVector,
                       newNonce: ByteVector) extends EncodeDecodable

case class PqHeader(authKeyId: ByteVector,
                    messageId: ByteVector,
                    messageBodyLength: Int) extends EncodeDecodable

object Pq {
  def fromByteVector(allBytes: ByteVector) = {
    val size = allBytes.slice(0, 1).toByte(false)
    val bytes = allBytes.slice(1, size + 1)
    val totalSize = allBytes.size.toByte
    Pq(size, bytes, totalSize)
  }
}
