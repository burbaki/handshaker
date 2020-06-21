package com.kobu.handshaker

import scodec.bits.ByteVector

trait Encodable

trait Decodable

trait EncodeDecodable extends Encodable with Decodable

trait MessageDecoder[T <: Decodable] {
  def decode(bytes: ByteVector): T
}

trait MessageEncoder[T <: Encodable] {
  def encode(message: T): ByteVector
}


object MessageEncodeDecode {

  implicit class ByteVectorOps(bytes: ByteVector) {
    def decode[T <: Decodable : MessageDecoder]: T = {
      implicitly[MessageDecoder[T]].decode(bytes)
    }
  }

  implicit class MessageOps[T <: Encodable](message: T) {
    def encode(implicit encoder: MessageEncoder[T]): ByteVector = {
      val x: MessageEncoder[T] = implicitly[MessageEncoder[T]]
      x.encode(message)
    }
  }

}

