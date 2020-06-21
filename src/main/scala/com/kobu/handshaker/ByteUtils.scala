package com.kobu.handshaker

import scodec.bits.ByteVector

object ByteUtils {

  def groupBytesBy(bytes: ByteVector, groupSize: Long): Vector[ByteVector] = {
    bytes match {
      case b: ByteVector if b.size >= groupSize =>
        b.take(groupSize) +: groupBytesBy(bytes.drop(groupSize), groupSize)
      case ByteVector() => Vector.empty[ByteVector]
      case b: ByteVector => Vector(b ++ (ByteVector.fill(groupSize - b.size)(0)))
    }
  }


}
