package com.kobu.handshaker

import java.security.{MessageDigest, PublicKey}

import com.kobu.handshaker.MessageEncodeDecode._
import javax.crypto.Cipher
import scodec.bits.ByteVector

object ClientTestHelper {


  def getEncryptedData(pQInnerData: PQInnerData, pk: PublicKey) = {
    val encoded = pQInnerData.encode
    val digest = encoded.digest(MessageDigest.getInstance("SHA1"))
    val withoutPadding = digest ++ encoded
    val dataWithHash = withoutPadding ++ ByteVector.fill(255 - withoutPadding.size)(0)

    val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
    cipher.init(Cipher.ENCRYPT_MODE, pk)
    ByteVector(cipher.doFinal(dataWithHash.toArray))
  }
}
