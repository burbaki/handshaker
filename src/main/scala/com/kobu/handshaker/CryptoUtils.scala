package com.kobu.handshaker

import java.security.MessageDigest

import com.kobu.handshaker.MessageEncodeDecode._
import scodec.bits.ByteVector

import scala.math.BigInt
import scala.util.Random

object CryptoUtils {

  def FermatFactor(N: BigInt): (BigInt, BigInt) = {
    var a = BigInt(N.bigInteger.sqrt()) + 1
    var b2 = (a * a) - N
    while (!isSquare(b2)) {
      a = a + 1
      b2 = a * a - N
    }
    val r1 = a - b2.bigInteger.sqrt()
    val r2 = N / r1
    (r1, r2)
  }

  /** function to check if N is a perfect square or not **/
  def isSquare(N: BigInt): Boolean = {
    val sqr = BigInt(N.bigInteger.sqrt)
    sqr * sqr == N || (sqr + 1) * (sqr + 1) == N

  }

  def generatePrimeProduct: (BigInt, BigInt) = {
    val first = BigInt.probablePrime(32, Random)
    val second = BigInt.probablePrime(32, Random)
    if (first < second)
      first -> second
    else
      second -> first
  }

  def getEncryptedData(dHInnerData: DHInnerData) = {
    val encoded = dHInnerData.encode
    val digest = encoded.digest(MessageDigest.getInstance("SHA1"))
    val withoutPadding = digest ++ encoded
    val padding = 16 - ((withoutPadding.size) % 16)
    withoutPadding ++ ByteVector.fill(padding)(0)
  }
}