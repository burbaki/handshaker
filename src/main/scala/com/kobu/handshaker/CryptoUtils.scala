package com.kobu.handshaker

import scala.math.BigInt
import scala.util.Random

object CryptoUtils {

  def FermatFactor(N: BigInt): (BigInt, BigInt) = {
    var a = BigInt(N.bigInteger.sqrt()) + 1
    println(s"a:  $a")
    var b2 = (a * a) - N
    println(s"a2:  ${a * a}")
    println(s"b2:  $b2")
    while (!isSquare(b2)) {
      a = a + 1
      b2 = a * a - N
    }
    val r1 = a - b2.bigInteger.sqrt()
    println(r1)
    val r2 = N / r1
    println(r2)
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
}