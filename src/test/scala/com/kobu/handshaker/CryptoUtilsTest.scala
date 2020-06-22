package com.kobu.handshaker

import java.security._

import com.kobu.handshaker.MessageEncodeDecode._
import javax.crypto.Cipher
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import scodec.bits.ByteVector

import scala.util.Random

class CryptoUtilsTest extends AnyFunSuite with Matchers {


  ignore(" 2 prime product should decomposing to the same primes ") {
    val primes = CryptoUtils.generatePrimeProduct
    val product = primes._1 * primes._2
    val primesDecomposition = CryptoUtils.FermatFactor(product)

    primesDecomposition shouldEqual primes
  }

  ignore(" 2 prime product should decomposing to the same primes in ByteVector") {
    val primes = CryptoUtils.generatePrimeProduct
    val product = ByteVector.fromLong((primes._1 * primes._2).toLong)
    val primesDecomposition = CryptoUtils.FermatFactor(BigInt(product.toArray))

    primesDecomposition shouldEqual primes
  }

  test("simple test") {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(2048)

    val pair: KeyPair = keyGen.generateKeyPair
    val privateKey: PrivateKey = pair.getPrivate
    val publicKey: PublicKey = pair.getPublic

    val primes = CryptoUtils.generatePrimeProduct
    val pq = ByteVector.fromLong((primes._1 * primes._2).toLong)
    val nonce = ByteVector(Random.nextBytes(16))
    val serverNonce = ByteVector(Random.nextBytes(16))
    val newNonce = ByteVector(Random.nextBytes(32))

    val innerData = PQInnerData(TcpString(8, pq), TcpString(4, ByteVector.fromInt((primes._1).toInt), 8),
      TcpString(4, ByteVector.fromInt((primes._2).toInt), 8), nonce, serverNonce, newNonce)
    val encrypted = ClientTestHelper.getEncryptedData(innerData, publicKey)
    encrypted.size shouldEqual 256

    val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    val decrypted = ByteVector(cipher.doFinal(encrypted.toArray)).drop(1)

    val encoded = innerData.encode
    val digest = encoded.digest(MessageDigest.getInstance("SHA1"))
    val withoutPadding = digest ++ encoded
    val dataWithHash = withoutPadding ++ ByteVector.fill(255 - withoutPadding.size)(0)

    dataWithHash shouldEqual decrypted
    encoded shouldEqual decrypted.slice(20, 96 + 20)
    digest shouldEqual decrypted.slice(0, 20)
  }

}
