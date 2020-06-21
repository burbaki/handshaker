package com.kobu.handshaker.handlers

import java.nio.channels.AsynchronousSocketChannel
import java.security._
import java.time.Instant

import com.kobu.handshaker.MessageEncodeDecode._
import com.kobu.handshaker.{CryptoUtils, Pq, PqHeader, ReqPqBody, RespPqBody, Server, messagePqHeaderLength}
import scodec.bits.{ByteOrdering, ByteVector}
import zio.ZIO
import zio.blocking.Blocking

import scala.util.Random

class TmHandlerPq extends TcpHandler {
  val keyGen = KeyPairGenerator.getInstance("RSA")
  keyGen.initialize(1024)

  val pair: KeyPair = keyGen.generateKeyPair
  val privateKey: PrivateKey = pair.getPrivate
  val publicKey: PublicKey = pair.getPublic

  override val nextTcpHandler: Option[TcpHandler] = None

  override def handleInternal(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel] = {
    Server.read(channel, messagePqHeaderLength).flatMap {
      header => {
        val pqHeader = header.decode[PqHeader]
        val sizeBody = pqHeader.messageBodyLength
        Server.read(channel, sizeBody).flatMap {
          body => {
            val reqBody = body.decode[ReqPqBody]
            //Some actions
            println(s"got request: $reqBody")
            val primes = CryptoUtils.generatePrimeProduct
            val pp = (primes._1 * primes._2).toLong
            val pq = ByteVector.fromLong(pp)
            val response: RespPqBody = RespPqBody(
              reqBody.nonce,
              ByteVector(Random.nextBytes(16)),
              Pq(8, pq),
              fingerprints = Vector(ByteVector(publicKey.getEncoded)
                .digest(MessageDigest.getInstance("SHA1")).take(8)))
            val responseEncoded = response.encode
            val respHeader = PqHeader(
              ByteVector.fill(8)(0),
              ByteVector.fromLong(Instant.now.getEpochSecond, ordering = ByteOrdering.LittleEndian),
              responseEncoded.size.toInt)
            Server.write(channel, respHeader.encode ++ responseEncoded).map(_ => channel)
          }
        }
      }
    }
  }


  //    read(channel).flatMap(res => {
  //      ascii32.decodeValue(res).toOption.foreach(dr => println(s"${Thread.currentThread().getId} ${dr}"))
  //      write(channel, res).map(_ => channel)
  //    })
}
