package com.kobu.handshaker.handlers

import java.nio.channels.AsynchronousSocketChannel
import java.security._
import java.time.Instant

import com.kobu.handshaker.MessageEncodeDecode._
import com.kobu.handshaker.{CryptoUtils, PqHeader, ReqPqBody, RespPqBody, Server, ServerState, TcpString}
import scodec.bits.{ByteOrdering, ByteVector}
import zio.blocking.Blocking
import zio.{Ref, ZIO}

import scala.util.Random

class TmHandlerPq(override val internalStateR: Ref[ServerState]) extends TcpHandler {

  override val nextTcpHandler: Option[TcpHandler] = Some(new TmHandlerDHParams(internalStateR))

  override def handleInternal(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel] = {
    for {
      (rawReqHeader, rawReqBody) <- readHeaderAndBody(channel)
      intrState <- internalStateR.get
      (respHeader, respBody, newState) <- {
        val reqBody = rawReqBody.decode[ReqPqBody]
        println(s"got request: $reqBody")

        val primes = CryptoUtils.generatePrimeProduct
        val pp = (primes._1 * primes._2).toLong
        val pq = ByteVector.fromLong(pp)
        val fingerprints = Vector(ByteVector(intrState.publicKey.getEncoded)
          .digest(MessageDigest.getInstance("SHA1")).take(8))

        val respBody: RespPqBody = RespPqBody(
          reqBody.nonce,
          ByteVector(Random.nextBytes(16)),
          TcpString(8, pq),
          fingerprints = fingerprints)

        val responseEncoded = respBody.encode
        val respHeader = PqHeader(
          ByteVector.fill(8)(0),
          ByteVector.fromLong(Instant.now.getEpochSecond, ordering = ByteOrdering.LittleEndian),
          responseEncoded.size.toInt)

        ZIO((respHeader.encode, responseEncoded,
          intrState
            .copy(nonce = Some(reqBody.nonce),
              severNonce = Some(respBody.serverNonce),
              pq = Some(pq),
              p = Some(ByteVector.fromInt(primes._1.toInt)),
              q = Some(ByteVector.fromInt(primes._2.toInt)))))
      }
      _ <- internalStateR.update(_ => newState)
      result <- Server.write(channel, respHeader ++ respBody).map(_ => channel)
    } yield result
  }
}
