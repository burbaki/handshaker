package com.kobu.handshaker.handlers

import java.nio.channels.AsynchronousSocketChannel
import java.security.MessageDigest
import java.time.Instant

import com.kobu.handshaker.MessageEncodeDecode._
import com.kobu.handshaker.{CryptoUtils, DHInnerData, PQInnerData, PqHeader, ReqDHParamsBody, Server, ServerDHParamsFail, ServerDHParamsOk, ServerState}
import javax.crypto.Cipher
import scodec.bits.{ByteOrdering, ByteVector}
import zio.blocking.Blocking
import zio.{Ref, ZIO}

import scala.util.Random

class TmHandlerDHParams(override val internalStateR: Ref[ServerState]) extends TcpHandler {
  override val nextTcpHandler: Option[TcpHandler] = None


  def validation(encrypt: PQInnerData, body: ReqDHParamsBody, state: ServerState): Either[String, ()] = {

    def equalsWithOption[T](op: Option[T], v: T, message: String): Either[String, ()] = {
      op.filter(_ == v).toRight(message).map(_ => ())
    }

    for {
      pq <- equalsWithOption(state.pq, encrypt.pq.bytes, "wrong pq")
      p <- equalsWithOption(state.p, encrypt.p.bytes, "wrong p")
      q <- equalsWithOption(state.q, encrypt.q.bytes, "wrong q")
      nonce <- equalsWithOption(state.nonce, encrypt.nonce, "wrong nonce")
      serverNonce <- equalsWithOption(state.severNonce, encrypt.serverNonce, "wrong serverNonce")
    } yield (serverNonce)

  }

  override def handleInternal(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel] = {
    for {
      (_, rawReqBody) <- readHeaderAndBody(channel)
      intrState <- internalStateR.get
      (respHeader, respBody, _) <- {
        val reqBody = rawReqBody.decode[ReqDHParamsBody]
        val encryptedData = reqBody.encryptedData
        val cipher = Cipher.getInstance("RSA/ECB/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, intrState.privateKey)
        val decrypted = ByteVector(cipher.doFinal(encryptedData.toArray)).drop(1).slice(20, 96 + 20)
        val internalClientData = decrypted.decode[PQInnerData]
        val validationResult = validation(internalClientData, reqBody, intrState)
        val headerWithoutSize = PqHeader(
          ByteVector.fill(8)(0),
          ByteVector.fromLong(Instant.now.getEpochSecond, ordering = ByteOrdering.LittleEndian),
          _)
        validationResult match {
          case Right(()) => {
            val serverInner = DHInnerData(
              reqBody.nonce,
              reqBody.serverNonce,
              ByteVector(Random.nextBytes(4)),
              ByteVector(Random.nextBytes(260)),
              ByteVector(Random.nextBytes(260)),
              ByteVector(Random.nextBytes(4)))
            val encryptedAnswer = CryptoUtils.getEncryptedData(serverInner)
            val respBody = ServerDHParamsOk(reqBody.nonce,
              reqBody.serverNonce,
              encryptedAnswer).encode
            headerWithoutSize(respBody.size.toInt)
            ZIO(headerWithoutSize(respBody.size.toInt), respBody, intrState)
          }
          case Left(s) =>
            val respBody = ServerDHParamsFail(reqBody.nonce,
              reqBody.serverNonce,
              internalClientData.newNonce
                .digest(MessageDigest.getInstance("SHA1")).take(16)).encode

            ZIO(headerWithoutSize(respBody.size.toInt), respBody, intrState)
        }
      }
      result <- Server.write(channel, respHeader.encode ++ respBody).map(_ => channel)
    } yield result
  }


}
