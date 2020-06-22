package com.kobu.handshaker.handlers

import java.nio.channels.AsynchronousSocketChannel

import com.kobu.handshaker.MessageEncodeDecode._
import com.kobu.handshaker.{PqHeader, Server, ServerState, messagePqHeaderLength}
import zio.ZIO
import zio.blocking.Blocking

trait TcpHandler {

  val nextTcpHandler: Option[TcpHandler]

  val internalStateR: zio.Ref[ServerState]

  final def handle(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel] =
    nextTcpHandler match {
      case None =>
        handleInternal(channel)
      case Some(next) =>
        handleInternal(channel).flatMap(_ => next.handle(channel))
    }

  def handleInternal(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel]


  def readHeaderAndBody(channel: AsynchronousSocketChannel) = {
    for {
      rawReqHeader <- Server.read(channel, messagePqHeaderLength)
      rawReqBody <- {
        val pqHeader = rawReqHeader.decode[PqHeader]
        val sizeBody = pqHeader.messageBodyLength
        Server.read(channel, sizeBody)
      }
    } yield (rawReqHeader, rawReqBody)
  }
}
