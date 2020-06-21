package com.kobu.handshaker.handlers

import java.nio.channels.AsynchronousSocketChannel

import zio.ZIO
import zio.blocking.Blocking

trait TcpHandler {

  val nextTcpHandler: Option[TcpHandler]

  final def handle(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel] =
    nextTcpHandler match {
      case None =>
        handleInternal(channel)
      case Some(next) =>
        handleInternal(channel).flatMap(next.handle)
    }

  def handleInternal(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel]

}
