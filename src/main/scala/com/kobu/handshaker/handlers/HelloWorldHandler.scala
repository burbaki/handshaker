package com.kobu.handshaker.handlers

import java.nio.channels.AsynchronousSocketChannel

import com.kobu.handshaker.Server._
import scodec.codecs.ascii32
import zio.ZIO
import zio.blocking.Blocking

class HelloWorldHandler extends TcpHandler {
  override def handleInternal(channel: AsynchronousSocketChannel): ZIO[Blocking, Throwable, AsynchronousSocketChannel] =
    read(channel, 32).flatMap(res => {
      ascii32.decodeValue(res.toBitVector).toOption.foreach(dr => println(s"${Thread.currentThread().getId} ${dr}"))
      write(channel, res).map(_ => channel)
    })

  override val nextTcpHandler: Option[TcpHandler] = None
}
