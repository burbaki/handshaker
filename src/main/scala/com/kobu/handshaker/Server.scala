package com.kobu.handshaker

import java.nio.ByteBuffer
import java.nio.channels.{AsynchronousServerSocketChannel, AsynchronousSocketChannel}

import com.kobu.handshaker.handlers.TcpHandler
import scodec.bits.ByteVector
import zio.blocking.Blocking
import zio.{RIO, ZIO}

object Server {

  def accept(server: AsynchronousServerSocketChannel, handler: TcpHandler): RIO[Blocking, AsynchronousSocketChannel] = {
    val x: RIO[Blocking, AsynchronousSocketChannel] = ZIO.fromFutureJava(server.accept).map(s => {
      println(s"new connection for: ${s}");
      s
    })
    x.flatMap(channel => handler.handle(channel))
  }

  def read(conn: AsynchronousSocketChannel, size: Int): RIO[Blocking, ByteVector] = {
    val buf = ByteBuffer.allocate(size)
    conn.read(buf).get()
    buf.flip()
    ZIO(ByteVector(buf))
  }

  def write(conn: AsynchronousSocketChannel, message: ByteVector) = {
    val buf = message.toByteBuffer
    ZIO.fromFutureJava(conn.write(buf))
  }

  def requstsListener(server: RIO[Blocking, AsynchronousServerSocketChannel], handler: TcpHandler): RIO[Blocking, AsynchronousServerSocketChannel] = {
    server.flatMap(accept(_, handler)).forever

  }

  def main() = {

  }
}
