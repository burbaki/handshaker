package com.kobu.handshaker

import java.net.InetSocketAddress
import java.nio.channels.AsynchronousServerSocketChannel

import com.kobu.handshaker.Server.requstsListener
import com.kobu.handshaker.handlers.HelloWorldHandler
import zio.RIO


object App extends scala.App {

  val hostAddress = new InetSocketAddress("127.0.0.1", 4999)
  val server = AsynchronousServerSocketChannel.open().bind(hostAddress)
  val serverZ = RIO(server)

  val runtime = zio.Runtime.default
  runtime.unsafeRun(requstsListener(serverZ, new HelloWorldHandler))


  //  implicit val exContext = ExecutionContext.fromExecutorService(Executors.newFixedThreadPool(4))
  //
  //  val hostAddress = new InetSocketAddress("127.0.0.1", 4999)
  //
  //  val server = AsynchronousServerSocketChannel.open()
  //  server.bind(hostAddress)
  //
  //  val acceptResult: Future[AsynchronousSocketChannel] = Future(server.accept.get)
  //
  //
  //  def listen(channel: AsynchronousSocketChannel): Unit  = {
  //      var buffer = ByteBuffer.allocate(32)
  //      val readResult = channel.read(buffer)
  //      readResult.get
  //      buffer.flip
  //      val message = BitVector(buffer.array)
  //      println(s"get income message: $message")
  //      val writeResult = channel.write(message.reverseByteOrder.toByteBuffer)
  //      writeResult.get
  //      buffer.clear
  //      listen(channel)
  //    }
  //
  //  acceptResult.map(listen)
}
