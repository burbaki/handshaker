package com.kobu.handshaker

import java.nio.ByteBuffer

import scodec.bits.BitVector
import scodec.codecs.ascii32

object Client extends scala.App {

  import java.net.InetSocketAddress
  import java.nio.channels.AsynchronousSocketChannel

  val client1 = AsynchronousSocketChannel.open
  val client2 = AsynchronousSocketChannel.open
  val client3 = AsynchronousSocketChannel.open
  val client4 = AsynchronousSocketChannel.open

  val hostAddress = new InetSocketAddress("localhost", 4999)


  def sendMessage(message: String, clientChannel: AsynchronousSocketChannel) = {
    clientChannel.connect(hostAddress).get()
    println(clientChannel.getLocalAddress)
    ascii32.encode(message).map(byteMsg => {
      val buffer = byteMsg.toByteBuffer
      val bv = BitVector(buffer)
      ascii32.decode(bv).toOption.foreach(dr => println(s"${Thread.currentThread().getId} ${dr.value}"))

      clientChannel.write(buffer).get()

      val readBuff = ByteBuffer.allocate(32)
      clientChannel.read(readBuff).get
      readBuff.flip()
      val bvr = BitVector(readBuff)
      println("-----------")
      println(buffer)
      println(readBuff)
      println(bv)
      println(bvr)
      println("-----------")
      ascii32.compact.decode(bvr).map(dr => println(s"${Thread.currentThread().getId} ${dr}"))


    })
  }

  //
  println(sendMessage("hihi1234567890client1", client1))
  println(sendMessage("hihi1234567890client2", client2))
  println(sendMessage("hihi1234567890client3", client3))
  println(sendMessage("hihi1234567890client4", client4))

}
