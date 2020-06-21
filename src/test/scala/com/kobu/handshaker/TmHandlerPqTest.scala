package com.kobu.handshaker

import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.{AsynchronousServerSocketChannel, AsynchronousSocketChannel}
import java.security.MessageDigest
import java.time.Instant

import com.kobu.handshaker.MessageEncodeDecode._
import com.kobu.handshaker.Server.requstsListener
import com.kobu.handshaker.handlers.TmHandlerPq
import org.scalatest.BeforeAndAfterAll
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import scodec.bits.{ByteOrdering, ByteVector}
import zio.RIO

import scala.util.Random

class TmHandlerPqTest extends AnyFunSuite with Matchers with BeforeAndAfterAll {

  final val hostAddress = new InetSocketAddress("127.0.0.1", 4999)
  val runtime = zio.Runtime.default
  val handler = new TmHandlerPq

  override def beforeAll() {
    val server = AsynchronousServerSocketChannel.open().bind(hostAddress)
    val serverZ = RIO(server)
    runtime.unsafeRunAsync_(requstsListener(serverZ, handler))
    println("started")
  }


  test("tmHandler should accept  rq request and response with rq response") {
    val unixTime: Long = Instant.now.getEpochSecond
    val reqHeader = PqHeader(ByteVector.fill(8)(0),
      ByteVector.fromLong(unixTime, ordering = ByteOrdering.LittleEndian),
      20)
    val encodedHeader: ByteVector = reqHeader.encode
    val request: ReqPqBody = ReqPqBody(
      ByteVector(Random.nextBytes(16)))
    val encodedRequest: ByteVector = request.encode

    val client = AsynchronousSocketChannel.open
    client.connect(hostAddress).get()
    val rawMessage: ByteBuffer = (encodedHeader ++ encodedRequest).toByteBuffer
    client.write(rawMessage).get()

    val readBuffForHeader = ByteBuffer.allocate(20)
    client.read(readBuffForHeader).get()
    readBuffForHeader.flip()
    val respHeader = ByteVector(readBuffForHeader).decode[PqHeader]

    val readBuffForResponse = ByteBuffer.allocate(respHeader.messageBodyLength)
    client.read(readBuffForResponse).get
    readBuffForResponse.flip()
    val response = ByteVector(readBuffForResponse).decode[RespPqBody]
    response.nonce shouldEqual request.nonce
    response.fingerprints.head shouldEqual
      ByteVector(handler.publicKey.getEncoded).digest(MessageDigest.getInstance("SHA1")).take(8)
  }

}
