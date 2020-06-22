package com.kobu.handshaker

import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.{AsynchronousServerSocketChannel, AsynchronousSocketChannel}
import java.security.{KeyPair, KeyPairGenerator, MessageDigest}
import java.time.Instant

import com.kobu.handshaker.MessageEncodeDecode._
import com.kobu.handshaker.Server.requestsListener
import com.kobu.handshaker.handlers.TmHandlerPq
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import org.scalatest.{BeforeAndAfterAll, GivenWhenThen}
import scodec.bits.{ByteOrdering, ByteVector}
import zio.{RIO, Ref}

import scala.util.Random

class TmHandlerPqTest
  extends AnyFunSuite
    with Matchers
    with BeforeAndAfterAll
    with GivenWhenThen {

  final val hostAddress = new InetSocketAddress("127.0.0.1", 4999)
  val runtime = zio.Runtime.default
  val keyGen = KeyPairGenerator.getInstance("RSA")
  keyGen.initialize(2048)
  val pair: KeyPair = keyGen.generateKeyPair
  val initServerState = ServerState(pair.getPrivate, pair.getPublic)
  val state = runtime.unsafeRun(Ref.make(initServerState))
  val handler = new TmHandlerPq(state)

  override def beforeAll() {
    val server = AsynchronousServerSocketChannel.open().bind(hostAddress)
    val serverZ = RIO(server)
    runtime.unsafeRunAsync_(requestsListener(serverZ, handler).map(_.close()))
  }


  test("tmHandler should accept rq request and response with rq response success case") {
    val unixTime: Long = Instant.now.getEpochSecond

    Given("request header for pq")
    val reqHeaderForPq = PqHeader(ByteVector.fill(8)(0),
      ByteVector.fromLong(unixTime, ordering = ByteOrdering.LittleEndian),
      20)
    val encodedHeader: ByteVector = reqHeaderForPq.encode

    Given("request body for pq")
    val reqBodyForPq: ReqPqBody = ReqPqBody(
      ByteVector(Random.nextBytes(16)))

    val encodedRequest: ByteVector = reqBodyForPq.encode

    val client = AsynchronousSocketChannel.open
    client.connect(hostAddress).get()

    When("client send header and body for pq")
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
    val stateAfterPqRequest: ServerState = runtime.unsafeRun(state.get)

    Then("internal state of server should be updated and server should send correct answer")
    stateAfterPqRequest.pq.isDefined shouldBe true
    stateAfterPqRequest.p.isDefined shouldBe true
    stateAfterPqRequest.q.isDefined shouldBe true
    stateAfterPqRequest.severNonce.isDefined shouldBe true
    stateAfterPqRequest.nonce.isDefined shouldBe true

    response.nonce shouldEqual reqBodyForPq.nonce
    response.fingerprints.head shouldEqual
      ByteVector(pair.getPublic.getEncoded).digest(MessageDigest.getInstance("SHA1")).take(8)

    Given("internal data for encrypting")
    val innerDataRequest = PQInnerData(response.pq,
      TcpString(4, stateAfterPqRequest.p.get, 8),
      TcpString(4, stateAfterPqRequest.q.get, 8),
      response.nonce,
      response.serverNonce,
      newNonce = ByteVector(Random.nextBytes(32)))
    val encrypted = ClientTestHelper.getEncryptedData(innerDataRequest, pair.getPublic)

    Given("request body for DH params")
    val reqDHParamsBody = ReqDHParamsBody(
      innerDataRequest.nonce,
      innerDataRequest.serverNonce,
      innerDataRequest.p,
      innerDataRequest.q,
      response.fingerprints.head,
      encrypted).encode

    Given("request header for DH params")
    val reqHeaderForReqDH = PqHeader(ByteVector.fill(8)(0),
      ByteVector.fromLong(unixTime, ordering = ByteOrdering.LittleEndian),
      reqDHParamsBody.size.toInt)

    When("send correct request DH params to server")
    val rawMessageReqDH: ByteBuffer = (reqHeaderForReqDH.encode ++ reqDHParamsBody).toByteBuffer
    client.write(rawMessageReqDH).get()

    val readBuffForHeaderReqDH = ByteBuffer.allocate(20)
    client.read(readBuffForHeaderReqDH).get()

    val schemaBuffer = ByteBuffer.allocate(4)
    client.read(schemaBuffer).get()

    schemaBuffer.flip()
    val respSchema = ByteVector(schemaBuffer)

    Then("Server should send serverDHParamsOk message")
    respSchema shouldBe serverDHParamsOk
  }

  test("tmHandler should accept rq request and response with rq response fail case") {
    val unixTime: Long = Instant.now.getEpochSecond

    Given("request header for pq")
    val reqHeaderForPq = PqHeader(ByteVector.fill(8)(0),
      ByteVector.fromLong(unixTime, ordering = ByteOrdering.LittleEndian),
      20)
    val encodedHeader: ByteVector = reqHeaderForPq.encode

    Given("request body for pq")
    val reqBodyForPq: ReqPqBody = ReqPqBody(
      ByteVector(Random.nextBytes(16)))

    val encodedRequest: ByteVector = reqBodyForPq.encode

    val client = AsynchronousSocketChannel.open
    client.connect(hostAddress).get()

    When("client send header and body for pq")
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
    val stateAfterPqRequest: ServerState = runtime.unsafeRun(state.get)

    Then("internal state of server should be updated and server should send correct answer")
    stateAfterPqRequest.pq.isDefined shouldBe true
    stateAfterPqRequest.p.isDefined shouldBe true
    stateAfterPqRequest.q.isDefined shouldBe true
    stateAfterPqRequest.severNonce.isDefined shouldBe true
    stateAfterPqRequest.nonce.isDefined shouldBe true

    response.nonce shouldEqual reqBodyForPq.nonce
    response.fingerprints.head shouldEqual
      ByteVector(pair.getPublic.getEncoded).digest(MessageDigest.getInstance("SHA1")).take(8)

    Given("internal data for encrypting")
    val innerDataRequest = PQInnerData(response.pq,
      TcpString(4, stateAfterPqRequest.p.get, 8),
      TcpString(4, stateAfterPqRequest.q.get, 8),
      response.nonce,
      ByteVector(Random.nextBytes(16)),
      newNonce = ByteVector(Random.nextBytes(32)))
    val encrypted = ClientTestHelper.getEncryptedData(innerDataRequest, pair.getPublic)

    Given("request body for DH params")
    val reqDHParamsBody = ReqDHParamsBody(
      innerDataRequest.nonce,
      innerDataRequest.serverNonce,
      innerDataRequest.p,
      innerDataRequest.q,
      response.fingerprints.head,
      encrypted).encode

    Given("request header for DH params")
    val reqHeaderForReqDH = PqHeader(ByteVector.fill(8)(0),
      ByteVector.fromLong(unixTime, ordering = ByteOrdering.LittleEndian),
      reqDHParamsBody.size.toInt)

    When("send incorrect request DH params to server")
    val rawMessageReqDH: ByteBuffer = (reqHeaderForReqDH.encode ++ reqDHParamsBody).toByteBuffer
    client.write(rawMessageReqDH).get()

    val readBuffForHeaderReqDH = ByteBuffer.allocate(20)
    client.read(readBuffForHeaderReqDH).get()

    val schemaBuffer = ByteBuffer.allocate(4)
    client.read(schemaBuffer).get()

    schemaBuffer.flip()
    val respSchema = ByteVector(schemaBuffer)

    Then("Server should send serverDHParamsFail message")
    respSchema shouldBe serverDHParamsFail
  }
}
