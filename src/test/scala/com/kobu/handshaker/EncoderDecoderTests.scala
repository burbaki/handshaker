package com.kobu.handshaker

import java.time.Instant

import com.kobu.handshaker.MessageEncodeDecode._
import org.scalatest.funsuite.AnyFunSuite
import org.scalatest.matchers.should.Matchers
import scodec.bits.{ByteOrdering, ByteVector}

import scala.util.Random

class EncoderDecoderTests extends AnyFunSuite with Matchers {

  test("pq header should be equal to encode and then decode message") {
    val unixTime: Long = Instant.now.getEpochSecond
    val header = PqHeader(ByteVector.fill(8)(0),
      ByteVector.fromLong(unixTime, ordering = ByteOrdering.LittleEndian),
      20)
    val encoded: ByteVector = header.encode
    val decoded = encoded.decode[PqHeader]
    decoded shouldEqual header
  }

  test("req Pq should be equal to encode and then decode message") {

    val request: ReqPqBody = ReqPqBody(
      ByteVector(Random.nextBytes(16)))
    val encoded: ByteVector = request.encode
    val decoded = encoded.decode[ReqPqBody]
    decoded shouldEqual request
  }

  test("resp Pq should be equal to encode and then decode message") {
    val response: RespPqBody = RespPqBody(
      ByteVector(Random.nextBytes(16)),
      ByteVector(Random.nextBytes(16)),
      Pq(8, ByteVector(Random.nextBytes(8))),
      fingerprints = Vector(ByteVector(Random.nextBytes(8))))
    val encoded: ByteVector = response.encode
    val decoded = encoded.decode[RespPqBody]
    decoded shouldEqual response
  }

  test("resp Pq with multiple fingerprints should be equal to encode and then decode message") {
    val response: RespPqBody = RespPqBody(
      ByteVector(Random.nextBytes(16)),
      ByteVector(Random.nextBytes(16)),
      Pq(8, ByteVector(Random.nextBytes(8))),
      fingerprints = Vector(ByteVector(Random.nextBytes(8)), ByteVector(Random.nextBytes(8)), ByteVector(Random.nextBytes(8))))
    val encoded: ByteVector = response.encode
    val decoded = encoded.decode[RespPqBody]
    decoded shouldEqual response
  }

  test("resp Pq with non 12 length pq string should be equal to encode and then decode message") {
    val response: RespPqBody = RespPqBody(
      ByteVector(Random.nextBytes(16)),
      ByteVector(Random.nextBytes(16)),
      // 1 + 13 == 14 => 14 + 2padding == 16
      Pq(13, ByteVector(Random.nextBytes(13)), 16),
      fingerprints = Vector(ByteVector(Random.nextBytes(8))))
    val encoded: ByteVector = response.encode
    val decoded = encoded.decode[RespPqBody]
    decoded shouldEqual response
  }
}

