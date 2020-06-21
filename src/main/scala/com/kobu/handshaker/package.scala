package com.kobu

import scodec.bits.{ByteVector, _}

package object handshaker {

  implicit val pqHeaderDecoder: MessageDecoder[PqHeader] = (bytes: ByteVector) => {
    require(bytes.size == messagePqHeaderLength, s"find bytes: ${bytes.size}, but should be $messagePqHeaderLength")

    PqHeader(authKeyId = bytes.slice(authKeyIdPosition.start, authKeyIdPosition.end),
      messageId = bytes.slice(messageIdPosition.start, messageIdPosition.end),
      messageBodyLength = bytes.slice(messageBodyLengthPosition.start, messageBodyLengthPosition.end)
        .toInt(false, ordering = ByteOrdering.LittleEndian))
  }

  implicit val pqHeaderEncoder: MessageEncoder[PqHeader] = (message: PqHeader) =>
    message.authKeyId ++
      message.messageId ++
      ByteVector.fromInt(message.messageBodyLength, ordering = ByteOrdering.LittleEndian)

  implicit val reqPqDecoder: MessageDecoder[ReqPqBody] = (bytes: ByteVector) => {
    val incomeSchemaNumber = bytes.slice(pqSchemaPosition.start, pqSchemaPosition.end)
    require(incomeSchemaNumber == reqPqNumber)
    ReqPqBody(
      nonce = bytes.slice(pqNoncePosition.start, pqNoncePosition.end))
  }

  implicit val reqPqEncoder: MessageEncoder[ReqPqBody] = (message: ReqPqBody) =>
    reqPqNumber ++ message.nonce

  implicit val respPqDecoder: MessageDecoder[RespPqBody] = (bytes: ByteVector) => {
    val incomeSchemaNumber = bytes.slice(pqSchemaPosition.start, pqSchemaPosition.end)
    require(incomeSchemaNumber == respPqNumber)

    val pqSizeWithoutPadding = bytes.slice(pqSizePosition.start, pqSizePosition.end).toByte(false) + 1
    val padding = 4 - ((pqSizeWithoutPadding) % 4)
    val pqStringSize = pqSizeWithoutPadding + padding
    val pq = Pq.fromByteVector(bytes.slice(pqPosition(pqStringSize).start, pqPosition(pqStringSize).end))

    require(bytes.slice(pqVectorLongPosition(pqStringSize).start,
      pqVectorLongPosition(pqStringSize).end) == vectorLong, "incorrect vector schema number")

    val fingerprintsCount = bytes.slice(fingerprintsCountPosition(pqStringSize).start,
      fingerprintsCountPosition(pqStringSize).end).toInt(false, ByteOrdering.LittleEndian)
    val fingerprints =
      ByteUtils.groupBytesBy(bytes.slice(fingerprintsPosition(pqStringSize, fingerprintsCount).start,
        fingerprintsPosition(pqStringSize, fingerprintsCount).end), 8)

    RespPqBody(
      nonce = bytes.slice(pqNoncePosition.start, pqNoncePosition.end),
      serverNonce = bytes.slice(pqServerNoncePosition.start, pqServerNoncePosition.end),
      pq = pq,
      fingerprints = fingerprints)
  }

  implicit val respPqEncoder: MessageEncoder[RespPqBody] = new MessageEncoder[RespPqBody] {
    override def encode(message: RespPqBody): ByteVector = {
      respPqNumber ++
        message.nonce ++
        message.serverNonce ++
        message.pq.resultingByteVector ++
        vectorLong ++
        ByteVector.fromInt(message.fingerprints.size, 4, ordering = ByteOrdering.LittleEndian) ++
        message.fingerprints.reduce(_ ++ _)
    }
  }

  implicit val pQInnerDataDecoder: MessageDecoder[PQInnerData] = (bytes: ByteVector) => {
    PQInnerData(pq = Pq.fromByteVector(bytes.slice(innerDataPqPosition.start, innerDataPqPosition.end)),
      p = bytes.slice(innerDataPPosition.start, innerDataPPosition.end),
      q = bytes.slice(innerDataQPosition.start, innerDataQPosition.end),
      nonce = bytes.slice(innerDataNoncePosition.start, innerDataNoncePosition.end),
      serverNonce = bytes.slice(innerDataServerNoncePosition.start, innerDataServerNoncePosition.end),
      newNonce = bytes.slice(innerDataNewNoncePosition.start, innerDataNewNoncePosition.end))
  }

  implicit val pQInnerDataEncoder: MessageEncoder[PQInnerData] = (message: PQInnerData) =>
    pqInnerDateNumber ++
      message.pq.resultingByteVector ++
      message.p ++
      message.q ++
      message.nonce ++
      message.serverNonce ++
      message.newNonce

  implicit val reqDHParamsBodyDecoder: MessageDecoder[ReqDHParamsBody] = new MessageDecoder[ReqDHParamsBody] {
    override def decode(bytes: ByteVector): ReqDHParamsBody = {
      val incomeSchemaNumber = bytes.slice(pqSchemaPosition.start, pqSchemaPosition.end)
      require(incomeSchemaNumber == reqDHParamsNumber)

      ReqDHParamsBody(
        nonce = bytes.slice(pqNoncePosition.start, pqNoncePosition.end),
        serverNonce = bytes.slice(pqServerNoncePosition.start, pqServerNoncePosition.end),
        p = bytes.slice(reqDHParamsPPosition.start, reqDHParamsPPosition.end),
        q = bytes.slice(reqDHParamsQPosition.start, reqDHParamsQPosition.end),
        fingerprint = bytes.slice(reqDHParamsFingerprintPosition.start, reqDHParamsFingerprintPosition.end),
        encryptedData = bytes.slice(reqDHParamsEncryptedData.start, reqDHParamsEncryptedData.end))
    }
  }

  implicit val reqDHParamsBodyEncoder: MessageEncoder[ReqDHParamsBody] = (message: ReqDHParamsBody) => {
    reqDHParamsNumber ++
      message.nonce ++
      message.serverNonce ++
      message.p ++
      message.q ++
      message.fingerprint ++
      message.encryptedData
  }

  val reqPqNumber: ByteVector = hex"60469778".reverse
  val respPqNumber: ByteVector = hex"05162463".reverse
  val vectorLong: ByteVector = hex"1cb5c415".reverse
  val pqInnerDateNumber: ByteVector = hex"83c95aec".reverse
  val reqDHParamsNumber: ByteVector = hex"d712e4be".reverse

  //POSITIONS

  case class Position(start: Int, shift: Int) {
    val end = start + shift
  }

  val messagePqHeaderLength: Int = 20
  val defaultPqStringSize = 12

  val authKeyIdPosition = Position(0, 8)
  val messageIdPosition = Position(8, 8)
  val messageBodyLengthPosition = Position(16, 4)
  val pqSchemaPosition = Position(20 - messagePqHeaderLength, 4)
  val pqNoncePosition = Position(24 - messagePqHeaderLength, 16)
  val pqServerNoncePosition = Position(40 - messagePqHeaderLength, 16)

  def pqPosition(stringSize: Int) = Position(56 - messagePqHeaderLength, stringSize)

  def pqSizePosition = Position(56 - messagePqHeaderLength, 1)

  def pqVectorLongPosition(pqStringLength: Int) =
    Position(68 + pqStringLength - defaultPqStringSize - messagePqHeaderLength, 4)

  def fingerprintsCountPosition(pqStringLength: Int) =
    Position(72 + pqStringLength - defaultPqStringSize - messagePqHeaderLength, 4)

  def fingerprintsPosition(pqStringLength: Int, fingerprintsCount: Int) =
    Position(76 + pqStringLength - defaultPqStringSize - messagePqHeaderLength, fingerprintsCount * 8)

  val innerDataPqPosition = Position(4, 12)
  val innerDataPPosition = Position(16, 8)
  val innerDataQPosition = Position(24, 8)
  val innerDataNoncePosition = Position(32, 16)
  val innerDataServerNoncePosition = Position(48, 16)
  val innerDataNewNoncePosition = Position(64, 32)


  val reqDHParamsPPosition = Position(56 - messagePqHeaderLength, 8)
  val reqDHParamsQPosition = Position(64 - messagePqHeaderLength, 8)

  val reqDHParamsFingerprintPosition = Position(72 - messagePqHeaderLength, 8)
  val reqDHParamsEncryptedData = Position(80 - messagePqHeaderLength, 256)
}
