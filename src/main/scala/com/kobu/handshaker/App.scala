package com.kobu.handshaker

import java.net.InetSocketAddress
import java.nio.channels.AsynchronousServerSocketChannel
import java.security.{KeyPair, KeyPairGenerator}

import com.kobu.handshaker.Server.requestsListener
import com.kobu.handshaker.handlers.TmHandlerPq
import zio.{RIO, Ref}

object App extends scala.App {

  val hostAddress = new InetSocketAddress("127.0.0.1", 4999)
  val server = AsynchronousServerSocketChannel.open().bind(hostAddress)
  val serverZ = RIO(server)

  val runtime = zio.Runtime.default
  val keyGen = KeyPairGenerator.getInstance("RSA")
  keyGen.initialize(2048)
  val pair: KeyPair = keyGen.generateKeyPair
  val initServerState = ServerState(pair.getPrivate, pair.getPublic)

  val app = for {
    state <- Ref.make(initServerState)
    _ <- requestsListener(serverZ, new TmHandlerPq(state))
  } yield ()

  runtime.unsafeRun(app)

}
