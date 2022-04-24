package com.pygostylia.sshagent

import com.pygostylia.sshagent.keys.KeySpec
import com.pygostylia.sshagent.packets.{AddKeyPacket, ListKeysPacket, Packet, SignReqPacket}
import com.pygostylia.sshagent.serialization.SshProtocolWriter

import java.io.File
import java.net.{StandardProtocolFamily, UnixDomainSocketAddress}
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.file.Path
import scala.collection.mutable.ArrayBuffer

object Server {
  val keys: ArrayBuffer[KeySpec] = ArrayBuffer()

  def main(args: Array[String]): Unit = {
    val filename = "./socket"

    val path = Path.of(filename)
    val bindAddress = UnixDomainSocketAddress.of(path)
    val serverSocket = ServerSocketChannel.open(StandardProtocolFamily.UNIX)
    serverSocket.bind(bindAddress)
    path.toFile.deleteOnExit()

    println(s"Listening on $filename")

    while (true) {
      val channel = serverSocket.accept()
      val conn = Connection(channel)
      println("Client connected")

      var done = false

      while (conn.open && !done) {
        val packet = conn.recv()
        println(packet)
        packet match {
          case _: ListKeysPacket => listKeys(conn)
          case p: AddKeyPacket => addKey(p, conn)
          case p: SignReqPacket => signRequest(p, conn)
          case null => done = true
          case _ => conn.sendFailure()
        }
      }
    }
  }

  def listKeys(conn: Connection): Unit = {
    val packet = SshProtocolWriter()
    packet.write(Packet.SSH_AGENT_IDENTITIES_ANSWER)
    packet.writeInt(keys.length)

    keys.foreach { key =>
      key.encodePubKey(packet)
    }

    conn.send(packet.done())
  }

  def addKey(p: AddKeyPacket, conn: Connection): Unit = {
    keys.addOne(p.key)
    conn.sendSuccess()
  }

  def signRequest(packet: SignReqPacket, conn: Connection): Unit = {
    val sign = packet.signature()

    // Signing key find debug
    // keys.foreach { key => println(bufferView(key.keyBlob).mkString("have: <<", ", ", ">>")) }
    // println(packet.keyBlob.mkString("want: <<", ", ", ">>"))

    val signingKey: Option[KeySpec] = keys.find { key => bufferView(key.keyBlob) sameElements packet.keyBlob }

    if (signingKey.isEmpty) {
      conn.sendFailure()
      return
    }

    val key = signingKey.get

    val buffer = SshProtocolWriter()
    sign.initSign(key.privateKey)
    sign.update(packet.signData)
    val signature = sign.sign()

    buffer.write(Packet.SSH_AGENT_SIGN_RESPONSE)

    val blob = SshProtocolWriter()
    blob.writeString(packet.signatureMethod)
    blob.writeBytes(signature)

    buffer.writeBytes(blob.done())

    conn.send(buffer.done())
  }
}
