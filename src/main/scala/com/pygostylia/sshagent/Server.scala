package com.pygostylia.sshagent

import com.pygostylia.sshagent.keys.KeySpec
import com.pygostylia.sshagent.packets.{AddKeyPacket, ListKeysPacket, Packet, SignReqPacket}
import com.pygostylia.sshagent.serialization.SshProtocolWriter

import java.io.{File, IOException}
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
      val socket = serverSocket.accept()
      val conn = new Connection(socket)
      Thread(new Runnable {
        def run(): Unit = try {
          while (true) {
            val packet = conn.recv()
            println(packet)
            packet match {
              case _: ListKeysPacket => listKeys(conn)
              case p: AddKeyPacket => addKey(p, conn)
              case p: SignReqPacket => signRequest(p, conn)
              case null => return;
              case _ => conn.sendFailure()
            }
          }
        } catch {
          case _: IOException =>
        }
      }).run()
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
    p.key.match {
      case Some(k) =>
        keys.addOne(k)
        conn.sendSuccess()
      case None => conn.sendFailure()
    }
  }

  def signRequest(packet: SignReqPacket, conn: Connection): Unit = {
    // Signing key find debug
    // keys.foreach { key => println(bufferView(key.keyBlob).mkString("have: <<", ", ", ">>")) }
    // println(packet.keyBlob.mkString("want: <<", ", ", ">>"))

    val signingKey: Option[KeySpec] = keys.find { key => bufferView(key.keyBlob) sameElements packet.keyBlob }

    if (signingKey.isEmpty) {
      conn.sendFailure()
      return
    }

    val key = signingKey.get

    val (sign, method) = key.signature(packet.flags)

    val buffer = SshProtocolWriter()
    sign.initSign(key.privateKey)
    sign.update(packet.signData)
    var signature = sign.sign()

    // Super hacky; we should probably move sign() into KeySpec implementations
    // if the encodings are going to be so different.
    if (method.startsWith("ecdsa")) {
      val startR = if ((signature(1) & 0x80) != 0) 3 else 2
      val lengthR = signature(startR + 1)
      val startS = startR + 2 + lengthR
      val lengthS = signature(startS + 1)
      val r = BigInt(signature.slice(startR + 2, startR + 2 + lengthR))
      val s = BigInt(signature.slice(startS + 2, startS + 2 + lengthS))

      val sigblob = SshProtocolWriter()
      sigblob.writeMpInt(r.bigInteger)
      sigblob.writeMpInt(s.bigInteger)
      signature = sigblob.array()
    }

    buffer.write(Packet.SSH_AGENT_SIGN_RESPONSE)

    val blob = SshProtocolWriter()
    blob.writeString(method)
    blob.writeBytes(signature)

    buffer.writeBytes(blob.done())

    conn.send(buffer.done())
  }
}
