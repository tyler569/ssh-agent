package com.pygostylia.sshagent

import com.pygostylia.sshagent.packets.{AddKeyPacket, ListKeysPacket, Packet, SignReqPacket}

import java.nio.ByteBuffer
import java.nio.channels.SocketChannel

class Connection(channel: SocketChannel) {
  def open: Boolean = channel.isConnected && channel.isOpen

  def recv(): Packet = {
    val lenBuffer = ByteBuffer.allocate(4)
    channel.read(lenBuffer)
    val len = lenBuffer.getInt(0)
    if (len == 0) return null
    val buffer = ByteBuffer.allocate(len)
    channel.read(buffer)
    val typ = buffer.get(0)
    val data = buffer.array().slice(1, len)

    typ match {
      case Packet.SSH_AGENTC_REQUEST_IDENTITIES => ListKeysPacket(data)
      case Packet.SSH_AGENTC_ADD_IDENTITY => AddKeyPacket(data)
      case Packet.SSH_AGENTC_SIGN_REQUEST => SignReqPacket(data)
      case _ => Packet(typ, data)
    }
  }

  def send(data: Array[Byte]): Unit = {
    val lenBuffer = ByteBuffer.allocate(4)
    lenBuffer.putInt(data.length)
    lenBuffer.rewind()
    channel.write(lenBuffer)
    println(s"sending: ${data.mkString("<<", ", ", ">>")}")
    channel.write(ByteBuffer.wrap(data))
  }

  def sendSuccess(): Unit = {
    send(Array(Packet.SSH_AGENT_SUCCESS))
  }

  def sendFailure(): Unit = {
    send(Array(Packet.SSH_AGENT_FAILURE))
  }
}
