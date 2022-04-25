package com.pygostylia.sshagent.packets

import java.security.Signature

class SignReqPacket(data: Array[Byte]) extends Packet(Packet.SSH_AGENTC_SIGN_REQUEST, data) {
  override def toString: String = s"SignReqPacket(...)"

  println(data.mkString("signreq data: <<", ", ", ">>"))

  val keyBlob: Array[Byte] = reader.readBytes()

  val signData: Array[Byte] = reader.readBytes()

  val flags: Int = reader.readInt()
}

object SignReqPacket {
  val SSH_AGENT_RSA_SHA2_256 = 2
  val SSH_AGENT_RSA_SHA2_512 = 4
}