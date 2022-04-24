package com.pygostylia.sshagent.packets

import com.pygostylia.sshagent.keys.{KeySpec, RsaKeySpec}

class AddKeyPacket(data: Array[Byte]) extends Packet(Packet.SSH_AGENTC_ADD_IDENTITY, data) {
  val keyType: String = reader.readString()

  val key: KeySpec = keyType match {
    case "ssh-rsa" => RsaKeySpec(reader)
  }

  override def toString: String = s"AddKeyPacket($keyType, $key)"
}
