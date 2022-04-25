package com.pygostylia.sshagent.packets

import com.pygostylia.sshagent.keys.{KeySpec, RsaKeySpec, EcdsaKeySpec}

class AddKeyPacket(data: Array[Byte]) extends Packet(Packet.SSH_AGENTC_ADD_IDENTITY, data) {
  val keyType: String = reader.readString()

  val key: Option[KeySpec] = keyType match {
    case "ssh-rsa" => Some(RsaKeySpec(reader))
    case typ if typ.startsWith("ecdsa-sha2-") => Some(EcdsaKeySpec(reader))
    case _ => None
  }

  override def toString: String = s"AddKeyPacket($keyType, $key)"
}
