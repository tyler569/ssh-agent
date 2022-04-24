package com.pygostylia.sshagent.packets

class ListKeysPacket(data: Array[Byte]) extends Packet(Packet.SSH_AGENTC_REQUEST_IDENTITIES, data) {
  override def toString: String = s"ListKeysPacket()"
}
