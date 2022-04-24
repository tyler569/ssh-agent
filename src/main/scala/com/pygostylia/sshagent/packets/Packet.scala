package com.pygostylia.sshagent.packets

import com.pygostylia.sshagent.serialization.SshProtocolReader

class Packet(val typ: Byte, data: Array[Byte]) {
  override def toString: String = s"Packet($typ, ...)"

  protected val reader: SshProtocolReader = SshProtocolReader(data)
}

object Packet {
  val SSH_AGENTC_REQUEST_IDENTITIES: Byte = 11
  val SSH_AGENTC_SIGN_REQUEST: Byte = 13
  val SSH_AGENTC_ADD_IDENTITY: Byte = 17
  val SSH_AGENTC_REMOVE_IDENTITY: Byte = 18
  val SSH_AGENTC_REMOVE_ALL_IDENTITIES: Byte = 19
  val SSH_AGENTC_ADD_ID_CONSTRAINED: Byte = 25
  val SSH_AGENTC_ADD_SMARTCARD_KEY: Byte = 20
  val SSH_AGENTC_REMOVE_SMARTCARD_KEY: Byte = 21
  val SSH_AGENTC_LOCK: Byte = 22
  val SSH_AGENTC_UNLOCK: Byte = 23
  val SSH_AGENTC_ADD_SMARTCARD_KEY_CONSTRAINED: Byte = 26
  val SSH_AGENTC_EXTENSION: Byte = 27

  val SSH_AGENT_FAILURE: Byte = 5
  val SSH_AGENT_SUCCESS: Byte = 6
  val SSH_AGENT_EXTENSION_FAILURE: Byte = 28
  val SSH_AGENT_IDENTITIES_ANSWER: Byte = 12
  val SSH_AGENT_SIGN_RESPONSE: Byte = 14
}