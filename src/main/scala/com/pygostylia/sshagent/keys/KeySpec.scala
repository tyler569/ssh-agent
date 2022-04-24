package com.pygostylia.sshagent.keys

import com.pygostylia.sshagent.serialization.SshProtocolWriter

import java.nio.ByteBuffer
import java.security.{PrivateKey, PublicKey}

trait KeySpec {
  protected val comment: String

  def keyBlob: ByteBuffer

  def keyType: String

  def encodePubKey(buffer: SshProtocolWriter): Unit = {
    buffer.writeBytes(keyBlob)
    buffer.writeString(comment)
  }

  def privateKey: PrivateKey

  def publicKey: PublicKey
}
