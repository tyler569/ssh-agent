package com.pygostylia.sshagent.keys

import com.pygostylia.sshagent.serialization.SshProtocolWriter

import java.nio.ByteBuffer
import java.security.{PrivateKey, PublicKey, Signature}

trait KeySpec {
  protected val comment: String

  def keyBlob: ByteBuffer

  def keyType: String

  def privateKey: PrivateKey

  def publicKey: PublicKey

  def signature(flags: Int): (Signature, String)

  final def encodePubKey(buffer: SshProtocolWriter): Unit = {
    buffer.writeBytes(keyBlob)
    buffer.writeString(comment)
  }
}
