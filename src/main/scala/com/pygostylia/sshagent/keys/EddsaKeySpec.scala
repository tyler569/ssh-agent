package com.pygostylia.sshagent.keys

import com.pygostylia.sshagent.serialization.{SshProtocolReader, SshProtocolWriter}

import java.nio.ByteBuffer
import java.security.interfaces.EdECPublicKey
import java.security.spec.{EdDSAParameterSpec, EdECPoint, EdECPrivateKeySpec, EdECPublicKeySpec, NamedParameterSpec}
import java.security.{AlgorithmParameters, KeyFactory, PrivateKey, PublicKey, Signature}

class EddsaKeySpec(reader: SshProtocolReader) extends KeySpec {
  private val pub = reader.readMpInt()
  private val priv = reader.readBytes()
  protected val comment: String = reader.readString()

  override def toString: String = s"EddsaKeySpec($comment, $pub)"

  override def keyBlob: ByteBuffer = {
    val blob = SshProtocolWriter()
    blob.writeString(keyType)
    blob.writeBytes(pub.toByteArray)
    blob.done()
  }

  override def keyType: String = "ssh-ed25519"

  private val keyFactory = KeyFactory.getInstance("Ed25519")

  private val privateKeyData = priv.slice(0, 32)

  override def privateKey: PrivateKey = {
    val keySpec = EdECPrivateKeySpec(NamedParameterSpec.ED25519, privateKeyData)
    keyFactory.generatePrivate(keySpec)
  }

  override def publicKey: PublicKey = {
    val ecPoint = EdECPoint(false, pub.bigInteger)
    val keySpec = EdECPublicKeySpec(NamedParameterSpec.ED25519, ecPoint)
    keyFactory.generatePublic(keySpec)
  }

  override def signature(flags: Int): (Signature, String) =
    (Signature.getInstance("Ed25519"), "ssh-ed25519")
}
