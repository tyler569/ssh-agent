package com.pygostylia.sshagent.keys

import com.pygostylia.sshagent.keys.KeySpec
import com.pygostylia.sshagent.packets.SignReqPacket
import com.pygostylia.sshagent.serialization.{SshProtocolReader, SshProtocolWriter}

import java.nio.ByteBuffer
import java.security.spec.{RSAPrivateKeySpec, RSAPublicKeySpec}
import java.security.{KeyFactory, PrivateKey, PublicKey, Signature}

class RsaKeySpec(reader: SshProtocolReader) extends KeySpec {
  private val n: BigInt = reader.readMpInt()
  private val e: BigInt = reader.readMpInt()
  private val d: BigInt = reader.readMpInt()
  private val iqmp: BigInt = reader.readMpInt()
  private val p: BigInt = reader.readMpInt()
  private val q: BigInt = reader.readMpInt()
  protected val comment: String = reader.readString()

  private val keyFactory = KeyFactory.getInstance("RSA")

  private val rsaPrivateKey = {
    val keySpec = RSAPrivateKeySpec(n.bigInteger, d.bigInteger)
    keyFactory.generatePrivate(keySpec)
  }

  private val rsaPubKey = {
    val keySpec = RSAPublicKeySpec(n.bigInteger, e.bigInteger)
    keyFactory.generatePublic(keySpec)
  }

  override def keyType: String = "ssh-rsa"

  override def toString: String = s"RsaKeySpec($e, $n)"

  // override def sign(data: Array[Byte], signatureType?): Array[Byte] // ?

  override def privateKey: PrivateKey = rsaPrivateKey

  override def publicKey: PublicKey = rsaPubKey

  override def keyBlob: ByteBuffer = {
    val blob = SshProtocolWriter()
    blob.writeString(keyType)
    blob.writeMpInt(e)
    blob.writeMpInt(n)
    blob.done()
  }

  def signature(flags: Int): (Signature, String) = {
    flags & 0x07 match {
      case SignReqPacket.SSH_AGENT_RSA_SHA2_256 => (Signature.getInstance("SHA256WithRSA"), "rsa-sha2-256")
      case SignReqPacket.SSH_AGENT_RSA_SHA2_512 => (Signature.getInstance("SHA512WithRSA"), "rsa-sha2-512")
    }
  }
}
