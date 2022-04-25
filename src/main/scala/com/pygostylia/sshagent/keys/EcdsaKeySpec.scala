package com.pygostylia.sshagent.keys

import com.pygostylia.sshagent.keys.EcdsaKeySpec.curveMapping
import com.pygostylia.sshagent.serialization.{SshProtocolReader, SshProtocolWriter}

import java.nio.ByteBuffer
import java.security.{AlgorithmParameters, KeyFactory, PrivateKey, PublicKey, Signature}
import java.security.spec.{ECGenParameterSpec, ECParameterSpec, ECPoint, ECPrivateKeySpec, ECPublicKeySpec, EllipticCurve}

class EcdsaKeySpec(reader: SshProtocolReader) extends KeySpec {
  private val curveName = reader.readString()
  private val q = reader.readBytes()
  private val d = reader.readMpInt()
  protected val comment: String = reader.readString()

  override def toString: String = s"EcdsaKeySpec($curveName, $comment, $qX, $qY)"

  def keyBlob: ByteBuffer = {
    val blob = SshProtocolWriter()
    blob.writeString(keyType)
    blob.writeString(curveName)
    // blob.writeBytes(publicEcdsaKey.getEncoded) // FIXME format?
    blob.writeBytes(q)
    blob.done()
  }

  def keyType: String = s"ecdsa-sha2-$curveName"

  def privateKey: PrivateKey = privateEcdsaKey

  def publicKey: PublicKey = publicEcdsaKey

  private val qComponents = {
    if (q(0) != 4) throw new RuntimeException("Cannot handle compressed points")
    val qs = q.view.slice(1, q.length).splitAt(q.length / 2)
    qs match {
      case (x, y) => (BigInt(x.toArray), BigInt(y.toArray))
    }
  }

  private def qX = qComponents(0)

  private def qY = qComponents(1)

  private val keyFactory = KeyFactory.getInstance("EC")

  private def ecParameterSpec: ECParameterSpec = {
    val parameters = AlgorithmParameters.getInstance("EC", "SunEC")
    parameters.init(new ECGenParameterSpec(curveMapping(curveName)))
    parameters.getParameterSpec(classOf[ECParameterSpec])
  }

  private val privateEcdsaKeySpec = ECPrivateKeySpec(d.bigInteger, ecParameterSpec)

  private val privateEcdsaKey = keyFactory.generatePrivate(privateEcdsaKeySpec)

  private val publicEcdsaKey = {
    val point = ECPoint(qComponents(0).bigInteger, qComponents(1).bigInteger)
    val keySpec = ECPublicKeySpec(point, ecParameterSpec)
    keyFactory.generatePublic(keySpec)
  }

  def signature(flags: Int): (Signature, String) = {
    (curveName match {
      case "nistp256" => Signature.getInstance("SHA256withECDSA")
      case "nistp384" => Signature.getInstance("SHA384withECDSA")
      case "nistp521" => Signature.getInstance("SHA512withECDSA")
      case "1.3.132.0.1" => Signature.getInstance("SHA256withECDSA")
      case "1.2.840.10045.3.1.1" => Signature.getInstance("SHA256withECDSA")
      case "1.3.132.0.33" => Signature.getInstance("SHA256withECDSA")
      case "1.3.132.0.26" => Signature.getInstance("SHA256withECDSA")
      case "1.3.132.0.27" => Signature.getInstance("SHA256withECDSA")
      case "1.3.132.0.16" => Signature.getInstance("SHA384withECDSA")
      case "1.3.132.0.36" => Signature.getInstance("SHA512withECDSA")
      case "1.3.132.0.37" => Signature.getInstance("SHA512withECDSA")
      case "1.3.132.0.38" => Signature.getInstance("SHA512withECDSA")
    }, keyType)
  }
}

object EcdsaKeySpec {
  private val curveMapping = Map(
    "nistp256" -> "secp256r1",
    "nistp384" -> "secp384r1",
    "nistp521" -> "secp521r1",
    "1.3.132.0.1" -> "sect163k1",
    "1.2.840.10045.3.1.1" -> "secp192r1",
    "1.3.132.0.33" -> "secp224r1",
    "1.3.132.0.26" -> "sect233k1",
    "1.3.132.0.27" -> "sect233r1",
    "1.3.132.0.16" -> "sect283k1",
    "1.3.132.0.36" -> "sect409k1",
    "1.3.132.0.37" -> "sect409r1",
    "1.3.132.0.38" -> "sect571k1",
  )
}