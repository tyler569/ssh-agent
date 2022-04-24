package com.pygostylia.sshagent.serialization

import java.nio.ByteBuffer

class SshProtocolWriter(buffer: ByteBuffer) {
  def this() = this(ByteBuffer.allocate(4096))

  def writeBytes(bytes: Array[Byte]): Unit = {
    buffer.putInt(bytes.length)
    buffer.put(bytes)
  }

  def writeString(str: String): Unit = {
    buffer.putInt(str.length)
    buffer.put(str.getBytes)
  }

  def writeMpInt(i: BigInt): Unit = {
    val bytes = i.toByteArray
    buffer.putInt(bytes.length)
    buffer.put(bytes)
  }

  def write(v: Byte): Unit = buffer.put(v)

  def writeInt(v: Int): Unit = buffer.putInt(v)

  def array(): Array[Byte] = buffer.array().slice(0, buffer.position())
}
