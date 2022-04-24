package com.pygostylia.sshagent.serialization

import java.nio.ByteBuffer

class SshProtocolReader(buffer: ByteBuffer) {
  def this(data: Array[Byte]) = this(ByteBuffer.wrap(data))

  def readInt(): Int = buffer.getInt()

  def readNBytes(n: Int): Array[Byte] = {
    val data = new Array[Byte](n)
    buffer.get(data)
    data
  }

  def readBytes(): Array[Byte] = {
    val len = buffer.getInt()
    readNBytes(len)
  }

  def readString(): String = {
    val len = buffer.getInt()
    String(readNBytes(len))
  }

  def readMpInt(): BigInt = {
    val len = buffer.getInt()
    BigInt(readNBytes(len))
  }
}
