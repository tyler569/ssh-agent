package com.pygostylia.sshagent.serialization

import java.nio.ByteBuffer

class SshProtocolWriter(buffer: ByteBuffer) {
  var isDone = false

  def this() = this(ByteBuffer.allocate(4096))

  def writeBytes(bytes: Array[Byte]): Unit = {
    buffer.putInt(bytes.length)
    buffer.put(bytes)
  }

  def writeBytes(bytes: ByteBuffer): Unit = {
    buffer.putInt(bytes.limit())
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

  def writeBytesRaw(bytes: Array[Byte]): Unit = buffer.put(bytes)

  def writeInt(v: Int): Unit = buffer.putInt(v)

  def done(): ByteBuffer = {
    if (isDone) throw RuntimeException("Cannot done() a completed writer")
    buffer.flip()
    isDone = true
    buffer
  }

  def array(): Array[Byte] = {
    if (isDone)
      buffer.array.slice(0, buffer.limit())
    else
      buffer.array.slice(0, buffer.position())
  }
}

object SshProtocolWriter {
  def withCapacity(capacity: Int): SshProtocolWriter = SshProtocolWriter(ByteBuffer.allocate(capacity))
}
