package com.pygostylia.sshagent

import java.nio.ByteBuffer
import scala.collection.IndexedSeqView

def bufferView(buffer: ByteBuffer): IndexedSeqView[Byte] = {
  buffer.array().view.slice(buffer.position(), buffer.limit())
}