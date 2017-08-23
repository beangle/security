package org.beangle.security.protobuf

import org.beangle.commons.logging.Logging
import org.beangle.security.authc.DefaultAccount
import org.beangle.security.session.DefaultSession
import org.beangle.serializer.protobuf.ProtobufSerializer
import org.junit.runner.RunWith
import org.scalatest.{ FunSpec, Matchers }
import org.scalatest.junit.JUnitRunner
import java.time.Instant

@RunWith(classOf[JUnitRunner])
class SerializerTest extends FunSpec with Matchers with Logging {
  describe("erializer") {
    it("serializing") {
      val account = new DefaultAccount("0001", "root")
      account.remoteToken = Some("OTHER_token")
      account.authorities = "12,3,4"
      account.details = Map("category" -> "1")

      val serializer = new ProtobufSerializer()
      serializer.register(classOf[DefaultAccount], AccountSerializer)
      serializer.register(classOf[DefaultSession], SessionSerializer)

      val data = serializer.asBytes(account)
      println("Account data has " + data.length + " bytes using protobuf serializer.")
      val newAccount = serializer.asObject(classOf[DefaultAccount], data)
      assert(newAccount.remoteToken == Some("OTHER_token"))

      val session = new DefaultSession("CAS_xxasdfafd", account, Instant.now)
      val sessionBytes = serializer.asBytes(session)
      val newSession = serializer.asObject(classOf[DefaultSession], sessionBytes)
      assert(newSession.id == "CAS_xxasdfafd")
    }
  }
}
