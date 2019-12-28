package org.beangle.security.authc

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.funspec.AnyFunSpec
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class DefaultAccountSerializerTest extends AnyFunSpec with Matchers with Logging {

  describe("DefaultAccount default serializer") {
    it(" read and write") {
      val account = new DefaultAccount("root", "超级管理员")
      account.remoteToken = None
      account.status = 1
      account.permissions = null
      account.authorities = Array("superman", "wheel")
      account.categoryId = 1
      account.details = Map("client" -> "firefox", "os" -> "linux")

      val os = new ByteArrayOutputStream()
      val oos = new ObjectOutputStream(os)
      account.writeExternal(oos)

      val bytes = os.toByteArray

      val is = new ByteArrayInputStream(bytes)
      val ois = new ObjectInputStream(is)
      val restored = new DefaultAccount
      restored.readExternal(ois)

      restored.authorities should be (account.authorities)
    }
  }

}
