package org.beangle.security.realm.cas.vendor

import java.io.File
import org.beangle.commons.io.Files
import org.beangle.security.realm.cas.TicketValidationException
import org.junit.runner.RunWith
import org.scalatest.{FunSpec, Matchers}
import org.scalatest.junit.JUnitRunner
import org.beangle.commons.lang.ClassLoaders

@RunWith(classOf[JUnitRunner])
class NeusoftCasTicketValidatorTest extends FunSpec with Matchers {
  val validator = new NeusoftCasTicketValidator
  describe("NeusoftCasTicketValidator") {
    it("should parse success") {
      val file = new File(ClassLoaders.getResource("neusoft-auth-success.xml").getFile())
      val response = Files.readString(file)
      val assertion = validator.parseResponse("testticket", response)
      assert(null != assertion)
      assert(assertion.principal == "admin")
    }

    it("should raise exception when failure") {
      val file = new File(ClassLoaders.getResource("neusoft-auth-failure.xml").getFile())
      val response = Files.readString(file)
      intercept[TicketValidationException] {
        validator.parseResponse("ticket", response)
      }
    }
  }
}