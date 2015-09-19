package org.beangle.security.realm.ldap

import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.scalatest.{ FunSpec, Matchers }
import org.scalatest.junit.JUnitRunner

/**
 * @author chaostone
 */
@RunWith(classOf[JUnitRunner])
class LdapPasswordHandlerTest extends FunSpec with Matchers with Logging {

  describe("LdapPasswordHandler generateDigest and verfity") {
    println(LdapPasswordHandler.generateDigest("1", null, "sha"))
    println(LdapPasswordHandler.verify("{SHA}NWoZK3kTsExUV00Ywo1G5jlUKKs=", "2"))
  }
}