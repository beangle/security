/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
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