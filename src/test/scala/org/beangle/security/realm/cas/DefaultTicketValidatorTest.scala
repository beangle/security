/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.realm.cas

import org.beangle.commons.io.Files
import org.beangle.commons.lang.ClassLoaders
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

import java.io.File

class DefaultTicketValidatorTest extends AnyFunSpec, Matchers {
  val validator = new DefaultTicketValidator
  describe("DefaultTicketValidator") {
    it("should parse sso success") {
      val file = new File(ClassLoaders.getResource("auth-success.xml").get.getFile)
      val response = Files.readString(file)
      val rs = DefaultTicketValidator.parse(response)
      assert(null != rs)
      assert(rs.user.contains("admin"))
      assert(rs.attributes.size == 8)
    }

    it("should parse cas success") {
      val file = new File(ClassLoaders.getResource("auth-success2.xml").get.getFile)
      val response = Files.readString(file)
      val rs = DefaultTicketValidator.parse(response)
      assert(null != rs)
      assert(rs.user.contains("admin"))
      assert(rs.attributes.size == 6)
    }

    it("should catch error code when failure") {
      val file = new File(ClassLoaders.getResource("auth-failure.xml").get.getFile)
      val response = Files.readString(file)
      val rs = DefaultTicketValidator.parse(response)
      assert(!rs.validated)
      assert(rs.code == "INVALID_TICKET")
      assert(rs.message == "ticket 'ST_portal1_-458698-1IBoJaTT8rVVf99hhy' not recognized")
    }

    it("should parse error text") {
      val txt = "any error response"
      val response = DefaultTicketValidator.parse(txt)
      assert(txt == response.message)
      assert(response.user.isEmpty)
    }

    it("should parse error xml") {
      val txt = "<a href='1'>anchor</a>"
      val response = DefaultTicketValidator.parse(txt)
      assert("Invalid Cas response xml." == response.message)
      assert(response.user.isEmpty)
    }
  }
}
