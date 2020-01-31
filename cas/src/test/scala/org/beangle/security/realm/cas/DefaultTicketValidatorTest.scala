/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.realm.cas

import java.io.File
import org.beangle.commons.io.Files
import org.junit.runner.RunWith
import org.scalatest.matchers.should.Matchers
import org.scalatest.funspec.AnyFunSpec
import org.scalatestplus.junit.JUnitRunner
import org.beangle.commons.lang.ClassLoaders

@RunWith(classOf[JUnitRunner])
class Cas20TicketValidatorTest extends AnyFunSpec with Matchers {
  val validator = new DefaultTicketValidator
  describe("DefaultCasTicketValidator") {
    it("should parse success") {
      val file = new File(ClassLoaders.getResource("auth-success.xml").get.getFile())
      val response = Files.readString(file)
      val assertion = validator.parseResponse("testticket", response)
      assert(null != assertion)
      assert(assertion == "admin")
    }

    it("should raise exception when failure") {
      val file = new File(ClassLoaders.getResource("auth-failure.xml").get.getFile())
      val response = Files.readString(file)
      intercept[TicketValidationException] {
        validator.parseResponse("ticket", response)
      }
    }
  }
}
