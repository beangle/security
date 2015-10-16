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
package org.beangle.security.realm.cas

import java.io.File
import org.beangle.commons.io.Files
import org.junit.runner.RunWith
import org.scalatest.{ FunSpec, Matchers }
import org.scalatest.junit.JUnitRunner
import org.beangle.commons.lang.ClassLoaders

@RunWith(classOf[JUnitRunner])
class Cas20TicketValidatorTest extends FunSpec with Matchers {
  val validator = new Cas20TicketValidator
  describe("NeusoftCasTicketValidator") {
    it("should parse success") {
      val file = new File(ClassLoaders.getResource("auth-success.xml").getFile())
      val response = Files.readString(file)
      val assertion = validator.parseResponse("testticket", response)
      assert(null != assertion)
      assert(assertion.principal == "admin")
    }

    it("should raise exception when failure") {
      val file = new File(ClassLoaders.getResource("auth-failure.xml").getFile())
      val response = Files.readString(file)
      intercept[TicketValidationException] {
        validator.parseResponse("ticket", response)
      }
    }
  }
}