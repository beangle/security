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
package org.beangle.security.authc

import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.scalatest.matchers.should.Matchers
import org.scalatest.funspec.AnyFunSpec
import org.scalatestplus.junit.JUnitRunner

/**
  * @author chaostone
  */
@RunWith(classOf[JUnitRunner])
class DefaultPasswordStrengthCheckerTest extends AnyFunSpec with Matchers with Logging {

  import PasswordStrengths._
  describe("DefaultPasswordStrengthChecker check password") {
    it("check week") {
      val checker = new DefaultPasswordStrengthChecker(8)
      var rs = checker.check("1234567")
      rs should be(PasswordStrengths.VeryWeak)

      checker.check("12345678") should be( Weak)

      checker.check("1234567A8") should be(Medium)

      checker.check("1234a567A8") should be(Strong)


    }
  }
}
