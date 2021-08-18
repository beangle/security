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

package org.beangle.security.authc

import org.beangle.commons.logging.Logging
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

/**
  * @author chaostone
  */
class PasswordStrengthCheckerTest extends AnyFunSpec with Matchers with Logging {

  describe("DefaultPasswordStrengthChecker check password") {
    it("check week") {
      val checker = PasswordStrengthChecker
      import PasswordPolicy._
      checker.check("1234567", Weak) should be(true)
      checker.check("12345678", Weak) should be(true)
      checker.check("1234567A8", Medium) should be(true)
      checker.check("1234a567A8", Strong) should be(true)
    }
  }
}
