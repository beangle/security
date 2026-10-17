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

package org.beangle.security.aot

import org.beangle.commons.aot.AotPolicy
import org.beangle.security.session.{DefaultSession, Session}
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

class SecurityAotHintsTest extends AnyFunSpec, Matchers {

  describe("SecurityAotHints") {
    it("registers session models used by bean serialization") {
      val hints = new SecurityAotHints()
      hints.registering()
      val types = hints.aotHints.getTypes
      types should contain(classOf[DefaultSession])
      types should contain(classOf[Session.Agent])
      hints.aotHints.getTypePolicies(classOf[DefaultSession]) shouldBe AotPolicy.default
      hints.aotHints.getTypePolicies(classOf[Session.Agent]) shouldBe AotPolicy.default
    }
  }
}
