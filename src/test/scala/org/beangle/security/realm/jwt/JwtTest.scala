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

package org.beangle.security.realm.jwt

import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

import java.time.Duration

class JwtTest extends AnyFunSpec, Matchers {
  describe("Jwts") {
    it("generate and verify") {
      val s = "8656afd0ea2472665a6f35ceb8d164d2a27244dd"
      val data = Map("userName" -> "大学OA系统", "userCode" -> "school.vender")
      val token = Jwts.builder().claims(data).sign(s)
      val claim = Jwts.getClaims(token)
      Jwts.validateToken(s, token) should be(true)
      claim.contains("exp") should be(true)
      val exp = claim.getInt("exp", 0)
      assert(exp > 0)
    }
  }
}
