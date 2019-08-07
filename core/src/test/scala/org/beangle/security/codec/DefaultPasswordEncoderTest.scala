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
package org.beangle.security.codec

import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.funspec.AnyFunSpec
import org.scalatestplus.junit.JUnitRunner

/**
 * @author chaostone
 */
@RunWith(classOf[JUnitRunner])
class DefaultPasswordEncoderTest extends AnyFunSpec with Matchers with Logging {

  describe("DefaultPasswordEncoder generate and verfity") {
    it("generate sha") {
      val hash = "{SHA}NWoZK3kTsExUV00Ywo1G5jlUKKs="
      DefaultPasswordEncoder.generate("1", null, "sha") should be equals hash
      DefaultPasswordEncoder.verify(hash, "2") should be(false)
    }
    it("generate md5") {
      val hash = "{MD5}c4ca4238a0b923820dcc509a6f75849b"
      DefaultPasswordEncoder.generate("1", null, "md5") should be equals hash
      DefaultPasswordEncoder.verify("{MD5}c4ca4238a0b923820dcc509a6f75849b", "1") should be(true)
    }
  }
}
