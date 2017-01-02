/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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
package org.beangle.security.codec

import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.scalatest.{ FunSpec, Matchers }
import org.scalatest.junit.JUnitRunner

/**
 * @author chaostone
 */
@RunWith(classOf[JUnitRunner])
class DefaultPasswordEncoderTest extends FunSpec with Matchers with Logging {

  describe("DefaultPasswordEncoder generate and verfity") {
    println(DefaultPasswordEncoder.generate("1", null, "sha"))
    println(DefaultPasswordEncoder.verify("{SHA}NWoZK3kTsExUV00Ywo1G5jlUKKs=", "2"))
  }
}