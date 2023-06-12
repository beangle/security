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

package org.beangle.security.realm.ltpa

import org.beangle.commons.logging.Logging
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers

class LtpaTokenTest extends AnyFunSpec with Matchers with Logging {

  describe("LtpaTokenGenerator") {
    val tokenString = "AAECAzY0ODU1QTlBNjQ4NjAzNUFDTj0wMDA3MDEsZGVwYXJ0PUlUyPGAE8ptQyih9snR63ep19QkNO0="
    val generator = LtpaTokenGenerator("Zc0Ul5jg1Bt9ZiBkfLqEO3MtsTc=", Array("CN"))
    //解析
    val token = generator.parse(tokenString)
    assert("000701" == token.username)
  }

}
