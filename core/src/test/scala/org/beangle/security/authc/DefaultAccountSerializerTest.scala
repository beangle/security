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

import java.io.{ByteArrayInputStream, ByteArrayOutputStream, ObjectInputStream, ObjectOutputStream}

import org.beangle.commons.logging.Logging
import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.funspec.AnyFunSpec
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class DefaultAccountSerializerTest extends AnyFunSpec with Matchers with Logging {

  describe("DefaultAccount default serializer") {
    it(" read and write") {
      val account = new DefaultAccount("root", "超级管理员")
      account.remoteToken = None
      account.status = 1
      account.permissions = null
      account.authorities = Array("superman", "wheel")
      account.categoryId = 1
      account.details = Map("client" -> "firefox", "os" -> "linux")

      val os = new ByteArrayOutputStream()
      val oos = new ObjectOutputStream(os)
      account.writeExternal(oos)

      val bytes = os.toByteArray

      val is = new ByteArrayInputStream(bytes)
      val ois = new ObjectInputStream(is)
      val restored = new DefaultAccount
      restored.readExternal(ois)

      restored.authorities should be (account.authorities)
    }
  }

}