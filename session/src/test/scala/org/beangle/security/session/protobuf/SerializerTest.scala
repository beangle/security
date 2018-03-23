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
package org.beangle.security.session.protobuf

import org.beangle.commons.logging.Logging
import org.beangle.security.authc.DefaultAccount
import org.beangle.security.session.DefaultSession
import org.beangle.serializer.protobuf.ProtobufSerializer
import org.junit.runner.RunWith
import org.scalatest.{ FunSpec, Matchers }
import org.scalatest.junit.JUnitRunner
import java.time.Instant
import org.beangle.security.session.Session
import org.beangle.security.session.protobuf.AccountSerializer
import org.beangle.security.session.protobuf.SessionSerializer
import org.beangle.security.session.protobuf.AgentSerializer

@RunWith(classOf[JUnitRunner])
class SerializerTest extends FunSpec with Matchers with Logging {
  describe("erializer") {
    it("serializing") {
      val account = new DefaultAccount("0001", "root")
      account.remoteToken = Some("OTHER_token")
      account.authorities = "12,3,4"
      account.details = Map("category" -> "1")

      val serializer = new ProtobufSerializer()
      serializer.register(classOf[DefaultAccount], AccountSerializer)
      serializer.register(classOf[DefaultSession], SessionSerializer)
      serializer.register(classOf[Session.Agent], AgentSerializer)

      val data = serializer.asBytes(account)
      println("Account data has " + data.length + " bytes using protobuf serializer.")
      val newAccount = serializer.asObject(classOf[DefaultAccount], data)
      assert(newAccount.remoteToken == Some("OTHER_token"))

      val agent = new Session.Agent("Firefox", "localhost", "Fedora Linux 27")
      val session = new DefaultSession("CAS_xxasdfafd", account, Instant.now, agent)
      val sessionBytes = serializer.asBytes(session)
      val newSession = serializer.asObject(classOf[DefaultSession], sessionBytes)
      assert(newSession.id == "CAS_xxasdfafd")
    }
  }
}
