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

package org.beangle.security.session.protobuf

import java.io.{ InputStream, OutputStream }
import java.time.Instant
import org.beangle.commons.io.ObjectSerializer
import org.beangle.security.session.DefaultSession

object SessionSerializer extends ObjectSerializer {

  override def serialize(data: Any, os: OutputStream, params: Map[String, Any]): Unit = {
    val session = data.asInstanceOf[DefaultSession]
    val builder = Model.Session.newBuilder()
    builder.setId(session.id)
    builder.setPrincipal(AccountSerializer.toMessage(session.principal))
    builder.setLoginAt(session.loginAt.getEpochSecond)
    builder.setLastAccessAt(session.lastAccessAt.getEpochSecond)
    builder.setAgent(AgentSerializer.toMessage(session.agent))
    builder.setTtiSeconds(session.ttiSeconds)
    builder.build().writeTo(os)
  }

  override def deserialize(is: InputStream, params: Map[String, Any]): Any = {
    val s = Model.Session.parseFrom(is)
    val session = new DefaultSession(s.getId, AccountSerializer.fromMessage(s.getPrincipal),
      Instant.ofEpochSecond(s.getLoginAt), AgentSerializer.fromMessage(s.getAgent),s.getTtiSeconds)
    session.lastAccessAt = Instant.ofEpochSecond(s.getLastAccessAt)
    session
  }
}
