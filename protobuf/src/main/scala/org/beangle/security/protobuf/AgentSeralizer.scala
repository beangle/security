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
package org.beangle.security.protobuf

import java.io.{ InputStream, OutputStream }

import org.beangle.commons.io.ObjectSerializer
import org.beangle.security.session.Session

object AgentSerializer extends ObjectSerializer {

  def toMessage(agent: Session.Agent): Model.Agent = {
    val builder = Model.Agent.newBuilder()
    builder.setName(agent.name)
    builder.setIp(agent.ip)
    builder.setOs(agent.os)
    builder.build()
  }

  def fromMessage(a: Model.Agent): Session.Agent = {
    new Session.Agent(a.getName(), a.getIp(), a.getOs)
  }

  override def serialize(data: Any, os: OutputStream, params: Map[String, Any]): Unit = {
    toMessage(data.asInstanceOf[Session.Agent]).writeTo(os)
  }

  override def deserialize(is: InputStream, params: Map[String, Any]): Any = {
    fromMessage(Model.Agent.parseFrom(is))
  }
}
