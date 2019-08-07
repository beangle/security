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
package org.beangle.security.session

import java.io.{ObjectInput, ObjectOutput}
import java.security.Principal
import java.time.Instant

import org.beangle.security.authc.DefaultAccount

object DefaultSessionBuilder extends SessionBuilder {
  def build(id: String, principal: Principal, loginAt: Instant, agent: Session.Agent): Session = {
    new DefaultSession(id, principal.asInstanceOf[DefaultAccount], loginAt, agent)
  }
}

class DefaultSession extends Session {
  var id: String = _
  var principal: DefaultAccount = _
  var loginAt: Instant = _
  var lastAccessAt: Instant = _
  var agent: Session.Agent = _

  def this(id: String, principal: DefaultAccount, loginAt: Instant, agent: Session.Agent) {
    this()
    this.id = id
    this.principal = principal
    this.loginAt = loginAt
    this.lastAccessAt = loginAt
    this.agent = agent
  }

  def writeExternal(out: ObjectOutput): Unit = {
    out.writeObject(id)
    principal.writeExternal(out)
    out.writeLong(loginAt.getEpochSecond)
    out.writeLong(lastAccessAt.getEpochSecond)
    out.writeObject(agent.name)
    out.writeObject(agent.ip)
    out.writeObject(agent.os)
  }

  def readExternal(in: ObjectInput): Unit = {
    id = readString(in)
    principal = new DefaultAccount()
    principal.readExternal(in)
    loginAt = Instant.ofEpochSecond(in.readLong)
    lastAccessAt = Instant.ofEpochSecond(in.readLong)
    agent = new Session.Agent(readString(in), readString(in), readString(in))
  }

  @inline
  private def readString(in: ObjectInput): String = {
    in.readObject.asInstanceOf[String]
  }
}
