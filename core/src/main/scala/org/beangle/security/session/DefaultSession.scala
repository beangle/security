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
package org.beangle.security.session

import java.time.{ Duration, Instant }

import org.beangle.security.authc.Account
import org.beangle.security.context.SecurityContext
import java.io.ObjectInput
import java.io.ObjectOutput
import org.beangle.security.authc.DefaultAccount
import java.security.Principal

object DefaultSessionBuilder extends SessionBuilder {
  def build(id: String, principal: Principal, loginAt: Instant): Session = {
    new DefaultSession(id, principal.asInstanceOf[DefaultAccount], loginAt)
  }
}

class DefaultSession extends Session {
  var id: String = _
  var principal: DefaultAccount = _
  var loginAt: Instant = _
  var lastAccessAt: Instant = _

  def this(id: String, principal: DefaultAccount, loginAt: Instant) {
    this()
    this.id = id
    this.principal = principal
    this.loginAt = loginAt
    this.lastAccessAt = loginAt
  }

  def writeExternal(out: ObjectOutput) {
    out.writeObject(id)
    principal.writeExternal(out)
    out.writeLong(loginAt.getEpochSecond)
    out.writeLong(lastAccessAt.getEpochSecond)
  }

  def readExternal(in: ObjectInput) {
    id = in.readObject.asInstanceOf[String]
    principal = new DefaultAccount()
    principal.readExternal(in)
    loginAt = Instant.ofEpochSecond(in.readLong)
    lastAccessAt = Instant.ofEpochSecond(in.readLong)
  }
}
