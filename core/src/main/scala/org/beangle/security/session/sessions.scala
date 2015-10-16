/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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

import java.io.{ Serializable => jSerializable }
import java.security.Principal
import java.{ util => ju }
import org.beangle.security.authc.Account
import org.beangle.security.authc.DetailNames.{ Agent, Host, Os }
import org.beangle.security.context.SecurityContext

trait SessionKey {
  def sessionId: String
}

case class SessionId(val sessionId: String) extends SessionKey

object Session {
  val DefaultTimeOut: Short = 30 * 60

  def user: String = {
    SecurityContext.session.principal.getName
  }

}

trait Session extends Serializable {

  def id: String

  def principal: Account

  def loginAt: ju.Date

  def lastAccessAt: ju.Date

  def expiredAt: ju.Date

  def expired: Boolean

  def onlineTime: Long

  def lastAccessed: String

  def os: String

  def agent: String

  def host: String

  def server: String

  /** the time in seconds that the session session may remain idle before expiring.*/
  def timeout: Short

  def stop(): Unit

  def expire(): Unit

  def access(accessAt: ju.Date, accessed: String): Unit

}

class DefaultSession(val id: String, val principal: Account, val loginAt: ju.Date, val timeout: Short, val os: String, val agent: String, val host: String)
    extends Session {
  var server: String = _
  var expiredAt: ju.Date = _
  var lastAccessAt: ju.Date = _
  var lastAccessed: String = _
  @transient
  var registry: SessionRegistry = _

  def onlineTime: Long = {
    if (null == expiredAt) System.currentTimeMillis() - loginAt.getTime()
    else expiredAt.getTime() - loginAt.getTime()
  }

  def expired: Boolean = null != expiredAt
  def stop(): Unit = registry.remove(SessionId(id))
  def expire(): Unit = {
    expiredAt = new ju.Date()
    registry.expire(this)
  }

  def access(accessAt: ju.Date, accessed: String): Unit = {
    registry.access(this, accessAt, accessed)
    lastAccessAt = accessAt
    lastAccessed = accessed
  }
}

trait SessionBuilder {
  def build(key: SessionKey, auth: Account, registry: SessionRegistry, loginAt: ju.Date, timeout: Short): Session
}

class DefaultSessionBuilder extends SessionBuilder {

  def build(key: SessionKey, auth: Account, registry: SessionRegistry, loginAt: ju.Date, timeout: Short): Session = {
    val session = new DefaultSession(key.sessionId, auth, loginAt, timeout, auth.details(Os).toString, auth.details(Agent).toString, auth.details(Host).toString)
    session.registry = registry
    session.lastAccessAt = new ju.Date()
    session
  }
}

