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
import java.security.Principal

object Session {
  val DefaultTimeOut = Duration.ofSeconds(30 * 60)

  def user: String = {
    SecurityContext.session.principal.getName
  }

  trait Client extends Serializable {
    def ip: String
  }

  class AgentClient(val agent: String, val ip: String, val os: String) extends Client

}

trait Session extends java.io.Externalizable {

  def id: String

  def principal: Principal

  def loginAt: Instant

  def lastAccessAt: Instant

  def lastAccessAt_=(newAccessed: Instant): Unit
}

trait SessionBuilder {
  def build(id: String, principal: Principal, loginAt: Instant): Session
}
