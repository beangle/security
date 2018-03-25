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

import java.security.Principal
import java.time.{ Duration, Instant }

import org.beangle.security.context.SecurityContext

object Session {
  val DefaultTimeOut = Duration.ofSeconds(30 * 60)

  class Agent(val name: String, val ip: String, val os: String) extends Serializable
}

trait Session extends java.io.Externalizable {

  def id: String

  def principal: Principal

  def loginAt: Instant

  def agent: Session.Agent

  def lastAccessAt: Instant

  def lastAccessAt_=(newAccessed: Instant): Unit
}

trait SessionBuilder {
  def build(id: String, principal: Principal, loginAt: Instant, agent: Session.Agent): Session
}
