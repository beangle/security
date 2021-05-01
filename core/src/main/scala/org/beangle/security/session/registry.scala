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

import java.time.Instant

import org.beangle.security.authc.Account

trait SessionRepo {
  def get(sessionId: String): Option[Session]

  def findByPrincipal(principal: String): collection.Seq[Session]

  def access(sessionId: String, accessAt: Instant): Option[Session]

  def expire(sessionId: String): Unit
}

trait SessionRegistry extends SessionRepo {

  def register(sessionId: String, info: Account, client: Session.Agent, profile: SessionProfile): Session

  def remove(sessionId: String, reason: String): Option[Session]

  def findExpired(): collection.Seq[String]
}

trait SessionProfileProvider {
  def getProfile(account: Account): SessionProfile
}
