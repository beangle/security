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

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.Account

trait SessionRegistry {

  def register(sessionId: String, info: Account, agent: Session.Agent): Session

  def remove(sessionId: String): Option[Session]

  /**
   * Get last accessed session key before the time
   */
  def getBeforeAccessAt(accessAt: Long): Seq[String]

  def access(sessionId: String, accessAt: Long, accessed: String): Option[Session]

  def isRegisted(principal: String): Boolean

  def get(sessionId: String): Option[Session]

  def getByPrincipal(principal: String): Seq[Session]

  def stat(): Unit

  def count: Int
}

abstract class AbstractSessionRegistry extends SessionRegistry with Logging with EventPublisher {

  /**
   * allocate a slot for user
   */
  protected def tryAllocate(sessionId: String, auth: Account): Unit = {
    val limit = getMaxSession(auth)
    if (limit == -1) {
      if (!allocate(auth, sessionId)) throw new OvermaxSessionException(limit, auth)
    } else {
      val sessions = getByPrincipal(auth.getName)
      if (sessions.size < limit) {
        if (!allocate(auth, sessionId)) throw new OvermaxSessionException(limit, auth)
      } else {
        // Determine least recently used session, and stop it
        sessions.minBy(_.loginAt).stop()
      }
    }
  }

  protected def getMaxSession(auth: Account): Int

  protected def getTimeout(auth: Account): Short

  protected def allocate(auth: Account, sessionId: String): Boolean
  /**
   * release slot for user
   */
  protected def release(session: Session)
}
