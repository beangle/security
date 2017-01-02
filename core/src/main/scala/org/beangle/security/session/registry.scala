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

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.Account

trait SessionRegistry {

  def register(sessionId: String, info: Account, client: Session.Client): Session

  def remove(sessionId: String): Option[Session]

  def access(sessionId: String, accessAt: Long, accessed: String): Option[Session]

  def get(sessionId: String): Option[Session]

}

trait LimitedSessionRegistry extends SessionRegistry {

  protected def getMaxSession(auth: Account): Int

  protected def getTimeout(auth: Account): Short

  protected def allocate(auth: Account, sessionId: String): Boolean
  /**
   * release slot for user
   */
  protected def release(session: Session)

  def getByPrincipal(principal: String): Seq[Session]
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

}