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
package org.beangle.security.session.cache

import java.time.Instant

import org.beangle.cache.CacheManager
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.security.session.{ Session, SessionRepo }
import org.beangle.security.session.util.{ SessionDaemon, UpdateDelayGenerator }

abstract class CacheSessionRepo(val cacheManager: CacheManager)
    extends SessionRepo with Initializing with Logging {

  private val sessions = cacheManager.getCache("sessions", classOf[String], classOf[Session])

  private val accessDelaySeconds = new UpdateDelayGenerator(60, 120).generateDelaySeconds()

  protected val heartbeatReporter = new HeartbeatReporter(sessions, this)

  /**
   * interval (5 min) report heartbeat.
   */
  var heartbeatIntervalMillis = 5 * 60 * 1000

  override def init() {
    SessionDaemon.start(heartbeatIntervalMillis, this.heartbeatReporter)
  }

  override def get(sessionId: String): Option[Session] = {
    if (null == sessionId) return None
    val data = sessions.get(sessionId)
    if (data.isEmpty) {
      val newData = getInternal(sessionId)
      if (!newData.isEmpty) sessions.putIfAbsent(sessionId, newData.get)
      newData
    } else {
      data
    }
  }

  override def access(sessionId: String, accessAt: Instant): Option[Session] = {
    val a = get(sessionId)
    a foreach { s =>
      if ((accessAt.getEpochSecond - s.lastAccessAt.getEpochSecond) > accessDelaySeconds) {
        s.lastAccessAt = accessAt
        heartbeatReporter.addSessionId(s.id)
      }
    }
    a
  }

  protected def put(session: Session): Unit = {
    sessions.putIfAbsent(session.id, session)
  }

  protected def evict(session: Session): Unit = {
    sessions.evict(session.id)
  }

  protected def getInternal(sessionId: String): Option[Session]

  def heartbeat(session: Session): Boolean

}
