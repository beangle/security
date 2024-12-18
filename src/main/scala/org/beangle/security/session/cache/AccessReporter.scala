/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.session.cache

import org.beangle.commons.cache.Cache
import org.beangle.commons.collection.Collections
import org.beangle.security.session.Session

import java.time.Instant
import java.util.concurrent.ConcurrentHashMap

/**
  * Report heartbeat.
  */
class AccessReporter(sessions: Cache[String, Session], repo: CacheSessionRepo) extends Runnable {

  private var lastReportAt: Instant = Instant.now

  private val sessionIds = new ConcurrentHashMap[String, Instant]

  def addSessionId(sessionId: String, accessAt: Instant): Unit = {
    sessionIds.put(sessionId, accessAt)
  }

  override def run(): Unit = {
    val last = lastReportAt
    lastReportAt = Instant.now
    val expired = Collections.newBuffer[String]
    val keys = sessionIds.keys()
    while (keys.hasMoreElements) {
      val sessionId = keys.nextElement()
      sessions.get(sessionId) match {
        case Some(s) =>
          if (s.lastAccessAt.isAfter(last) && !repo.flush(s))
            expired += sessionId
        case None => expired += sessionId
      }
    }
    expired foreach { e =>
      sessionIds.remove(e)
      sessions.evict(e)
    }
  }
}
