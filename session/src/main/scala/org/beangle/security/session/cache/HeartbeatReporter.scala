package org.beangle.security.session.cache

import org.beangle.cache.Cache
import org.beangle.security.session.Session
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.HashSet
import org.beangle.commons.collection.Collections
import java.util.TimerTask
import org.beangle.security.session.util.Task

/**
 * Report heartbeat every 5 min.
 */
class HeartbeatReporter(sessions: Cache[String, Session], repo: CacheSessionRepo) extends Task {

  private var lastReportAt: Instant = Instant.now

  private val sessionIds = new ConcurrentHashMap[String, Boolean]

  def addSessionId(sessionId: String): Unit = {
    sessionIds.put(sessionId, true)
  }

  def run() {
    val last = lastReportAt
    lastReportAt = Instant.now
    val expired = Collections.newBuffer[String]
    val keys = sessionIds.keys()
    while (keys.hasMoreElements) {
      val sessionId = keys.nextElement()
      sessions.get(sessionId) match {
        case Some(s) =>
          if (s.lastAccessAt.isAfter(last) && !repo.heartbeat(s))
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