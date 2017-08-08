package org.beangle.security.session.cache

import org.beangle.security.session.SessionRepo
import org.beangle.cache.CacheManager
import org.beangle.security.session.Session
import java.time.Instant
import org.beangle.security.session.util.UpdateDelayGenerator
import java.sql.Timestamp
import org.beangle.security.session.util.SessionDaemon
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging

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