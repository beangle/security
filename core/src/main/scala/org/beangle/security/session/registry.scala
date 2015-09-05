package org.beangle.security.session

import java.{ util => ju }

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.Account

trait SessionRegistry {

  def register(info: Account, key: SessionKey): Session

  def remove(key: SessionKey): Option[Session]

  def expire(session: Session): Unit

  def access(session: Session, accessAt: ju.Date, accessed: String)

  def isRegisted(principal: String): Boolean

  def get(key: SessionKey): Option[Session]

  def get(principal: String, includeExpiredSessions: Boolean): Seq[Session]
  /**
   * Get Expired and last accessed before the time
   */
  def getExpired(lastAccessAt: ju.Date): Seq[Session]

  def stat(): Unit

  def count: Int
}

abstract class AbstractSessionRegistry extends SessionRegistry with Logging with EventPublisher {

  override def expire(session: Session): Unit = {}

  override def access(session: Session, accessAt: ju.Date, accessed: String): Unit = {}

  /**
   * allocate a slot for user
   */
  protected def tryAllocate(key: SessionKey, auth: Account): Unit = {
    val sessions = get(auth.getName, false)
    val limit = getMaxSession(auth)
    if (sessions.isEmpty) {
      if (!allocate(auth, key)) throw new OvermaxSessionException(limit, auth)
    } else {
      if (sessions.size < limit || limit == -1) {
        if (!allocate(auth, key)) throw new OvermaxSessionException(limit, auth)
      } // Determine least recently used session, and mark it for invalidation
      else sessions.minBy(_.loginAt).expire()
    }
  }

  protected def getMaxSession(auth: Account): Int

  protected def getTimeout(auth: Account): Short

  protected def allocate(auth: Account, key: SessionKey): Boolean
  /**
   * release slot for user
   */
  protected def release(session: Session)
}
