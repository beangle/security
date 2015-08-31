package org.beangle.security.session

import java.security.Principal
import java.{ util => ju }

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.{ Dates, Objects }
import org.beangle.commons.lang.time.Stopwatch
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.AuthenticationInfo

trait SessionRegistry {

  def register(info: AuthenticationInfo, key: SessionKey): Session

  def remove(key: SessionKey): Option[Session]

  def onExpire(session: Session): Unit

  def onAccess(session: Session, accessAt: ju.Date, accessed: String)

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

/**
 * Session Profile
 */
trait SessionProfile {
  def capacity: Int
  def maxSession: Int
  def timeout: Short
}

object DefaultSessionProfile extends DefaultSessionProfile("*") {
  this.capacity = Short.MaxValue
  this.maxSession = 2
  this.timeout = Session.DefaultTimeOut
}

class DefaultSessionProfile(val category: String) extends SessionProfile {
  var capacity: Int = _
  var maxSession: Int = _
  var timeout: Short = _

  override def toString(): String = {
    Objects.toStringBuilder(this).add("category", category)
      .add("capacity", capacity).add("maxSession", maxSession)
      .add("timeout", timeout).toString
  }
}

abstract class AbstractSessionRegistry extends SessionRegistry with Logging with EventPublisher {

  override def onExpire(session: Session): Unit = {}

  override def onAccess(session: Session, accessAt: ju.Date, accessed: String): Unit = {}

  /**
   * allocate a slot for user
   */
  def tryAllocate(key: SessionKey, auth: AuthenticationInfo): Unit = {
    val sessions = get(auth.getName, false)
    if (sessions.isEmpty) {
      if (!allocate(auth, key)) throw new OvermaxSessionException(getMaxSession(auth), auth)
    } else {
      val limit = getMaxSession(auth)
      if (sessions.size < limit || limit == -1) {
        if (!allocate(auth, key)) throw new OvermaxSessionException(getMaxSession(auth), auth)
      } // Determine least recently used session, and mark it for invalidation
      else sessions.minBy(_.loginAt).expire()
    }
  }

  def getMaxSession(auth: AuthenticationInfo): Int = {
    getProfile(auth) match {
      case Some(p) => p.maxSession
      case None => 1
    }
  }

  def getTimeout(auth: AuthenticationInfo): Short = {
    getProfile(auth) match {
      case Some(p) => p.timeout
      case None => Session.DefaultTimeOut
    }
  }
  protected def allocate(auth: AuthenticationInfo, key: SessionKey): Boolean
  /**
   * release slot for user
   */
  protected def release(session: Session)

  protected def getProfile(auth: AuthenticationInfo): Option[SessionProfile]
}



/**
 * Database session registry cleaner.
 * <ul>
 * <li>removed expired session</li>
 * <li>removed long time idle session( now - last access time>expiredTime)</li>
 * </ul>
 * <strong>Implementation note:</strong> Make sure only one instance run clean up when multiple  deployed.
 */
class SessionCleaner(val registry: SessionRegistry) extends Logging {
  /** 默认过期时间 30分钟 */
  var expiredTime = 30
  def cleanup() {
    val watch = new Stopwatch(true)
    logger.debug("clean up expired or over expired time session start ...")
    val calendar = ju.Calendar.getInstance()
    try {
      var removed = 0
      registry.getExpired(Dates.rollMinutes(calendar.getTime(), -expiredTime)) foreach { s =>
        registry.remove(SessionId(s.id)) foreach (olds => removed += 1)
      }
      if (removed > 0) logger.info(s"removed $removed expired sessions in $watch")
      registry.stat()
    } catch {
      case e: Exception => logger.error("Beangle session cleanup failure.", e)
    }
  }
}
