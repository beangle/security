package org.beangle.security.session

import java.util.Date
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.AuthenticationInfo
import java.io.{ Serializable => jSerializable }
import java.security.Principal
import org.beangle.commons.event.EventPublisher

trait SessionKey {
  def sessionId: jSerializable
}

case class SessionId(val sessionId: jSerializable) extends SessionKey

trait Session {

  def id: jSerializable

  def principal: Principal

  def loginAt: Date

  def lastAccessAt: Date

  def expiredAt: Date

  def expired: Boolean

  def onlineTime: Long

  def lastAccessed: jSerializable

  def remark: String

  def os: String

  def agent: String

  def host: String

  def server: String

  /** the time in seconds that the session session may remain idle before expiring.*/
  def timeout: Int

  def stop(): Unit

  def expire(): Unit

  def access(accessAt: Long, accessed: String): Unit

  def remark(added: String): Unit

}
class DefaultSession(val id: jSerializable, val principal: Principal, val loginAt: Date, val os: String, val agent: String, val host: String) extends Session {
  var server: String = _
  var expiredAt: Date = _
  var remark: String = _
  var timeout: Int = 30 * 60 //default 30 minutes
  var registry: SessionRegistry = _
  var lastAccessAt: Date = _
  var lastAccessed: jSerializable = _

  def onlineTime: Long = {
    if (null == expiredAt) System.currentTimeMillis() - loginAt.getTime()
    else expiredAt.getTime() - loginAt.getTime()
  }
  def expired: Boolean = null != expiredAt
  def stop(): Unit = registry.remove(SessionId(id))
  def expire(): Unit = expiredAt = new Date()
  def access(accessAt: Long, accessed: String): Unit = registry.access(SessionId(id), accessAt, accessed)
  def remark(added: String): Unit = if (null == remark) remark = added else remark = remark + added
}
/**
 * registry aware session
 */
trait RegistrySession extends Session {
  def registry: SessionRegistry
  override def stop() = registry.remove(SessionId(id))
  override def expire() = registry.expire(SessionId(id))
  override def access(accessAt: Long, accessed: String): Unit = registry.access(SessionId(id), accessAt, accessed)
}

trait SessionBuilder {
  def build(auth: AuthenticationInfo, key: SessionKey): Session
}

class DefaultSessionBuilder extends SessionBuilder {
  import org.beangle.security.authc.DetailNames._
  def build(auth: AuthenticationInfo, key: SessionKey): Session = {
    val session = new DefaultSession(key.sessionId, auth, new Date(), auth.details(Os).toString, auth.details(Agent).toString, auth.details(Host).toString)
    auth.details.get(Timeout) foreach { timeout => session.timeout = timeout.asInstanceOf }
    session
  }
}

trait SessionRegistry {

  def register(info: AuthenticationInfo, key: SessionKey): Session

  def remove(key: SessionKey): Option[Session]

  def expire(key: SessionKey): Boolean

  def access(key: SessionKey, accessAt: Long, accessed: String)

  def get(principal: String, includeExpiredSessions: Boolean): List[Session]

  def get(key: SessionKey): Option[Session]

  def getStatus(key: SessionKey): Option[SessionStatus]

  def isRegisted(principal: String): Boolean

  def count: Int
}

trait SessionController {

  def onRegister(auth: AuthenticationInfo, key: SessionKey, registry: SessionRegistry): Boolean

  def onLogout(info: Session)

  def stat()

  def getMaxSessions(auth: AuthenticationInfo): Int

  def getInactiveInterval(auth: AuthenticationInfo): Option[Short]
}

@SerialVersionUID(-1110252524091983477L)
class SessionStatus(val principal: Principal, var lastAccessAt: Long, var acessed: jSerializable) extends jSerializable() {

  def this(info: Session) {
    this(info.principal, info.lastAccessAt.getTime(), info.lastAccessed)
  }
}

trait SessionStatusCache {

  def get(sessionId: jSerializable): SessionStatus

  def put(sessionId: jSerializable, newstatus: SessionStatus)

  def evict(sessionId: jSerializable)

  def ids: Set[jSerializable]
}

class MemSessionRegistry extends SessionRegistry with Initializing with Logging with EventPublisher {

  var controller: SessionController = _

  var builder: SessionBuilder = _

  protected var principals = new collection.concurrent.TrieMap[Any, collection.mutable.HashSet[jSerializable]]

  protected var sessionids = new collection.concurrent.TrieMap[jSerializable, Session]

  def init() {
    require(null != controller)
    require(null != builder)
  }

  def isRegisted(principal: String): Boolean = {
    val sids = principals.get(principal)
    (!sids.isEmpty && !sids.get.isEmpty)
  }

  override def get(principal: String, includeExpired: Boolean): List[Session] = {
    principals.get(principal) match {
      case None => List.empty
      case Some(sids) => {
        val list = new collection.mutable.ListBuffer[Session]
        for (sessionid <- sids)
          get(SessionId(sessionid)).foreach(info => if (includeExpired || !info.expired) list += info)
        list.toList
      }
    }
  }

  override def get(key: SessionKey): Option[Session] = sessionids.get(key.sessionId)

  override def register(auth: AuthenticationInfo, key: SessionKey): Session = {
    val principal = auth.getName
    val existed = get(key) match {
      case Some(existed) => {
        if (existed.principal.getName() != principal) {
          if (!controller.onRegister(auth, key, this)) throw new SessionException("security.OvermaxSession", auth)
          existed.remark(" expired with replacement.")
          remove(key)
        }
      }
      case None => if (!controller.onRegister(auth, key, this)) throw new SessionException("security.OvermaxSession", auth)
    }

    val newSession = builder.build(auth, key)
    sessionids.put(key.sessionId, newSession)
    principals.get(principal) match {
      case None => principals.put(principal, new collection.mutable.HashSet += key.sessionId)
      case Some(sids) => sids += key.sessionId
    }
    publish(new LoginEvent(newSession))
    newSession
  }

  override def remove(key: SessionKey): Option[Session] = {
    get(key) match {
      case Some(s) => {
        sessionids.remove(key.sessionId)
        val principal = s.principal
        debug("Remove session " + key + " for " + principal)
        val sids = principals.get(principal) foreach { sids =>
          sids.remove(key.sessionId)
          if (sids.isEmpty) {
            principals.remove(principal)
            debug("Remove principal " + principal + " from registry")
          }
        }
        controller.onLogout(s)
        publish(new LogoutEvent(s))
        Some(s)
      }
      case None => None
    }
  }

  override def expire(key: SessionKey): Boolean = {
    get(key).foreach(info => info.expire())
    true
  }

  def getStatus(key: SessionKey): Option[SessionStatus] = {
    get(key) match {
      case None => None
      case Some(info) => Some(new SessionStatus(info))
    }
  }

  def count(): Int = sessionids.size

  def access(key: SessionKey, accessAt: Long, accessed: String) {
    get(key) match {
      case None => None
      case Some(info) => info.access(accessAt, accessed)
    }
  }
}
