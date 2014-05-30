package org.beangle.security.session

import java.util.Date
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.AuthenticationInfo
import java.io.{ Serializable => jSerializable }
import java.security.Principal

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

  /** the time in milliseconds that the session session may remain idle before expiring.*/
  def timeout: Long

  def stop(): Unit

  def expire(): Unit

  def access(accessAt: Long, accessed: String)

  def remark(added: String): Session

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

  def getSessionType(): Class[_ <: Session]

  def build(auth: AuthenticationInfo, key: SessionKey): Session
}

trait SessionRegistry {

  def register(authentication: AuthenticationInfo, key: SessionKey)

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

class MemSessionRegistry extends SessionRegistry with Initializing with Logging {

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

  def get(key: SessionKey): Option[Session] = sessionids.get(key.sessionId)

  def register(auth: AuthenticationInfo, key: SessionKey) {
    val principal = auth.getName
    val existed = get(key) match {
      case Some(existed) => {
        if (existed.principal.getName() != principal) {
          if (!controller.onRegister(auth, key, this)) throw new SessionException("security.OvermaxSession")
          existed.remark(" expired with replacement.")
          remove(key)
        }
      }
      case None => if (!controller.onRegister(auth, key, this)) throw new SessionException("security.OvermaxSession")
    }

    sessionids.put(key.sessionId, builder.build(auth, key))
    principals.get(principal) match {
      case None => principals.put(principal, new collection.mutable.HashSet += key.sessionId)
      case Some(sids) => sids += key.sessionId
    }
  }

  override def remove(key: SessionKey): Option[Session] = {
    get(key) match {
      case Some(info) => {
        sessionids.remove(key.sessionId)
        val principal = info.principal
        debug("Remove session " + key + " for " + principal)
        val sids = principals.get(principal) foreach { sids =>
          sids.remove(key.sessionId)
          if (sids.isEmpty) {
            principals.remove(principal)
            debug("Remove principal " + principal + " from registry")
          }
        }
        controller.onLogout(info)
        Some(info)
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
