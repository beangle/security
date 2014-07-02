package org.beangle.security.session

import java.io.{ Serializable => jSerializable }
import java.security.Principal
import java.{ util => ju }

import org.beangle.security.authc.AuthenticationInfo
import org.beangle.security.authc.DetailNames.{ Agent, Host, Os }

trait SessionKey {
  def sessionId: jSerializable
}

case class SessionId(val sessionId: jSerializable) extends SessionKey

object Session {
  val DefaultTimeOut: Short = 30 * 60
}
trait Session {

  def id: jSerializable

  def principal: AuthenticationInfo

  def loginAt: ju.Date

  def lastAccessAt: ju.Date

  def expiredAt: ju.Date

  def expired: Boolean

  def onlineTime: Long

  def lastAccessed: jSerializable

  def remark: String

  def os: String

  def agent: String

  def host: String

  def server: String

  /** the time in seconds that the session session may remain idle before expiring.*/
  def timeout: Short

  def timeout_=(s: Short)

  def stop(): Unit

  def expire(): Unit

  def access(accessAt: ju.Date, accessed: String): Unit

  def remark(added: String): Unit

}

class DefaultSession(val id: jSerializable, val principal: AuthenticationInfo, val registry: SessionRegistry, val loginAt: ju.Date, val os: String, val agent: String, val host: String)
  extends Session {
  var server: String = _
  var expiredAt: ju.Date = _
  var remark: String = _
  var timeout: Short = Session.DefaultTimeOut
  var lastAccessAt: ju.Date = _
  var lastAccessed: jSerializable = _

  def onlineTime: Long = {
    if (null == expiredAt) System.currentTimeMillis() - loginAt.getTime()
    else expiredAt.getTime() - loginAt.getTime()
  }

  def expired: Boolean = null != expiredAt
  def stop(): Unit = registry.remove(SessionId(id))
  def expire(): Unit = {
    expiredAt = new ju.Date()
    registry.onExpire(this)
  }

  def access(accessAt: ju.Date, accessed: String): Unit = {
    lastAccessAt = accessAt
    lastAccessed = accessed
    registry.onAccess(this, accessAt, accessed)
  }
  def remark(added: String): Unit = if (null == remark) remark = added else remark = remark + added
}

trait SessionBuilder {
  def build(key: SessionKey, auth: AuthenticationInfo, registry: SessionRegistry): Session
}

class DefaultSessionBuilder extends SessionBuilder {

  def build(key: SessionKey, auth: AuthenticationInfo, registry: SessionRegistry): Session = {
    val session = new DefaultSession(key.sessionId, auth, registry, new ju.Date(), auth.details(Os).toString, auth.details(Agent).toString, auth.details(Host).toString)
    session.lastAccessAt = new ju.Date()
    session
  }
}

