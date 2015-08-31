package org.beangle.security.session.mem

import java.io.{ Serializable => jSerializable }
import java.{ util => ju }

import org.beangle.commons.event.EventPublisher
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.AuthenticationInfo
import org.beangle.security.session.{ AbstractSessionRegistry, DefaultSessionProfile, LoginEvent, LogoutEvent, Session, SessionBuilder, SessionId, SessionKey, SessionProfile }

class MemSessionRegistry(val builder: SessionBuilder) extends AbstractSessionRegistry with Logging with EventPublisher {

  protected val principals = new collection.concurrent.TrieMap[Any, collection.mutable.HashSet[jSerializable]]

  protected val sessionids = new collection.concurrent.TrieMap[jSerializable, Session]

  private val defaultProfile = new DefaultSessionProfile("*")

  def isRegisted(principal: String): Boolean = {
    val sids = principals.get(principal)
    (!sids.isEmpty && !sids.get.isEmpty)
  }

  override def get(principal: String, includeExpired: Boolean): Seq[Session] = {
    principals.get(principal) match {
      case None => List.empty
      case Some(sids) => {
        val list = new collection.mutable.ListBuffer[Session]
        for (sessionid <- sids)
          get(SessionId(sessionid)).foreach(info => if (includeExpired || !info.expired) list += info)
        list
      }
    }
  }

  override def getExpired(lastAccessAt: ju.Date): Seq[Session] = {
    val expired = new collection.mutable.ListBuffer[Session]
    sessionids foreach {
      case (id, s) => if (s.expired || s.lastAccessAt.before(lastAccessAt)) expired += s
    }
    expired
  }

  override def get(key: SessionKey): Option[Session] = {
    if (null == key) None
    else sessionids.get(key.sessionId)
  }

  override def register(auth: AuthenticationInfo, key: SessionKey): Session = {
    val principal = auth.getName
    val existed = get(key) match {
      case Some(existed) => {
        if (existed.principal.getName() != principal) {
          tryAllocate(key, auth)
          existed.remark(" expired with replacement.")
          remove(key)
        }
      }
      case None => tryAllocate(key, auth)
    }

    val newSession = builder.build(key, auth, this)
    newSession.timeout = getTimeout(auth)
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
        logger.debug(s"Remove session $key for $principal")
        val sids = principals.get(principal) foreach { sids =>
          sids.remove(key.sessionId)
          if (sids.isEmpty) principals.remove(principal)
        }
        release(s)
        publish(new LogoutEvent(s))
        Some(s)
      }
      case None => None
    }
  }

  def count(): Int = sessionids.size

  override def stat(): Unit = {}

  protected override def allocate(auth: AuthenticationInfo, key: SessionKey): Boolean = true
  /**
   * release slot for user
   */
  protected override def release(session: Session): Unit = {}

  protected def getProfile(auth: AuthenticationInfo): Option[SessionProfile] = Some(DefaultSessionProfile)

}