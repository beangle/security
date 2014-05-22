package org.beangle.security.session

import java.util.Date
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.AuthenticationInfo

trait Sessioninfo {

  def id: String

  def username: String

  def fullname: String

  def loginAt: Date

  def expired: Boolean

  def onlineTime: Long

  def remark: String

  def expireNow(): Sessioninfo

  def addRemark(added: String): Sessioninfo

  def expiredAt: Date

  def lastAccessAt: Date

  def server: String
}

trait SessioninfoBuilder {

  def getSessioninfoType(): Class[_ <: Sessioninfo]

  def build(auth: AuthenticationInfo, sessionid: String): Sessioninfo
}

trait SessionIdAware {

  def sessionId: String
}

trait SessionRegistry {

  def register(authentication: AuthenticationInfo, sessionid: String)

  def remove(sessionid: String): Option[Sessioninfo]

  def expire(sessionid: String): Boolean

  def getSessioninfos(principal: String, includeExpiredSessions: Boolean): List[Sessioninfo]

  def getSessioninfo(sessionid: String): Option[Sessioninfo]

  def getSessionStatus(sessionid: String): Option[SessionStatus]

  def isRegisted(principal: String): Boolean

  def count: Int

  def access(sessionid: String, accessAt: Long)

  def controller: SessionController
}

trait SessionController {

  def onRegister(auth: AuthenticationInfo, sessionId: String, registry: SessionRegistry): Boolean

  def onLogout(info: Sessioninfo)

  def stat()

  def getMaxSessions(auth: AuthenticationInfo): Int

  def getInactiveInterval(auth: AuthenticationInfo): Option[Short]
}

@SerialVersionUID(-1110252524091983477L)
class SessionStatus(val username: String) extends Serializable() {

  var lastAccessedTime: Long = _

  def this(info: Sessioninfo) {
    this(info.username)
    lastAccessedTime = if ((null == info.lastAccessAt)) -1 else info.lastAccessAt.getTime
  }
}

trait SessionStatusCache {

  def get(id: String): SessionStatus

  def put(id: String, newstatus: SessionStatus)

  def evict(id: String)

  def ids: Set[String]
}

class MemSessionRegistry extends SessionRegistry with Initializing with Logging {

  var controller: SessionController = _

  var builder: SessioninfoBuilder = _

  protected var principals = new collection.concurrent.TrieMap[String, collection.mutable.HashSet[String]]

  protected var sessionids = new collection.concurrent.TrieMap[String, Sessioninfo]

  def init() {
    require(null != controller)
    require(null != builder)
  }

  def isRegisted(principal: String): Boolean = {
    val sids = principals.get(principal)
    (!sids.isEmpty && !sids.get.isEmpty)
  }

  def getSessioninfos(principal: String, includeExpired: Boolean): List[Sessioninfo] = {
    principals.get(principal) match {
      case None => List.empty
      case Some(sids) => {
        val list = new collection.mutable.ListBuffer[Sessioninfo]
        for (sessionid <- sids)
          getSessioninfo(sessionid).foreach(info => if (includeExpired || !info.expired) list += info)
        list.toList
      }
    }
  }

  def getSessioninfo(sessionid: String): Option[Sessioninfo] = sessionids.get(sessionid)

  def register(auth: AuthenticationInfo, sessionid: String) {
    val principal = auth.getName
    val existed = getSessioninfo(sessionid) match {
      case Some(existed) => {
        if (existed.username != principal) {
          if (!controller.onRegister(auth, sessionid, this)) throw new SessionException("security.OvermaxSession")
          existed.addRemark(" expired with replacement.")
          remove(sessionid)
        }
      }
      case None => if (!controller.onRegister(auth, sessionid, this)) throw new SessionException("security.OvermaxSession")
    }
    sessionids.put(sessionid, builder.build(auth, sessionid))
    principals.get(principal) match {
      case None => principals.put(principal, new collection.mutable.HashSet += sessionid)
      case Some(sids) => sids += sessionid
    }
  }

  def remove(sessionid: String): Option[Sessioninfo] = {
    getSessioninfo(sessionid) match {
      case Some(info) => {
        sessionids.remove(sessionid)
        val principal = info.username
        debug("Remove session " + sessionid + " for " + principal)
        val sids = principals.get(principal) foreach { sids =>
          sids.remove(sessionid)
          if (sids.isEmpty) {
            principals.remove(principal)
            debug("Remove principal "+principal+" from registry" )
          }
        }
        controller.onLogout(info)
        Some(info)
      }
      case None => None
    }
  }

  def expire(sessionid: String): Boolean = {
    getSessioninfo(sessionid).foreach(info => info.expireNow())
    true
  }

  def getSessionStatus(sessionid: String): Option[SessionStatus] = {
    getSessioninfo(sessionid) match {
      case None => None
      case Some(info) => Some(new SessionStatus(info))
    }
  }

  def count(): Int = sessionids.size

  def access(sessionid: String, beginAt: Long) {
  }
}

