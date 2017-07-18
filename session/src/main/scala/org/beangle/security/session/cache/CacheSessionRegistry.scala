/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.session.jdbc

import java.time.{ Duration, Instant }

import org.beangle.cache.CacheManager
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.Objects
import org.beangle.security.authc.Account
import org.beangle.security.session.{ DefaultSession, DefaultSessionBuilder, LogoutEvent, Session, SessionBuilder, SessionRegistry }
import org.beangle.security.session.util.UpdateDelayGenerator

/**
 * 基于数据库的session注册表
 */
class CacheSessionRegistry(dataCacheManager: CacheManager, statusCacheManager: CacheManager) extends SessionRegistry
    with EventPublisher {

  private val accessDelaySeconds = new UpdateDelayGenerator().generateDelaySeconds()

  private val dataCache = dataCacheManager.getCache("session_data", classOf[String], classOf[Session.Data])

  private val statusCache = statusCacheManager.getCache("session_status", classOf[String], classOf[Session.Status])

  private val timeout = Duration.ofSeconds(dataCache.ttl)

  var builder: SessionBuilder = DefaultSessionBuilder

  var cleaner: SessionCleaner = _

  override def register(sessionId: String, info: Account, client: Session.Client): Session = {
    val existed = get(sessionId).orNull
    val principal = info.getName
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      if (null != existed) remove(sessionId, " expired with replacement."); // 注销同会话的其它账户
      val session = builder.build(sessionId, this, info, client, Instant.now, timeout) // 新生
      save(session)
      //      publish(new LoginEvent(session))
      session
    }
  }

  override def remove(sessionId: String): Option[Session] = {
    remove(sessionId, null)
  }

  override def access(sessionId: String, accessAt: Instant, accessed: String): Option[Session] = {
    get(sessionId) match {
      case s @ Some(session) =>
        if ((accessAt.getEpochSecond - session.status.lastAccessAt.getEpochSecond) > accessDelaySeconds) {
          //the session was killed by some one,next access will issue login
          if (dataCache.touch(session.id)) {
            statusCache.put(session.id, new Session.DefaultStatus(accessAt))
          } else {
            dataCache.evict(session.id)
            statusCache.evict(session.id)
          }
        }
        s
      case None => None
    }
  }

  override def get(sessionId: String): Option[Session] = {
    if (null == sessionId) return None

    val data = dataCache.get(sessionId).orNull
    var status = statusCache.get(sessionId).orNull
    if (null == data) {
      if (null == status) statusCache.evict(sessionId)
      None
    } else {
      if (null == status) {
        status = new Session.DefaultStatus(Instant.now)
        statusCache.put(sessionId, status)
      }
      Some(builder.build(sessionId, this, data, status))
    }
  }

  private def remove(sessionId: String, reason: String): Option[Session] = {
    val s = get(sessionId)
    s foreach { session =>
      publish(new LogoutEvent(session, reason))
      dataCache.evict(sessionId)
      statusCache.evict(sessionId)
    }
    s
  }

  private def save(session: Session): Unit = {
    val s = session.asInstanceOf[DefaultSession]
    val sessionId = s.id
    dataCache.putIfAbsent(sessionId, s.data)
    statusCache.put(sessionId, s.status) // Given the status cache is local cache
  }

}
