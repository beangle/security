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

import java.io.{ InputStream, ObjectInputStream }
import java.{ util => ju }
import java.util.Timer
import org.beangle.commons.bean.Initializing
import org.beangle.cache.CacheManager
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.Objects
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.authc.Account
import org.beangle.security.session.profile.{ ProfileChangeEvent, ProfiledSessionRegistry }
import org.beangle.security.session.util.UpdateDelayGenerator
import org.nustaq.serialization.FSTConfiguration
import javax.sql.DataSource
import org.beangle.security.session.SessionRegistry
import org.beangle.security.session.LogoutEvent
import org.beangle.security.session.DefaultSession
import org.beangle.security.session.SessionBuilder
import org.beangle.security.session.DefaultSessionBuilder
import org.beangle.security.session.Session
/**
 * 基于数据库的session注册表
 */
class CacheSessionRegistry(dataCacheManager: CacheManager, statusCacheManager: CacheManager) extends SessionRegistry
    with EventPublisher {

  private val fstconf = FSTConfiguration.createDefaultConfiguration()

  private val accessDelayMillis = new UpdateDelayGenerator().generateDelayMilliTime()

  private val dataCache = dataCacheManager.getCache("session_data", classOf[String], classOf[Session.Data])

  private val statusCache = statusCacheManager.getCache("session_status", classOf[String], classOf[Session.Status])

  private val timeout = dataCache.ttl

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
      val session = builder.build(sessionId, this, info, client, System.currentTimeMillis(), timeout) // 新生
      save(session)
      //      publish(new LoginEvent(session))
      session
    }
  }

  override def remove(sessionId: String): Option[Session] = {
    remove(sessionId, null)
  }

  override def access(sessionId: String, accessAt: Long, accessed: String): Option[Session] = {
    get(sessionId) match {
      case s @ Some(session) =>
        if ((accessAt - session.status.lastAccessAt) > accessDelayMillis) {
          //the session was killed by some one,next access will issue login
//          if (dataCache.touch(session.id)) {
//            statusCache.put(session.id, new Session.DefaultStatus(accessAt))
//          } else {
//            dataCache.evict(session.id)
//            statusCache.evict(session.id)
//          }
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
        status = new Session.DefaultStatus(System.currentTimeMillis)
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
