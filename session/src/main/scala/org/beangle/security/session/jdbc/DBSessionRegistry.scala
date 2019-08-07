/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.session.jdbc

import java.sql.{Timestamp, Types}
import java.time.Instant

import org.beangle.cache.CacheManager
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.io.BinarySerializer
import org.beangle.commons.lang.Objects
import org.beangle.data.jdbc.query.ParamSetter
import org.beangle.security.authc.Account
import org.beangle.security.session.{LoginEvent, LogoutEvent, Session, SessionRegistry}
import org.beangle.security.session.util.SessionDaemon

import javax.sql.DataSource

/**
  * 基于数据库的session注册表
  */
class DBSessionRegistry(dataSource: DataSource, cacheManager: CacheManager, serializer: BinarySerializer)
  extends DBSessionRepo(dataSource, cacheManager, serializer)
    with EventPublisher with SessionRegistry {

  private val insertColumns = "id,principal,description,ip,agent,os,login_at,last_access_at,data"

  /** 默认过期时间 45分钟 */
  var ttiMinutes: Int = 45

  override def init(): Unit = {
    SessionDaemon.start(heartbeatSeconds, heartbeatReporter,
      new DBSessionCleaner(this, ttiMinutes))
  }

  override def register(sessionId: String, info: Account, agent: Session.Agent): Session = {
    val existed = get(sessionId).orNull
    val principal = info.getName
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      if (null != existed) remove(sessionId, " expired by replacement."); // 注销同会话的其它账户
      val session = builder.build(sessionId, info, Instant.now, agent) // 新生
      save(session)
      publish(new LoginEvent(session))
      session
    }
  }

  override def remove(sessionId: String): Option[Session] = {
    remove(sessionId, null)
  }

  def getBeforeAccessAt(lastAccessAt: Instant): collection.Seq[String] = {
    executor.query(s"select id from $sessionTable info where info.last_access_at < ?", Timestamp.from(lastAccessAt)).map { data => data(0).toString }
  }

  private def remove(sessionId: String, reason: String): Option[Session] = {
    val s = get(sessionId)
    s foreach { session =>
      publish(new LogoutEvent(session, reason))
      evict(session)
      executor.update(s"delete from $sessionTable where id=?", sessionId)
    }
    s
  }

  private def save(s: Session): Unit = {
    val sessionId = s.id
    val ac = s.agent
    executor.statement(s"insert into $sessionTable ($insertColumns) values(?,?,?,?,?,?,?,?,?)")
      .prepare(x => {
        x.setString(1, sessionId)
        x.setString(2, s.principal.getName)
        x.setString(3, s.principal.asInstanceOf[Account].description)
        x.setString(4, ac.ip)
        x.setString(5, ac.name)
        x.setString(6, ac.os)
        x.setTimestamp(7, Timestamp.from(s.loginAt))
        x.setTimestamp(8, Timestamp.from(s.loginAt))
        ParamSetter.setParam(x, 9, serializer.asBytes(s), Types.BINARY)
      }).execute()
    put(s)
  }
}
