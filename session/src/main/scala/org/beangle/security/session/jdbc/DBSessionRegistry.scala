/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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
import org.beangle.commons.cache.CacheManager
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.lang.Objects
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.authc.Account
import org.beangle.security.session.{ DefaultSession, DefaultSessionBuilder, LoginEvent, LogoutEvent, Session, SessionBuilder }
import org.beangle.security.session.profile.{ ProfileChangeEvent, ProfiledSessionRegistry }
import org.beangle.security.session.util.UpdateDelayGenerator
import org.nustaq.serialization.FSTConfiguration

import javax.sql.DataSource
/**
 * 基于数据库的session注册表
 */
class DBSessionRegistry(dataSource: DataSource, dataCacheManager: CacheManager, statusCacheManager: CacheManager)
    extends ProfiledSessionRegistry with EventPublisher with Initializing {

  private val fstconf = FSTConfiguration.createDefaultConfiguration()

  private val insertColumns = "id,data,last_access_at,principal,profile_id"

  private val allSelectColumns = "data,last_access_at"

  private val statusSelectColumns = "last_access_at"

  private val accessDelayMillis = new UpdateDelayGenerator().generateDelayMilliTime()

  private val dataCache = dataCacheManager.getCache[String, Session.Data]("session_data")

  private val statusCache = statusCacheManager.getCache[String, Session.Status]("session_status")

  private val executor = new JdbcExecutor(dataSource)

  var builder: SessionBuilder = DefaultSessionBuilder

  var sessionTable = "session_infoes"

  var statTable = "session_stats"

  var cleaner: SessionCleaner = _

  def init() {
    val exists = executor.query(s"select id from $statTable").map(x => x.head.asInstanceOf[Int]).toSet
    profileProvider.getProfiles() foreach { p =>
      if (exists.contains(p.id)) {
        executor.update(s"update $statTable set capacity=? where id=?", p.capacity, p.id.longValue)
      } else {
        executor.update(s"insert into $statTable(id,on_line,capacity,stat_at) values(?,?,?,?)", p.id, 0, p.capacity, new ju.Date)
      }
    }
    if (null != cleaner) {
      // 下一次间隔开始清理，不浪费启动时间
      new Timer("Beangle Session Cleaner", true).schedule(new SessionCleanupDaemon(cleaner),
        new ju.Date(System.currentTimeMillis + cleaner.cleanIntervalMillis),
        cleaner.cleanIntervalMillis);
    }
  }

  override def register(sessionId: String, info: Account, client: Session.Client): Session = {
    val existed = get(sessionId).orNull
    val principal = info.getName
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      tryAllocate(sessionId, info) // 争取名额
      if (null != existed) remove(sessionId, " expired with replacement."); // 注销同会话的其它账户
      val session = builder.build(sessionId, this, info, client, System.currentTimeMillis(), getTimeout(info)) // 新生
      save(session)
      publish(new LoginEvent(session))
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
          val existed = executor.update(s"update $sessionTable set last_access_at=? where id=?", accessAt, session.id) > 0
          //the session was killed by some one,next access will issue login
          if (existed) {
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

  override def getByPrincipal(principal: String): Seq[Session] = {
    executor.query(s"select id from $sessionTable info where info.principal=?", principal)
      .map(s => get(s(0).toString)).flatten
  }

  override def get(sessionId: String): Option[Session] = {
    if (null == sessionId) return None

    var data = dataCache.get(sessionId).orNull
    var status = statusCache.get(sessionId).orNull

    if (null == data) {
      val datas = executor.query(s"select $allSelectColumns from $sessionTable where id=?", sessionId)
      if (datas.isEmpty) {
        if (null != status) statusCache.evict(sessionId)
        None
      } else {
        val result = datas(0)
        data = result(0) match {
          case is: InputStream => new ObjectInputStream(is).readObject().asInstanceOf[Session.Data]
          case ba: Array[Byte] => fstconf.asObject(ba).asInstanceOf[Session.Data]
        }
        status = new Session.DefaultStatus(result(1).asInstanceOf[Number].longValue)
        dataCache.putIfAbsent(sessionId, data)
        statusCache.put(sessionId, status)
        Some(builder.build(sessionId, this, data, status))
      }
    } else if (null == status) {
      val datas = executor.query(s"select $statusSelectColumns from $sessionTable where id=?", sessionId)
      if (datas.isEmpty) {
        dataCache.evict(sessionId)
        None
      } else {
        val result = datas(0)
        status = new Session.DefaultStatus(result(0).asInstanceOf[Number].longValue)
        statusCache.put(sessionId, status)
        Some(builder.build(sessionId, this, data, status))
      }
    } else {
      Some(builder.build(sessionId, this, data, status))
    }
  }

  def getBeforeAccessAt(lastAccessAt: Long): Seq[String] = {
    executor.query(s"select id from $sessionTable info where info.last_access_at <?", lastAccessAt).map { data => data(0).toString }
  }

  override def size: Int = {
    executor.queryForInt(s"select count(id) from $sessionTable")
  }

  protected override def allocate(auth: Account, sessionId: String): Boolean = {
    executor.update(s"update $statTable set on_line = on_line + 1 where on_line < capacity and id=?", getProfileId(auth).longValue()) > 0
  }

  protected override def release(session: Session): Unit = {
    executor.update(s"update $statTable set on_line=on_line - 1 where on_line>0 and id=?", getProfileId(session.principal).longValue())
  }

  def stat(): Unit = {
    executor.update(s"update $statTable stat set on_line=(select count(id) from $sessionTable " +
      " info where  info.profile_id=stat.id),stat_at = ?", new ju.Date())
  }
  /**
   * Handle an application event.
   */
  override def onEvent(event: ProfileChangeEvent): Unit = {
    executor.update(s"update $statTable set capacity=? where id=?", event.profile.id.longValue())
  }

  private def remove(sessionId: String, reason: String): Option[Session] = {
    val s = get(sessionId)
    s foreach { session =>
      release(session)
      publish(new LogoutEvent(session, reason))
      dataCache.evict(sessionId)
      statusCache.evict(sessionId)
      executor.update(s"delete from $sessionTable where id=?", sessionId)
    }
    s
  }

  private def save(session: Session): Unit = {
    val s = session.asInstanceOf[DefaultSession]
    val sessionId = s.id

    executor.update(s"insert into $sessionTable ($insertColumns) values(?,?,?,?,?)",
      sessionId, fstconf.asByteArray(new Session.Data(s.principal, s.client, s.loginAt, s.timeout)),
      s.status.lastAccessAt, s.principal.getName, profileProvider.getProfile(s.principal).id.longValue)

    dataCache.putIfAbsent(sessionId, s.data)
    statusCache.put(sessionId, s.status) // Given the status cache is local cache
  }

}
