/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.session.jdbc

import org.beangle.commons.bean.Initializing
import org.beangle.commons.cache.CacheManager
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.io.BinarySerializer
import org.beangle.commons.lang.Objects
import org.beangle.jdbc.query.JdbcExecutor
import org.beangle.security.authc.Account
import org.beangle.security.session.*
import org.beangle.security.session.cache.CacheSessionRepo

import java.io.InputStream
import java.sql.{Timestamp, Types}
import java.time.Instant
import javax.sql.DataSource

/** 基于数据库的session注册表
 * 使用数据库的$sessionTable表
 */
class DBSessionRegistry(domainProvider: DomainProvider, dataSource: DataSource,
                        cacheManager: CacheManager, serializer: BinarySerializer)
  extends CacheSessionRepo(cacheManager), EventPublisher, Initializing, SessionRegistry {

  private val insertColumns = "id,principal,description,ip,agent,os,login_at,last_access_at,tti_seconds,category_id,domain_id,data"
  var sessionTable = "session_infoes"

  private var domainId: Int = _

  private val executor = new JdbcExecutor(dataSource)

  private val builder = DefaultSessionBuilder

  override def init(): Unit = {
    super.init()
    domainId = domainProvider.getDomainId
  }

  protected override def getInternal(sessionId: String): Option[Session] = {
    val datas = executor.query(s"select data,last_access_at,tti_seconds from $sessionTable where id=?", sessionId)
    if (datas.isEmpty) {
      None
    } else {
      val data = datas.head.head match {
        case is: InputStream => serializer.deserialize(classOf[DefaultSession], is, Map.empty)
        case ba: Array[Byte] => serializer.asObject(classOf[DefaultSession], ba)
      }
      //从数据库中取出时，需要更新访问时间和tti，这两项会有改变
      data.lastAccessAt = datas.head(1).asInstanceOf[Timestamp].toInstant
      data.ttiSeconds = datas.head(2).asInstanceOf[Number].intValue
      Some(data)
    }
  }

  override def findByPrincipal(principal: String): collection.Seq[Session] = {
    val datas = executor.query(s"select data,last_access_at,tti_seconds from $sessionTable info where principal =? and domain_id=? order by last_access_at", principal, domainId)
    datas.map { data =>
      val s = data.head match {
        case is: InputStream => serializer.deserialize(classOf[DefaultSession], is, Map.empty)
        case ba: Array[Byte] => serializer.asObject(classOf[DefaultSession], ba)
      }
      //从数据库中取出时，需要更新访问时间和tti，这两项会有改变
      s.access(datas.head(1).asInstanceOf[Timestamp].toInstant)
      s.ttiSeconds = datas.head(2).asInstanceOf[Number].intValue
      s
    }
  }

  /** 后端是否依然存在该会话
   *
   * @param session 会话
   * @return true如果仍然存在
   */
  override def flush(session: Session): Boolean = {
    executor.update(s"update $sessionTable set last_access_at=? where id=?",
      Timestamp.from(session.lastAccessAt), session.id) > 0
  }

  /** 过期指定会话
   * 同时更新数据库和缓存
   */
  override def expire(sessionId: String): Unit = {
    executor.update(s"update $sessionTable set tti_seconds=0 where id=?", sessionId)
    get(sessionId) foreach { session =>
      session.ttiSeconds = 0
      evict(sessionId)
      executor.update(s"delete from $sessionTable where id=?", sessionId)
      publish(new LogoutEvent(session, "强制过期"))
    }
  }

  override def register(sessionId: String, info: Account, agent: Session.Agent, profile: SessionProfile): Session = {
    val existed = get(sessionId).orNull
    val principal = info.getName
    if (profile.checkCapacity) {
      val sc = sessionCount(info.categoryId)
      if (sc + 1 > profile.capacity) {
        throw new OvermaxSessionException(profile.capacity, principal)
      }
    }
    // 是否为重复注册
    if (null != existed && Objects.equals(existed.principal, principal)) {
      existed
    } else {
      if (null != existed) remove(sessionId, " expired by replacement."); // 注销同会话的其它账户
      if (profile.checkConcurrent && profile.concurrent > 0) {
        val concurrents = findByPrincipal(principal)
        val expiredCnt = concurrents.size + 1 - profile.concurrent
        if (expiredCnt > 0) {
          concurrents.take(expiredCnt) foreach (x => expire(x.id))
        }
      }
      val session = builder.build(sessionId, info, Instant.now, agent, profile.ttiSeconds) // 新生
      save(session)
      publish(new LoginEvent(session))
      session
    }
  }

  override def findExpired(): collection.Seq[String] = {
    executor.query(s"select id from $sessionTable info where add_seconds(info.last_access_at,tti_seconds) <= current_timestamp and domain_id=?", this.domainId)
      .map { data => data(0).toString }
  }

  private def sessionCount(categoryId: Int): Int = {
    executor.queryForInt(s"select count(*) from $sessionTable where category_id=" + categoryId + " and domain_id=" + domainId).getOrElse(0)
  }

  override def remove(sessionId: String, reason: String): Option[Session] = {
    val s = get(sessionId)
    s foreach { session =>
      evict(sessionId)
      executor.update(s"delete from $sessionTable where id=?", sessionId)
      publish(new LogoutEvent(session, reason))
    }
    s
  }

  private def save(s: Session): Unit = {
    val sessionId = s.id
    val ac = s.agent
    executor.statement(s"insert into $sessionTable ($insertColumns) values(?,?,?,?,?,?,?,?,?,?,?,?)")
      .prepare(x => {
        x.setString(1, sessionId)
        x.setString(2, s.principal.getName)
        x.setString(3, s.principal.asInstanceOf[Account].description)
        x.setString(4, ac.ip)
        x.setString(5, ac.name)
        x.setString(6, ac.os)
        x.setTimestamp(7, Timestamp.from(s.loginAt))
        x.setTimestamp(8, Timestamp.from(s.loginAt))
        x.setInt(9, s.ttiSeconds)
        x.setInt(10, s.principal.asInstanceOf[Account].categoryId)
        x.setInt(11, domainId)
        executor.setParam(x, 12, serializer.asBytes(s), Types.BINARY)
      }).execute()
    put(s)
  }
}
