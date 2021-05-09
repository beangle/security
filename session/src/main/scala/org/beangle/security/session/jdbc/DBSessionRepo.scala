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

import java.io.InputStream
import java.sql.Timestamp

import javax.sql.DataSource
import org.beangle.cache.CacheManager
import org.beangle.commons.bean.Initializing
import org.beangle.commons.event.EventPublisher
import org.beangle.commons.io.BinarySerializer
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.session._
import org.beangle.security.session.cache.CacheSessionRepo

class DBSessionRepo(domainProvider: DomainProvider, dataSource: DataSource, cacheManager: CacheManager, serializer: BinarySerializer)
  extends CacheSessionRepo(cacheManager) with EventPublisher with Initializing {

  var domainId: Int = _

  override def init(): Unit = {
    domainId = domainProvider.getDomainId
  }

  protected val executor = new JdbcExecutor(dataSource)

  var builder: SessionBuilder = DefaultSessionBuilder

  var sessionTable = "session_infoes"

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
}
