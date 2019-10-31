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
import org.beangle.commons.io.BinarySerializer
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.session.cache.CacheSessionRepo
import org.beangle.security.session.{DefaultSession, DefaultSessionBuilder, Session, SessionBuilder}

class DBSessionRepo(dataSource: DataSource, cacheManager: CacheManager, serializer: BinarySerializer)
  extends CacheSessionRepo(cacheManager) {

  protected val executor = new JdbcExecutor(dataSource)

  var builder: SessionBuilder = DefaultSessionBuilder

  var sessionTable = "session_infoes"

  protected override def getInternal(sessionId: String): Option[Session] = {
    val datas = executor.query(s"select data from $sessionTable where id=?", sessionId)
    if (datas.isEmpty) {
      None
    } else {
      val data = datas.head.head match {
        case is: InputStream => serializer.deserialize(classOf[DefaultSession], is, Map.empty)
        case ba: Array[Byte] => serializer.asObject(classOf[DefaultSession], ba)
      }
      Some(data)
    }
  }

  override def findByPrincipal(principal: String): collection.Seq[Session] = {
    val datas = executor.query(s"select data from $sessionTable info where principal =? order by last_access_at", principal)
    datas.map { data =>
      data.head match {
        case is: InputStream => serializer.deserialize(classOf[DefaultSession], is, Map.empty)
        case ba: Array[Byte] => serializer.asObject(classOf[DefaultSession], ba)
      }
    }
  }

  override def heartbeat(session: Session): Boolean = {
    executor.update(s"update $sessionTable set last_access_at=? where id=?",
      Timestamp.from(session.lastAccessAt), session.id) > 0
  }

}
