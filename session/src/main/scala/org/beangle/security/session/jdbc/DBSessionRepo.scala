package org.beangle.security.session.jdbc

import java.io.{ InputStream, ObjectInputStream }
import java.sql.Timestamp

import org.beangle.cache.CacheManager
import org.beangle.commons.io.BinarySerializer
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.session.{ DefaultSessionBuilder, Session, SessionBuilder }
import org.beangle.security.session.cache.CacheSessionRepo

import javax.sql.DataSource

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
        case is: InputStream => serializer.deserialize(classOf[Session], is, Map.empty)
        case ba: Array[Byte] => serializer.asObject(classOf[Session], ba)
      }
      Some(data)
    }
  }

  override def heartbeat(session: Session): Boolean = {
    executor.update(s"update $sessionTable set last_access_at=? where id=?",
      Timestamp.from(session.lastAccessAt), session.id) > 0
  }

}