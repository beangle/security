package org.beangle.security.session.jdbc

import java.io.{ InputStream, ObjectInputStream }
import java.sql.Timestamp

import org.beangle.cache.CacheManager
import org.beangle.commons.io.DefaultBinarySerializer
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.session.{ DefaultSessionBuilder, Session, SessionBuilder }
import org.beangle.security.session.cache.CacheSessionRepo

import javax.sql.DataSource

class DBSessionRepo(val dataSource: DataSource, cacheManager: CacheManager)
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
        case is: InputStream => new ObjectInputStream(is).readObject().asInstanceOf[Session]
        case ba: Array[Byte] => DefaultBinarySerializer.deserialize(ba, Map.empty).asInstanceOf[Session]
      }
      Some(data)
    }
  }

  override def heartbeat(session: Session): Boolean = {
    executor.update(s"update $sessionTable set last_access_at=? where id=?",
      Timestamp.from(session.lastAccessAt), session.id) > 0
  }

}