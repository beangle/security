package org.beangle.security.session.jdbc

import org.beangle.cache.CacheManager
import org.beangle.commons.io.BinarySerializer
import javax.sql.DataSource
import org.beangle.data.jdbc.query.JdbcExecutor
import org.beangle.security.session.SessionBuilder
import org.beangle.security.session.util.UpdateDelayGenerator
import org.beangle.security.session.Session
import java.time.Instant
import org.beangle.security.session.SimpleSessionBuilder
import java.io.ObjectInputStream
import java.io.ObjectInputStream
import org.beangle.security.session.SessionRepo
import java.sql.Timestamp
import java.io.InputStream
import org.beangle.security.session.cache.CacheSessionRepo
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import java.util.Timer
import org.beangle.security.session.util.SessionDaemon

class DBSessionRepo(val dataSource: DataSource, val serializer: BinarySerializer, cacheManager: CacheManager)
    extends CacheSessionRepo(cacheManager) {

  protected val executor = new JdbcExecutor(dataSource)

  var builder: SessionBuilder = SimpleSessionBuilder

  var sessionTable = "session_infoes"

  protected override def getInternal(sessionId: String): Option[Session] = {
    val datas = executor.query(s"select data from $sessionTable where id=?", sessionId)
    if (datas.isEmpty) {
      None
    } else {
      val data = datas.head.head match {
        case is: InputStream => new ObjectInputStream(is).readObject().asInstanceOf[Session]
        case ba: Array[Byte] => serializer.deserialize(ba, Map.empty).asInstanceOf[Session]
      }
      Some(data)
    }
  }

  override def heartbeat(session: Session): Boolean = {
    executor.update(s"update $sessionTable set last_access_at=? where id=?",
      Timestamp.from(session.lastAccessAt), session.id) > 0
  }

}