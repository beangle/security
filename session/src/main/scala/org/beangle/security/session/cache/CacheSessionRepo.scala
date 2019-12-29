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
package org.beangle.security.session.cache

import java.time.Instant

import org.beangle.cache.CacheManager
import org.beangle.commons.bean.Initializing
import org.beangle.commons.logging.Logging
import org.beangle.security.session.util.UpdateDelayGenerator
import org.beangle.security.session.{Session, SessionRepo}
import org.beangle.security.util.SecurityDaemon

abstract class CacheSessionRepo(val cacheManager: CacheManager)
  extends SessionRepo with Initializing with Logging {

  private val sessions = cacheManager.getCache("sessions", classOf[String], classOf[Session])

  /** 访问更新延迟
   * 如果访问非常频繁，则根据访问延迟决定是否向后端发出心跳
   * 默认按照20~60秒的随机数字防止更新过快,具体到后端需要看flushInterval
   * 一般是3分钟
   */
  private val accessDelaySeconds = new UpdateDelayGenerator(20, 60).generateDelaySeconds()

  protected val accessReporter = new AccessReporter(sessions, this)

  /**
   * flush 间隔，以秒计,默认3分钟
   */
  var flushInterval: Int = 3 * 60

  override def init(): Unit = {
    SecurityDaemon.start("Beangle Session",flushInterval, this.accessReporter)
  }

  override def get(sessionId: String): Option[Session] = {
    if (null == sessionId) return None
    val data = sessions.get(sessionId)
    if (data.isEmpty) {
      val newData = getInternal(sessionId)
      if (newData.nonEmpty) sessions.putIfAbsent(sessionId, newData.get)
      newData
    } else {
      data
    }
  }

  override def access(sessionId: String, accessAt: Instant): Option[Session] = {
    get(sessionId) match {
      case None => None
      case se@Some(s) =>
        val elapse = s.access(accessAt)
        if (elapse > accessDelaySeconds) {
          accessReporter.addSessionId(s.id, accessAt)
          se
        } else {
          if (elapse == -1) {
            expire(s.id)
            None
          } else {
            se
          }
        }
    }
  }

  protected def put(session: Session): Unit = {
    sessions.putIfAbsent(session.id, session)
  }

  protected def evict(session: Session): Unit = {
    sessions.evict(session.id)
  }

  protected def getInternal(sessionId: String): Option[Session]

  /** 向后端更新该会话的访问时间
   *
   * @param session 会话
   * @return true如果是否依然存在该会话
   */
  def flush(session: Session): Boolean

}
