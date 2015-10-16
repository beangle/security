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
package org.beangle.security.session

import org.beangle.commons.lang.Dates
import org.beangle.commons.logging.Logging
import org.beangle.commons.lang.time.Stopwatch
import java.{ util => ju }
import java.util.TimerTask
/**
 * Database session registry cleaner.
 * <ul>
 * <li>removed expired session</li>
 * <li>removed long time idle session( now - last access time>expiredTime)</li>
 * </ul>
 * <strong>Implementation note:</strong> Make sure only one instance run clean up when multiple  deployed.
 */
class SessionCleaner(val registry: SessionRegistry) extends Logging {

  /** 默认过期时间 30分钟 */
  var expiredMinutes = 30

  /**
   * Default interval(5 minutes) for clean up expired session infos.
   */
  var cleanIntervalMillis = 5 * 60 * 1000

  def cleanup() {
    val watch = new Stopwatch(true)
    logger.debug("clean up expired or over expired time session start ...")
    val calendar = ju.Calendar.getInstance()
    try {
      var removed = 0
      registry.getExpired(Dates.rollMinutes(calendar.getTime(), -expiredMinutes)) foreach { s =>
        registry.remove(SessionId(s.id)) foreach (olds => removed += 1)
      }
      if (removed > 0) logger.info(s"removed $removed expired sessions in $watch")
      registry.stat()
    } catch {
      case e: Exception => logger.error("Beangle session cleanup failure.", e)
    }
  }
}

class SessionCleanupDaemon(cleaner: SessionCleaner) extends TimerTask {
  override def run() {
    cleaner.cleanup();
  }

}
