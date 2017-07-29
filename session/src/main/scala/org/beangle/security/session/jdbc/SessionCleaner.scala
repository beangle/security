/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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

import org.beangle.commons.lang.Dates
import org.beangle.commons.logging.Logging
import org.beangle.commons.lang.time.Stopwatch
import java.{ util => ju }
import java.util.TimerTask
import org.beangle.security.session.util.UpdateDelayGenerator
/**
 * Database session registry cleaner.
 * <ul>
 * <li>removed expired session</li>
 * <li>removed long time idle session( now - last access time>expiredTime)</li>
 * </ul>
 * <strong>Implementation note:</strong> Make sure only one instance run clean up when multiple  deployed.
 */
class SessionCleaner(val registry: DBSessionRegistry) extends Logging {

  /** 默认过期时间 30分钟 */
  var expiredMinutes = 30

  /**
   * Default interval(最大写延迟的基础上增加5分钟)clean up expired session infos.
   */
  var cleanIntervalMillis = 5 * 60 * 1000 + new UpdateDelayGenerator().maxDelay

  def cleanup() {
    val watch = new Stopwatch(true)
    logger.debug("starting clean up over expired time sessions ...")
    val calendar = ju.Calendar.getInstance()
    try {
      var removed = 0
      registry.getBeforeAccessAt(Dates.rollMinutes(calendar.getTime(), -expiredMinutes).toInstant) foreach { sid =>
        registry.remove(sid) foreach (olds => removed += 1)
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
