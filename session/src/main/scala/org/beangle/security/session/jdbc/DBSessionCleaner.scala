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

import org.beangle.commons.lang.Dates
import org.beangle.commons.logging.Logging
import org.beangle.commons.lang.time.Stopwatch
import java.{ util => ju }
import java.util.TimerTask
import org.beangle.security.session.util.UpdateDelayGenerator
import org.beangle.security.session.util.Task

/**
 * Database session registry cleaner.
 * <ul>
 * <li>removed expired session</li>
 * <li>removed long time idle session( now - last access time>expiredTime)</li>
 * </ul>
 * <strong>Implementation note:</strong> Make sure only one instance run clean up when multiple  deployed.
 */
class DBSessionCleaner(val registry: DBSessionRegistry, val ttiMinutes: Int)
  extends Logging with Task {

  def run() {
    val watch = new Stopwatch(true)
    logger.debug("starting clean up over expired time sessions ...")
    val calendar = ju.Calendar.getInstance()
    try {
      var removed = 0
      registry.getBeforeAccessAt(Dates.rollMinutes(calendar.getTime(), -ttiMinutes).toInstant) foreach { sid =>
        registry.remove(sid) foreach (olds => removed += 1)
      }
      if (removed > 0) logger.info(s"removed $removed expired sessions in $watch")
    } catch {
      case e: Exception => logger.error("Beangle session cleanup failure.", e)
    }
  }
}
