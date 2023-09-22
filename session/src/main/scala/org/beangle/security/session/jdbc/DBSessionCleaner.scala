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

import org.beangle.commons.lang.time.Stopwatch
import org.beangle.commons.logging.Logging
import org.beangle.security.util.Task

/** Database session registry cleaner.
  * <ul>
  * <li>removed expired session</li>
  * <li>removed long time idle session( now - last access time>tti seconds)</li>
  * </ul>
  * <strong>Implementation note:</strong> Make sure only one instance run clean up when multiple deployed.
  */
class DBSessionCleaner(val registry: DBSessionRegistry) extends Logging with Task {

  def run(): Unit = {
    val watch = new Stopwatch(true)
    logger.debug("starting clean up over expired time sessions ...")
    try {
      var removed = 0
      registry.findExpired() foreach { sid =>
        registry.remove(sid, "会话过期") foreach (_ => removed += 1)
      }
      if (removed > 0) logger.debug(s"removed $removed expired sessions in $watch")
    } catch {
      case e: Exception => logger.error("Beangle session cleanup failure.", e)
    }
  }
}
