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
package org.beangle.security.session.util

import java.util.{Timer, TimerTask}

object SessionDaemon {

  def start(intervalSeconds: Int, tasks: Task*): Unit = {
    println(s"Starting Beangle Session Daemon after $intervalSeconds seconds")
    val daemon = new SessionDaemon(tasks)
    new Timer("Beangle Session Daemon", true).schedule(
      daemon,
      new java.util.Date(System.currentTimeMillis + intervalSeconds * 1000),
      intervalSeconds * 1000)
  }
}

class SessionDaemon(tasks: collection.Seq[Task]) extends TimerTask {
  override def run(): Unit = {
    tasks foreach { task =>
      task.run()
    }
  }
}
