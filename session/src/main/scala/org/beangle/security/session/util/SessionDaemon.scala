package org.beangle.security.session.util

import java.util.{ Timer, TimerTask }

object SessionDaemon {
  def start(interval: Int, tasks: Task*): Unit = {
    println(s"Starting Beangle Session Daemon after ${interval} millis")
    val daemon = new SessionDaemon(tasks)
    new Timer("Beangle Session Daemon", true).schedule(daemon,
      new java.util.Date(System.currentTimeMillis + interval),
      interval)
  }
}
class SessionDaemon(tasks: Seq[Task]) extends TimerTask {
  override def run() {
    tasks foreach { task =>
      task.run()
    }
  }
}