package org.beangle.security.core.session

import org.beangle.commons.event.Event

@SerialVersionUID(-6802410177820837015L)
class LoginEvent(source: Sessioninfo) extends Event(source) {

  def sessioninfo = source.asInstanceOf[Sessioninfo]
}

@SerialVersionUID(5562102005395894399L)
class LogoutEvent(source: Sessioninfo) extends Event(source) {

  def sessioninfo = source.asInstanceOf[Sessioninfo]
}
