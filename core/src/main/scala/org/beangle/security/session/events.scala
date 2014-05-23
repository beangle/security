package org.beangle.security.session

import org.beangle.commons.event.Event

@SerialVersionUID(-6802410177820837015L)
class LoginEvent(source: Session) extends Event(source) {

  def sessioninfo = source.asInstanceOf[Session]
}

@SerialVersionUID(5562102005395894399L)
class LogoutEvent(source: Session) extends Event(source) {

  def sessioninfo = source.asInstanceOf[Session]
}
