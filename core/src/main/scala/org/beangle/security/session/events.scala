package org.beangle.security.session

import org.beangle.commons.event.Event

@SerialVersionUID(-6802410177820837015L)
class LoginEvent(src: Session) extends Event(src) {

  def session: Session = source.asInstanceOf[Session]
}

@SerialVersionUID(5562102005395894399L)
class LogoutEvent(src: Session, var reason: String = null) extends Event(src) {

  def session: Session = source.asInstanceOf[Session]
}


