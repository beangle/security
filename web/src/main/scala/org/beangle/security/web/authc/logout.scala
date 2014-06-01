package org.beangle.security.web.authc

import org.beangle.security.session.Session

import javax.servlet.{ServletRequest, ServletResponse}

trait LogoutHandler {
  def logout(req: ServletRequest, res: ServletResponse, session: Session): Unit
}

final class LogoutStack(handlers: List[LogoutHandler]) extends LogoutHandler {
  def logout(req: ServletRequest, res: ServletResponse, session: Session): Unit = {
    handlers.foreach { handler =>
      handler.logout(req, res, session)
    }
  }
}