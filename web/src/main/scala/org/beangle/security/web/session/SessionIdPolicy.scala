package org.beangle.security.web.session

import javax.servlet.http.HttpServletRequest
import org.beangle.security.session.SessionId

trait SessionIdPolicy {

  def getSessionId(request: HttpServletRequest): SessionId
}