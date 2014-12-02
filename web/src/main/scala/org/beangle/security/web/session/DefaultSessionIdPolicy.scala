package org.beangle.security.web.session

import javax.servlet.http.HttpServletRequest
import org.beangle.security.session.SessionId

class DefaultSessionIdPolicy extends SessionIdPolicy {

  var sessionIdParam: String = _

  def getSessionId(req: HttpServletRequest): SessionId = {
    var sid: String = null
    if (null != sessionIdParam) {
      sid = req.getParameter(sessionIdParam)
    } else {
      val hs = req.getSession(true)
      sid = hs.getId
    }
    if (null != sid) SessionId(sid) else null
  }
}