package org.beangle.security.web

import org.beangle.security.authc.AuthenticationToken
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.SessionRegistry
import org.beangle.security.session.Session
import org.beangle.security.authc.Authenticator
import org.beangle.security.web.session.SessionIdPolicy
import org.beangle.security.mgt.SecurityManager
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.beangle.security.web.authc.WebClient

class WebSecurityManager(val authenticator: Authenticator, val authorizer: Authorizer,
                         val sessionRegistry: SessionRegistry, val sessionIdPolicy: SessionIdPolicy)
    extends SecurityManager {

  override def login(sessionId: String, token: AuthenticationToken, client: Session.Client): Session = {
    sessionRegistry.register(sessionId, authenticator.authenticate(token), client)
  }

  def login(request: HttpServletRequest, response: HttpServletResponse, token: AuthenticationToken): Session = {
    val key = sessionIdPolicy.newId(request, response)
    sessionRegistry.register(key, authenticator.authenticate(token), WebClient.get(request))
  }

  def logout(request: HttpServletRequest, response: HttpServletResponse,
             session: Session): Unit = {
    session.stop()
    sessionIdPolicy.delId(request, response)
    val s = request.getSession(false)
    if (null != s) s.invalidate()
  }

}
