/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
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
