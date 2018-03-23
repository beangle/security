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
package org.beangle.security.web

import org.beangle.security.authc.{ AuthenticationToken, Authenticator }
import org.beangle.security.authz.Authorizer
import org.beangle.security.mgt.SecurityManager
import org.beangle.security.session.{ Session, SessionRegistry }
import org.beangle.security.web.authc.WebClient
import org.beangle.security.web.session.SessionIdPolicy

import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

class WebSecurityManager(val authenticator: Authenticator, val authorizer: Authorizer,
  val registry: SessionRegistry, val sessionIdPolicy: SessionIdPolicy)
  extends SecurityManager {

  override def login(sessionId: String, token: AuthenticationToken, client: Session.Agent): Session = {
    registry.register(sessionId, authenticator.authenticate(token), client)
  }

  def login(request: HttpServletRequest, response: HttpServletResponse, token: AuthenticationToken): Session = {
    val key = sessionIdPolicy.newId(request, response)
    registry.register(key, authenticator.authenticate(token), WebClient.get(request))
  }

  def logout(request: HttpServletRequest, response: HttpServletResponse,
    session: Session): Unit = {
    registry.remove(session.id)
    sessionIdPolicy.delId(request, response)
    val s = request.getSession(false)
    if (null != s) s.invalidate()
  }

}
