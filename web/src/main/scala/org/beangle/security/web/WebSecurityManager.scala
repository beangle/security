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

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.web.security.RequestConvertor
import org.beangle.security.authc._
import org.beangle.security.authz.Authorizer
import org.beangle.security.mgt.SecurityManager
import org.beangle.security.session.{Session, SessionProfileProvider, SessionRegistry}
import org.beangle.security.web.authc.WebClient
import org.beangle.security.web.session.SessionIdPolicy

class WebSecurityManager extends SecurityManager {

  var authenticator: Authenticator = _
  var authorizer: Authorizer = _
  var registry: SessionRegistry = _
  var sessionIdPolicy: SessionIdPolicy = _
  var requestConvertor: RequestConvertor = _
  var sessionProfileProvider: SessionProfileProvider = _

  override def login(sessionId: String, token: AuthenticationToken, client: Session.Agent): Session = {
    val account = authc(token)
    val profile = sessionProfileProvider.getProfile(account)
    registry.register(sessionId, account, client, profile)
  }

  def login(request: HttpServletRequest, response: HttpServletResponse, token: AuthenticationToken): Session = {
    val key = sessionIdPolicy.newId(request, response)
    val account = authc(token)
    val profile = sessionProfileProvider.getProfile(account)
    registry.register(key, account, WebClient.get(request), profile)
  }

  /** 认证token，并负责将detail传递给最终的account
   *
   * @param token
   * @return
   */
  private def authc(token: AuthenticationToken): Account = {
    val account = authenticator.authenticate(token)
    account match {
      case da: DefaultAccount =>
        da.credentialReadOnly = isCredentialReadOnly(token)
        da.details ++= token.details
      case _ =>
    }
    account
  }

  private def isCredentialReadOnly(token: AuthenticationToken): Boolean = {
    token match {
      case _: PreauthToken => true
      case _ =>
        val a = token.removeDetail("credentialReadOnly")
        a.contains("true") || a.contains(true)
    }
  }

  def logout(request: HttpServletRequest, response: HttpServletResponse, session: Session): Unit = {
    registry.remove(session.id, null)
    sessionIdPolicy.delId(request, response)
    val s = request.getSession(false)
    if (null != s) s.invalidate()
  }

}
