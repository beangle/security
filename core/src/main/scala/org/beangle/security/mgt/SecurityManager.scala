/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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
package org.beangle.security.mgt

import org.beangle.commons.security.Request
import org.beangle.security.authc.{ AuthenticationException, AuthenticationToken, Authenticator }
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.{ Session, SessionKey, SessionRegistry }

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def sessionRegistry: SessionRegistry

  def isPermitted(session: Option[Session], request: Request): Boolean = {
    authorizer.isPermitted(session, request)
  }

  //@throw(classOfAuthenticationException])
  def login(token: AuthenticationToken, key: SessionKey): Session

  def logout(session: Session): Unit = session.stop()
}

class DefaultSecurityManager(val authenticator: Authenticator, val authorizer: Authorizer,
    val sessionRegistry: SessionRegistry) extends SecurityManager {

  def login(token: AuthenticationToken, key: SessionKey): Session = {
    sessionRegistry.register(authenticator.authenticate(token), key)
  }

}