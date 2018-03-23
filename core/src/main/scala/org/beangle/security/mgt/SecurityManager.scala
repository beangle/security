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
package org.beangle.security.mgt

import org.beangle.commons.security.Request
import org.beangle.security.authc.{ AuthenticationToken, Authenticator }
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.{ Session, SessionRegistry }

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def registry: SessionRegistry

  def isPermitted(session: Option[Session], request: Request): Boolean = {
    authorizer.isPermitted(session, request)
  }

  //@throw(classOfAuthenticationException])
  def login(sessionId: String, token: AuthenticationToken, client: Session.Agent): Session

  def logout(session: Session): Unit = {
    this.registry.remove(session.id)
  }
}
