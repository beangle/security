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
package org.beangle.security.realm.cas

import jakarta.servlet.http.HttpServletRequest
import org.beangle.commons.web.util.CookieUtils
import org.beangle.security.authc.AuthenticationException

trait LocalLoginStrategy {

  def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean

}

class DefaultLocalLoginStrategy extends LocalLoginStrategy {

  var forceLocalParam: String = "local"

  override def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean = {
    null != req.getParameter(forceLocalParam) ||
      null != CookieUtils.getCookieValue(req, "CAS_" + CasConfig.ServiceName)
  }
}
