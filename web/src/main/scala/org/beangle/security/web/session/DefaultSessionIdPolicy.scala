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