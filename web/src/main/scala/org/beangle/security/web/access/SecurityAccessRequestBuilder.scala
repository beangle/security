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
package org.beangle.security.web.access

import org.beangle.commons.web.access.DefaultAccessRequestBuilder
import org.beangle.security.session.{ SessionId, SessionRegistry }
import javax.servlet.http.HttpServletRequest
import org.beangle.security.web.session.SessionIdPolicy

/**
 * Security access request
 *
 * @author chaostone
 * @since 3.0.1
 */
class SecurityAccessRequestBuilder(val registry: SessionRegistry) extends DefaultAccessRequestBuilder {

  var sessionIdPolicy: SessionIdPolicy = _

  protected override def abtainUsername(request: HttpServletRequest): String = {
    val session = request.getSession(false)
    if (null == session) null
    else {
      registry.get(sessionIdPolicy.getSessionId(request)) match {
        case Some(s) => s.principal.getName
        case None => null
      }
    }
  }

}
