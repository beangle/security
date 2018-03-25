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
package org.beangle.security.web.access

import java.time.Instant

import org.beangle.commons.web.security.RequestConvertor
import org.beangle.commons.web.util.CookieUtils
import org.beangle.security.authz.Authorizer
import org.beangle.security.context.SecurityContext
import org.beangle.security.session.SessionRepo
import org.beangle.security.web.session.SessionIdReader

import javax.servlet.http.HttpServletRequest
import org.beangle.security.session.Session

trait SecurityContextBuilder {

  def find(request: HttpServletRequest): SecurityContext

  def build(request: HttpServletRequest, session: Option[Session]): SecurityContext
}

class DefaultSecurityContextBuilder extends SecurityContextBuilder {
  var authorizer: Authorizer = _
  var requestConvertor: RequestConvertor = _

  var repo: SessionRepo = _
  var sessionIdReader: SessionIdReader = _

  def find(request: HttpServletRequest): SecurityContext = {
    val session =
      sessionIdReader.getId(request) match {
        case Some(sid) => repo.access(sid, Instant.now)
        case None      => None
      }
    build(request, session)
  }

  def build(request: HttpServletRequest, session: Option[Session]): SecurityContext = {
    var isRoot = false;
    session foreach { s =>
      isRoot = authorizer.isRoot(s.principal.getName)
    }
    var runAs: String = null
    if (isRoot) {
      runAs = CookieUtils.getCookieValue(request, "beangle.security.runAs")
    }
    new SecurityContext(session, requestConvertor.convert(request), isRoot, Option(runAs))
  }
}
