/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.web.access

import java.time.Instant

import org.beangle.web.servlet.security.RequestConvertor
import org.beangle.web.servlet.util.CookieUtils
import org.beangle.security.authz.Authorizer
import org.beangle.security.context.SecurityContext
import org.beangle.security.session.{ Session, SessionRepo }
import org.beangle.security.web.session.SessionIdReader

import jakarta.servlet.http.{ HttpServletRequest, HttpServletResponse }

trait SecurityContextBuilder {

  def find(request: HttpServletRequest, response: HttpServletResponse): SecurityContext

  def build(request: HttpServletRequest, session: Option[Session]): SecurityContext

}

class DefaultSecurityContextBuilder extends SecurityContextBuilder {
  var authorizer: Authorizer = _
  var requestConvertor: RequestConvertor = _

  var repo: SessionRepo = _
  var sessionIdReader: SessionIdReader = _

  def find(request: HttpServletRequest, response: HttpServletResponse): SecurityContext = {
    val session =
      sessionIdReader.getId(request, response) match {
        case Some(sid) => repo.access(sid, Instant.now)
        case None      => None
      }
    build(request, session)
  }

  def build(request: HttpServletRequest, session: Option[Session]): SecurityContext = {
    var isRoot = false
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
