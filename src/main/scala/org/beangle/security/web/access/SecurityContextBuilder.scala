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

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.json.{Json, JsonArray}
import org.beangle.security.authc.Profile
import org.beangle.security.context.{RunAs, SecurityContext}
import org.beangle.security.session.{Session, SessionRepo}
import org.beangle.security.web.CookieKeys
import org.beangle.security.web.session.SessionIdReader
import org.beangle.web.servlet.security.RequestConvertor
import org.beangle.web.servlet.util.CookieUtils

import java.time.Instant

trait SecurityContextBuilder {

  def find(request: HttpServletRequest, response: HttpServletResponse): SecurityContext

  def build(request: HttpServletRequest, session: Option[Session]): SecurityContext

}

class DefaultSecurityContextBuilder extends SecurityContextBuilder {
  var requestConvertor: RequestConvertor = _

  var repo: SessionRepo = _
  var sessionIdReader: SessionIdReader = _

  def find(request: HttpServletRequest, response: HttpServletResponse): SecurityContext = {
    val session =
      sessionIdReader.getId(request, response) match {
        case Some(sid) => repo.access(sid, Instant.now)
        case None => None
      }
    build(request, session)
  }

  def build(request: HttpServletRequest, session: Option[Session]): SecurityContext = {
    var runAs: Option[RunAs] = None
    var profile: Option[Profile] = None
    session foreach { s =>
      if (s.principal.isRoot) {
        val runAsJson = CookieUtils.getCookieValue(request, CookieKeys.RunAsKey)
        if (null != runAsJson) {
          runAs = RunAs.parseJson(runAsJson)
        }
      }

      // 切换 profile 的当次请求：URL contextProfileId 优先于 cookie
      val profileId = {
        val fromParam = request.getParameter("contextProfileId")
        if (null != fromParam && fromParam.nonEmpty) fromParam
        else CookieUtils.getCookieValue(request, CookieKeys.ProfileIdKey)
      }
      if (null != profileId && profileId.nonEmpty) {
        runAs match {
          case None => profile = Option(s.principal.profiles).flatMap(_.find(_.id.toString == profileId))
          case Some(rs) => profile = rs.profiles.find(_.id.toString == profileId)
        }
      }
    }
    new SecurityContext(session, requestConvertor.convert(request), profile, runAs.map(_.name))
  }
}
