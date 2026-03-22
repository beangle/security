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

package org.beangle.security.web.session

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.json.Json
import org.beangle.commons.lang.Strings
import org.beangle.security.SecurityLogger
import org.beangle.security.realm.jwt.{Claims, JwtDigest}
import org.beangle.web.servlet.util.CookieUtils

import java.time.Instant

class CookieSessionIdReader(val idName: String) extends SessionIdReader {

  override def getId(request: HttpServletRequest, response: HttpServletResponse): Option[String] = {
    var psid = request.getParameter(idName)

    if (Strings.isEmpty(psid)) {
      val header = request.getHeader("Authorization")
      if (Strings.isNotEmpty(header)) {
        if (header.startsWith("Bearer ")) {
          psid = header.substring("Bearer ".length)
        } else {
          psid = header
        }
      }
    }

    if (Strings.isEmpty(psid)) {
      psid = CookieUtils.getCookieValue(request, idName)
    }
    psid = Strings.trim(psid)
    if (Strings.isEmpty(psid)) {
      None
    } else {
      val dotIdx = psid.indexOf('.')
      //without dot or only last dot
      if (dotIdx < 0 || dotIdx == psid.length - 1) {
        Some(psid)
      } else {
        val dot2Idx = psid.indexOf('.', dotIdx + 1)
        if (dot2Idx < 0) {
          Some(psid)
        } else {
          try {
            val claims = Json.parseObject(JwtDigest.urlDecode(psid.substring(dotIdx + 1, dot2Idx)))
            val exp = claims.getInt(Claims.Exp, 0)
            if (exp == 0 || exp < Instant.now.getEpochSecond) {
              None
            } else {
              Option(claims.getString(Claims.JTI, null))
            }
          } catch {
            case e: Exception =>
              SecurityLogger.error("parsing json failed", e)
              None
          }
        }
      }
    }
  }

}
