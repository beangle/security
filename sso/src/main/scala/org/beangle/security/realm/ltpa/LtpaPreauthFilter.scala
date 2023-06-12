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

package org.beangle.security.realm.ltpa

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.security.authc.PreauthToken
import org.beangle.security.web.WebSecurityManager
import org.beangle.security.web.authc.AbstractPreauthFilter
import org.beangle.web.servlet.util.CookieUtils

class LtpaPreauthFilter(config: LtpaConfig, ltpaTokenGenerator: LtpaTokenGenerator, securityManager: WebSecurityManager)
  extends AbstractPreauthFilter(securityManager) {

  override protected def getCredential(req: HttpServletRequest): Option[Any] = {
    Option(CookieUtils.getCookieValue(req, config.cookieName))
  }

  override protected def resolveToken(req: HttpServletRequest, res: HttpServletResponse, credential: Any): Option[PreauthToken] = {
    ltpaTokenGenerator.parse(credential.toString) match
      case null => None
      case t: LtpaToken => Some(new PreauthToken(t.username, t.token))
  }
}
