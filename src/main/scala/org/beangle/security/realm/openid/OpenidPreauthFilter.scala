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

package org.beangle.security.realm.openid

import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.lang.Strings
import org.beangle.commons.net.http.HttpUtils
import org.beangle.security.authc.PreauthToken
import org.beangle.security.web.WebSecurityManager
import org.beangle.security.web.authc.AbstractPreauthFilter

/** 使用openid进行远程查询
 *
 * @param securityManager
 */
class OpenidPreauthFilter(securityManager: WebSecurityManager) extends AbstractPreauthFilter(securityManager) {
  var serviceUrl: String = _

  override protected def getCredential(req: HttpServletRequest): Option[Any] = {
    val p = req.getParameter("openid")
    val u = req.getParameter("username")
    if Strings.isNotEmpty(p) && Strings.isNotBlank(u) then Some(p.trim) else None
  }

  override protected def resolveToken(req: HttpServletRequest, res: HttpServletResponse, credential: Any): Option[PreauthToken] = {
    val username = req.getParameter("username")
    var url = serviceUrl
    url = Strings.replace(url, "{openid}", credential.toString)
    url = Strings.replace(url, "{username}", username)
    val rs = HttpUtils.getText(url).getText.trim
    if Strings.isBlank(rs) && rs != "true" then None
    else Some(new PreauthToken(username, credential))
  }
}
