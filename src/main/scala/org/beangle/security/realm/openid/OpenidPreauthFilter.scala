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
import org.beangle.commons.bean.Initializing
import org.beangle.commons.lang.Strings
import org.beangle.commons.net.http.HttpUtils
import org.beangle.security.authc.PreauthToken
import org.beangle.security.web.WebSecurityManager
import org.beangle.security.web.authc.AbstractPreauthFilter

/** 使用openid进行远程查询
 *
 * @param securityManager
 */
class OpenidPreauthFilter(securityManager: WebSecurityManager) extends AbstractPreauthFilter(securityManager), Initializing {
  var serviceUrl: String = _

  override def init(): Unit = {
    super.init()
  }

  override protected def getCredential(req: HttpServletRequest): Option[Any] = {
    val p = req.getParameter("openid")
    if Strings.isNotEmpty(p) then Some(p.trim) else None
  }

  override protected def resolveToken(req: HttpServletRequest, res: HttpServletResponse, credential: Any): Option[PreauthToken] = {
    var url = serviceUrl
    url = Strings.replace(url, "{openid}", credential.toString)
    val rs = HttpUtils.getText(url).getText.trim
    if Strings.isBlank(rs) then None
    else Some(new PreauthToken(rs, credential))
  }
}
