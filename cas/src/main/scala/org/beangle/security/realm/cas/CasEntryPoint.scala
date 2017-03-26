/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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
package org.beangle.security.realm.cas

import java.net.URLEncoder

import org.beangle.commons.lang.Strings
import org.beangle.security.authc.{ AccountStatusException, AuthenticationException, UsernameNotFoundException }
import org.beangle.security.session.SessionException
import org.beangle.security.web.EntryPoint

import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }
import org.beangle.security.web.session.SessionIdPolicy

object CasEntryPoint {

  def constructServiceUrl(req: HttpServletRequest, res: HttpServletResponse, service: String, serverName: String, ticketName: String): String = {
    if (Strings.isNotBlank(service)) return res.encodeURL(service)

    val buffer = new StringBuilder()
    if (!serverName.startsWith("https://") && !serverName.startsWith("http://"))
      buffer.append(if (req.isSecure) "https://" else "http://")

    buffer.append(serverName).append(req.getRequestURI)
    if (Strings.isNotBlank(req.getQueryString)) {
      val location = req.getQueryString.indexOf(ticketName + "=")
      if (location != 0) {
        buffer.append("?")
        if (location == -1) {
          buffer.append(req.getQueryString)
        } else if (location > 0) {
          val actualLocation = req.getQueryString().indexOf("&" + ticketName + "=")
          if (actualLocation == -1) buffer.append(req.getQueryString)
          else if (actualLocation > 0) buffer.append(req.getQueryString().substring(0, actualLocation))
        }
      }
    }
    res.encodeURL(buffer.toString)
  }
}

class CasEntryPoint(val config: CasConfig) extends EntryPoint {
  import CasConfig._
  import CasEntryPoint._
  /** 本地登录地址 */
  var localLogin: String = _
  var sessionIdPolicy: SessionIdPolicy = _

  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    if (null != ae && (ae.isInstanceOf[UsernameNotFoundException] || ae.isInstanceOf[AccountStatusException] || ae.isInstanceOf[SessionException])) {
      res.getWriter().append(String.valueOf(ae.principal.toString)).append(ae.getMessage())
    } else {
      if (null != localLogin) {
        // 防止在localLogin也不是公开资源的错误配置情况下，出现CasEntryPoint和CasServer之间的死循环
        if (req.getServletPath().endsWith(localLogin)) {
          throw ae
        } else {
          val serviceUrl = constructLocalLoginUrl(req, res, null, getLocalServer(req))
          val redirectUrl = constructLoginUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
          res.sendRedirect(redirectUrl + "&isLoginService=11")
        }
      } else {
        val serviceUrl = constructServiceUrl(req, res, null, getLocalServer(req), config.artifactName)
        val redirectUrl = constructLoginUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
        res.sendRedirect(redirectUrl)
      }
    }
  }

  def constructLocalLoginUrl(req: HttpServletRequest, res: HttpServletResponse, service: String, serverName: String): String = {
    if (Strings.isNotBlank(service)) {
      res.encodeURL(service)
    } else {
      val buffer = new StringBuilder()
      if (!serverName.startsWith("https://") && !serverName.startsWith("http://"))
        buffer.append(if (req.isSecure) "https://" else "http://")
      buffer.append(serverName).append(req.getContextPath).append(localLogin)
      res.encodeURL(buffer.toString)
    }
  }
  /**
   * Constructs the URL to use to redirect to the CAS server.
   */
  def constructLoginUrl(loginUrl: String, serviceName: String, serviceUrl: String, renew: Boolean, gateway: Boolean): String = {
    loginUrl + (if (loginUrl.indexOf("?") != -1) "&" else "?") + serviceName + "=" + URLEncoder.encode(serviceUrl, "UTF-8") +
      (if (renew) "&renew=true" else "") + (if (gateway) "&gateway=true" else "") +
      "&" + SessionIdPolicy.SessionIdName + "=" + sessionIdPolicy.idName
  }
}
