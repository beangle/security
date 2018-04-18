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
package org.beangle.security.realm.cas

import java.net.URLEncoder
import java.util.Arrays

import org.beangle.commons.lang.Strings
import org.beangle.security.authc.{ AccountStatusException, AuthenticationException, UsernameNotFoundException }
import org.beangle.security.session.SessionException
import org.beangle.security.web.EntryPoint
import org.beangle.security.web.session.SessionIdReader

import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

class CasEntryPoint(val config: CasConfig) extends EntryPoint {
  import CasConfig._
  /** 本地登录地址 */
  var localLogin: String = _
  var sessionIdReader: SessionIdReader = _

  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    Cas.cleanup(config, req, res)
    if (null != ae && (ae.isInstanceOf[UsernameNotFoundException] || ae.isInstanceOf[AccountStatusException]
      || ae.isInstanceOf[SessionException])) {
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
        val serviceUrl = constructServiceUrl(req, res, null, getLocalServer(req))
        val redirectUrl = constructLoginUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
        res.sendRedirect(redirectUrl)
      }
    }
  }

  def constructLocalLoginUrl(req: HttpServletRequest, res: HttpServletResponse,
    service: String, serverName: String): String = {
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
  def constructLoginUrl(loginUrl: String, serviceName: String, serviceUrl: String,
    renew: Boolean, gateway: Boolean): String = {
    loginUrl + (if (loginUrl.indexOf("?") != -1) "&" else "?") +
      (serviceName + "=" + URLEncoder.encode(serviceUrl, "UTF-8")) +
      (if (renew) "&renew=true" else "") + (if (gateway) "&gateway=true" else "") +
      (if (null != sessionIdReader) "&" + SessionIdReader.SessionIdName + "=" + sessionIdReader.idName else "")
  }

  def constructServiceUrl(req: HttpServletRequest, res: HttpServletResponse,
    service: String, serverName: String): String = {
    if (Strings.isNotBlank(service)) return res.encodeURL(service)

    val buffer = new StringBuilder()
    if (!serverName.startsWith("https://") && !serverName.startsWith("http://")) {
      buffer.append(if (req.isSecure) "https://" else "http://")
    }

    val reservedKeys =
      if (null == sessionIdReader) { Set(config.artifactName) }
      else { Set(sessionIdReader.idName, config.artifactName) }
    buffer.append(serverName).append(req.getRequestURI)
    val queryString = req.getQueryString
    if (Strings.isNotBlank(queryString)) {
      val parts = Strings.split(queryString, '&')
      //这里的排序，保证请求和验证的使用的service是一样的
      Arrays.sort(parts.asInstanceOf[Array[AnyRef]])
      val paramBuf = new StringBuilder
      parts foreach { part =>
        val equIdx = part.indexOf('=')
        if (equIdx > 0) {
          val key = part.substring(0, equIdx)
          if (!reservedKeys.contains(key)) {
            paramBuf.append("&").append(key).append(part.substring(equIdx))
          }
        }
      }
      if (!paramBuf.isEmpty) {
        paramBuf.setCharAt(0, '?')
        buffer.append(paramBuf)
      }
    }
    res.encodeURL(buffer.toString)
  }
}
