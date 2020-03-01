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
import java.{util => ju}

import javax.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.lang.Strings
import org.beangle.commons.web.url.UrlBuilder
import org.beangle.commons.web.util.{CookieUtils, RequestUtils}
import org.beangle.security.authc.{AccountStatusException, AuthenticationException, UsernameNotFoundException}
import org.beangle.security.session.SessionException
import org.beangle.security.web.EntryPoint
import org.beangle.security.web.session.SessionIdReader

class CasEntryPoint(val config: CasConfig) extends EntryPoint {

  import CasConfig._

  var localLoginStrategy = new DefaultLocalLoginStrategy

  var sessionIdReader: Option[SessionIdReader] = None

  var allowSessionIdAsParameter: Boolean = true

  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    Cas.cleanup(config, req, res)
    if (null != ae && (ae.isInstanceOf[UsernameNotFoundException] || ae.isInstanceOf[AccountStatusException]
      || ae.isInstanceOf[SessionException])) {
      res.getWriter.append(String.valueOf(ae.principal.toString)).append(ae.getMessage())
    } else {
      if (config.gateway) {
        val localLogin = config.localLoginUri.get
        // 防止在localLogin也不是公开资源的错误配置情况下，出现CasEntryPoint和CasServer之间的死循环
        if (req.getRequestURI.endsWith(localLogin) && null != ae) {
          throw ae
        } else {
          val localUrl = localLoginUrl(req)
          CookieUtils.addCookie(req, res, CasConfig.ServiceName, localUrl, req.getContextPath, 30 * 60)
          res.sendRedirect(casLoginUrl(localUrl))
        }
      } else {
        config.localLoginUri match {
          case None =>
            res.sendRedirect(casLoginUrl(serviceUrl(req)))
          case Some(_) =>
            if (isLocalLogin(req, ae)) {
              res.sendRedirect(localLoginUrl(req))
            } else {
              res.sendRedirect(casLoginUrl(localLoginUrl(req)))
            }
        }
      }
    }
  }

  def localLoginUrl(req: HttpServletRequest): String = {
    val localLogin = config.localLoginUri.get
    val builder = new UrlBuilder(req.getContextPath)
    builder.serverName = req.getServerName
    builder.port = RequestUtils.getServerPort(req)
    builder.scheme = if (RequestUtils.isHttps(req)) "https" else "http"
    builder.servletPath = localLogin

    if (req.getRequestURI.endsWith(localLogin)) {
      builder.queryString = req.getQueryString
    } else {
      var queryString = new StringBuilder()
      if (Strings.isNotBlank(queryString)) {
        queryString ++= req.getQueryString
        queryString ++= "&"
      }
      queryString ++= "service="
      queryString ++= URLEncoder.encode(serviceUrl(req), "UTF-8")
      builder.queryString = queryString.mkString
    }
    builder.buildUrl()
  }

  /**
    * Constructs the URL to use to redirect to the CAS server.
    */
  def casLoginUrl(service: String): String = {
    val loginUrl = config.loginUrl
    val sb = new StringBuilder(loginUrl)
    sb.append(if (loginUrl.indexOf("?") != -1) "&" else "?")
    sb.append(CasConfig.ServiceName + "=" + URLEncoder.encode(service, "UTF-8"))
    sb.append(if (config.gateway) "&gateway=true" else "")
    if (allowSessionIdAsParameter) {
      sessionIdReader.foreach { x =>
        sb.append("&" + SessionIdReader.SessionIdName + "=" + x.idName)
      }
    }
    sb.toString
  }

  def serviceUrl(req: HttpServletRequest): String = {
    val buffer = new StringBuilder()
    val serverName = getLocalServer(req)
    val reservedKeys = sessionIdReader match {
      case None => Set(CasConfig.TicketName)
      case Some(r) => Set(r.idName, CasConfig.TicketName)
    }
    buffer.append(serverName).append(req.getRequestURI)
    val queryString = req.getQueryString
    if (Strings.isNotBlank(queryString)) {
      val parts = Strings.split(queryString, '&')
      //这里的排序，保证请求和验证的使用的service是一样的
      ju.Arrays.sort(parts.asInstanceOf[Array[AnyRef]])
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
      if (paramBuf.nonEmpty) {
        paramBuf.setCharAt(0, '?')
        buffer.append(paramBuf)
      }
    }
    buffer.toString
  }

  override def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean = {
    localLoginStrategy.isLocalLogin(req, ae)
  }

  override def remoteLogin(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    val localUrl = this.localLoginUrl(request)
    CookieUtils.addCookie(request, response, "CAS_" + CasConfig.ServiceName, localUrl, request.getContextPath, 1 * 60)
    response.sendRedirect(this.casLoginUrl(localUrl))
  }
}
