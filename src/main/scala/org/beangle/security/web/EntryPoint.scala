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

package org.beangle.security.web

import jakarta.servlet.ServletException
import jakarta.servlet.http.{HttpServletRequest, HttpServletResponse}
import org.beangle.commons.activation.MediaTypes
import org.beangle.commons.json.{JsonArray, JsonObject}
import org.beangle.commons.lang.Strings
import org.beangle.security.authc.AuthenticationException
import org.beangle.web.servlet.http.accept.{ContentNegotiationManager, ContentNegotiationManagerFactory}
import org.beangle.web.servlet.url.UrlBuilder
import org.beangle.web.servlet.util.RedirectUtils

import java.io.IOException

trait EntryPoint {

  def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean

  def remoteLogin(request: HttpServletRequest, response: HttpServletResponse): Unit

  @throws(classOf[IOException])
  @throws(classOf[ServletException])
  def commence(request: HttpServletRequest, response: HttpServletResponse, ae: AuthenticationException): Unit
}

abstract class ContentNegotiationEntryPoint extends EntryPoint {
  private val contentNegotiationManager: ContentNegotiationManager = buildContentNegotiationManagerFactory()

  protected def isJsonRequest(req: HttpServletRequest): Boolean = {
    contentNegotiationManager.resolve(req).exists(x => x == MediaTypes.json || x == MediaTypes.jsonApi)
  }

  protected def responseAsJson(loginUrl: Option[String], req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    val error = new JsonObject()
    error.add("status", 401)
    error.add("title", if null == ae then "Unauthorized" else ae.getMessage)
    loginUrl foreach { url =>
      val meta = new JsonObject()
      meta.add("redirectUrl", loginUrl)
      error.add("meta", meta)
    }
    val rs = JsonObject("errors" -> JsonArray(error))
    res.setStatus(401)
    res.setContentType("application/json; charset=utf-8")
    res.getWriter.write(rs.toString)
  }

  private def buildContentNegotiationManagerFactory(): ContentNegotiationManager = {
    val factory = new ContentNegotiationManagerFactory
    factory.favorPathExtension = true
    factory.favorParameter = true
    factory.parameterName = "format"
    factory.ignoreAcceptHeader = false
    factory.init()
    factory.getObject
  }
}

class UrlEntryPoint(val url: String) extends ContentNegotiationEntryPoint {

  /** Performs the redirect (or forward) to the login form URL. */
  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    val failOnLogin = req.getRequestURI == Strings.replace(req.getContextPath + url, "//", "/")
    if (failOnLogin) {
      res.getWriter.println(ae.getMessage)
    } else {
      // redirect to login page. Use https if forceHttps true
      val url = determineUrl(req, ae)
      if (isJsonRequest(req)) {
        responseAsJson(Some(url), req, res, ae)
      } else {
        RedirectUtils.sendRedirect(req, res, url)
      }
    }
  }

  /**
   * Allows subclasses to modify the login form URL that should be applicable
   * for a given request.
   */
  protected def determineUrl(req: HttpServletRequest, ae: AuthenticationException): String = {
    if (url.contains("${goto}")) Strings.replace(url, "${goto}", UrlBuilder.url(req))
    else url
  }

  override def isLocalLogin(req: HttpServletRequest, ae: AuthenticationException): Boolean = {
    true
  }

  override def remoteLogin(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    throw new org.beangle.security.SecurityException("UrlEntryPoint doesn't support remoteLogin", null)
  }
}
