package org.beangle.security.web.session

import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.beangle.commons.web.util.CookieUtils
import org.beangle.commons.web.util.CookieGenerator
import org.beangle.commons.lang.annotation.value
import java.net.URLEncoder
import javax.servlet.http.Cookie
import org.beangle.commons.bean.Initializing
import org.beangle.commons.web.context.ServletContextHolder

/**
 * @author chaostone
 */
abstract class CookieSessionIdPolicy(cookieName: String) extends CookieGenerator(cookieName) with SessionIdPolicy with Initializing {

  override def getSessionId(request: HttpServletRequest): String = {
    val sid = CookieUtils.getCookieValue(request, cookieName)
    if (null == sid) null else sid
  }

  override def newSessionId(request: HttpServletRequest, response: HttpServletResponse): String = {
    val newid = newId(request)
    addCookie(response, newid)
    newid
  }

  def init(): Unit = {
    if (null == path) {
      val contextPath = ServletContextHolder.context.getContextPath
      path = if (!contextPath.endsWith("/")) contextPath + "/" else contextPath
    }
  }

  override def delSessionId(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    removeCookie(response)
  }

  protected def newId(request: HttpServletRequest): String
}