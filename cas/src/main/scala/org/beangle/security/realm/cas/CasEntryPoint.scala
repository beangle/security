package org.beangle.security.realm.cas

import org.beangle.security.web.EntryPoint
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import org.beangle.commons.lang.Strings
import org.beangle.security.authc.UsernameNotFoundException
import javax.servlet.ServletResponse
import org.beangle.security.authc.AccountStatusException
import javax.servlet.ServletRequest
import org.beangle.security.authc.AuthenticationException
import java.net.URLEncoder

object CasEntryPoint {
  def constructServiceUrl(request: HttpServletRequest, response: HttpServletResponse, service: String, serverName: String,
    artifactParameterName: String, encode: Boolean): String = {
    if (Strings.isNotBlank(service)) return if (encode) response.encodeURL(service) else service

    val buffer = new StringBuilder()
    if (!serverName.startsWith("https://") && !serverName.startsWith("http://")) {
      buffer.append(if (request.isSecure()) "https://" else "http://")
    }

    buffer.append(serverName)
    buffer.append(request.getRequestURI())
    if (Strings.isNotBlank(request.getQueryString())) {
      val location = request.getQueryString().indexOf(artifactParameterName + "=")
      if (location == 0) {
        val returnValue = if (encode) response.encodeURL(buffer.toString()) else buffer.toString()
        return returnValue
      }
      buffer.append("?")
      if (location == -1) {
        buffer.append(request.getQueryString())
      } else if (location > 0) {
        val actualLocation = request.getQueryString().indexOf("&" + artifactParameterName + "=")
        if (actualLocation == -1) buffer.append(request.getQueryString())
        else if (actualLocation > 0) buffer.append(request.getQueryString().substring(0, actualLocation))
      }
    }
    return if (encode) response.encodeURL(buffer.toString()) else buffer.toString
  }
}

class CasEntryPoint extends EntryPoint {
  import CasEntryPoint._
  import CasConfig._
  var config: CasConfig = _
  /** 本地登录地址 */
  var localLogin: String = _

  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    if (null != ae && (ae.isInstanceOf[UsernameNotFoundException] || ae.isInstanceOf[AccountStatusException])) {
      res.getWriter().append(String.valueOf(ae.principal.toString)).append(ae.getMessage())
    } else {
      if (null != localLogin) {
        // 防止在localLogin也不是公开资源的错误配置情况下，出现CasEntryPoint和CasServer之间的死循环
        if (req.getServletPath().endsWith(localLogin)) {
          throw ae
        } else {
          val serviceUrl = constructLocalLoginServiceUrl(req, res, null, getLocalServer(req), config.artifactName, config.encode)
          val redirectUrl = constructRedirectUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
          res.sendRedirect(redirectUrl + "&isLoginService=11")
        }
      } else {
        val serviceUrl = constructServiceUrl(req, res, null,
          getLocalServer(req), config.artifactName, config.encode)
        val redirectUrl = constructRedirectUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
        res.sendRedirect(redirectUrl)
      }
    }
  }

  def constructLocalLoginServiceUrl(request: HttpServletRequest, response: HttpServletResponse, service: String, serverName: String,
    artifactParameterName: String, encode: Boolean): String = {
    if (Strings.isNotBlank(service)) return if (encode) response.encodeURL(service) else service
    val buffer = new StringBuilder()
    if (!serverName.startsWith("https://") && !serverName.startsWith("http://"))
      buffer.append(if (request.isSecure) "https://" else "http://")
    buffer.append(serverName)
    buffer.append(request.getContextPath())
    buffer.append(localLogin)
    if (encode) response.encodeURL(buffer.toString) else buffer.toString
  }
  /**
   * Constructs the URL to use to redirect to the CAS server.
   */
  def constructRedirectUrl(casServerLoginUrl: String, serviceParameterName: String,
    serviceUrl: String, renew: Boolean, gateway: Boolean): String = {
    casServerLoginUrl + (if (casServerLoginUrl.indexOf("?") != -1) "&" else "?") + serviceParameterName +
      "=" + URLEncoder.encode(serviceUrl, "UTF-8") + (if (renew) "&renew=true" else "") +
      (if (gateway) "&gateway=true" else "")
  }
}