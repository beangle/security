package org.beangle.security.realm.cas

import java.net.URLEncoder
import org.beangle.commons.lang.Strings
import org.beangle.security.authc.{ AbstractAccountRealm, Account, AccountStatusException, AccountStore, AuthenticationException, AuthenticationToken, BadCredentialsException, UsernameNotFoundException }
import org.beangle.security.mgt.SecurityManager
import org.beangle.security.web.{ AbstractPreauthFilter, EntryPoint, PreauthToken }

import CasConfig.{ getLocalServer, TicketName }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

class CasToken(t: String) extends PreauthToken(t) {

  def ticket: String = principal.toString

  details += CasConfig.TicketName -> principal.toString
}

object CasEntryPoint {

  def constructServiceUrl(req: HttpServletRequest, res: HttpServletResponse, service: String, serverName: String,
    ticketName: String, encode: Boolean): String = {
    if (Strings.isNotBlank(service)) return if (encode) res.encodeURL(service) else service

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
    if (encode) res.encodeURL(buffer.toString()) else buffer.toString
  }
}

class CasEntryPoint(val config: CasConfig) extends EntryPoint {
  import CasEntryPoint._
  import CasConfig._
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
          val serviceUrl = constructLocalLoginUrl(req, res, null, getLocalServer(req), config.encode)
          val redirectUrl = constructLoginUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
          res.sendRedirect(redirectUrl + "&isLoginService=11")
        }
      } else {
        val serviceUrl = constructServiceUrl(req, res, null,
          getLocalServer(req), config.artifactName, config.encode)
        val redirectUrl = constructLoginUrl(config.loginUrl, "service", serviceUrl, config.renew, false)
        res.sendRedirect(redirectUrl)
      }
    }
  }

  def constructLocalLoginUrl(req: HttpServletRequest, res: HttpServletResponse, service: String, serverName: String, encode: Boolean): String = {
    if (Strings.isNotBlank(service)) {
      if (encode) res.encodeURL(service) else service
    } else {
      val buffer = new StringBuilder()
      if (!serverName.startsWith("https://") && !serverName.startsWith("http://"))
        buffer.append(if (req.isSecure) "https://" else "http://")
      buffer.append(serverName).append(req.getContextPath).append(localLogin)
      if (encode) res.encodeURL(buffer.toString) else buffer.toString
    }
  }
  /**
   * Constructs the URL to use to redirect to the CAS server.
   */
  def constructLoginUrl(loginUrl: String, serviceName: String, serviceUrl: String, renew: Boolean, gateway: Boolean): String = {
    loginUrl + (if (loginUrl.indexOf("?") != -1) "&" else "?") + serviceName + "=" + URLEncoder.encode(serviceUrl, "UTF-8") +
      (if (renew) "&renew=true" else "") + (if (gateway) "&gateway=true" else "")
  }
}
/**
 * Processes a CAS service ticket.
 */
class CasPreauthFilter(securityManager: SecurityManager, val config: CasConfig) extends AbstractPreauthFilter(securityManager) {

  protected[cas] override def getPreauthToken(request: HttpServletRequest, response: HttpServletResponse): PreauthToken = {
    val ticket = request.getParameter(CasConfig.TicketName)
    if (ticket == null) {
      null
    } else {
      val url = CasEntryPoint.constructServiceUrl(request, response, null,
        CasConfig.getLocalServer(request), CasConfig.TicketName, config.encode)
      val token = new CasToken(ticket)
      token.details += "url" -> url
      token
    }
  }
}

class DefaultCasRealm(val accountStore: AccountStore, val ticketValidator: TicketValidator) extends AbstractAccountRealm {

  protected override def determinePrincipal(token: AuthenticationToken): String = {
    try {
      val ticket = token.details(TicketName).toString
      val assertion = ticketValidator.validate(ticket, token.details("url").toString)
      assertion.principal
    } catch {
      case e: TicketValidationException => throw new BadCredentialsException("Bad credentials :" + token.details(TicketName), token, e)
    }
  }

  protected override def credentialsCheck(token: AuthenticationToken, account: Account): Unit = {}

  protected override def loadAccount(principal: Any): Option[Account] = accountStore.load(principal)

  override def supports(token: AuthenticationToken): Boolean = token.isInstanceOf[CasToken]
}
