/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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
package org.beangle.security.web.authc

import java.util.Date
import org.beangle.commons.codec.digest.Digests
import org.beangle.commons.lang.{ Objects, Strings }
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.filter.GenericHttpFilter
import org.beangle.commons.web.util.RequestUtils
import org.beangle.security.authc.{ AbstractAccountRealm, Account, AccountStore, AuthenticationException, AuthenticationToken }
import org.beangle.security.context.SecurityContext
import org.beangle.security.mgt.SecurityManager
import org.beangle.security.session.Session
import org.beangle.security.web.session.{ DefaultSessionIdPolicy, SessionIdPolicy }
import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

object PreauthToken {
  val TokenName = "preauth_token"
}

/**
 * Preauth Authentication Token
 */
class PreauthToken(val principal: Any, tokenstr: String) extends AuthenticationToken {

  var details: Map[String, Any] = Map.empty

  details += PreauthToken.TokenName -> tokenstr

  def token: String = {
    details(PreauthToken.TokenName).toString
  }

  override def credentials: Any = null

  override def trusted: Boolean = {
    true
  }

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: PreauthToken =>
        Objects.equalsBuilder.add(principal, test.principal)
          .add(details, test.details)
          .isEquals
      case _ => false
    }
  }
}

case class PreauthUser(val name: String, token: String)

abstract class AbstractPreauthFilter(val securityManager: SecurityManager) extends GenericHttpFilter with Logging {

  var sessionIdPolicy: SessionIdPolicy = new DefaultSessionIdPolicy
  /**
   * Try to authenticate a pre-authenticated user if the
   * user has not yet been authenticated.
   */
  override final def doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain): Unit = {
    val request = req.asInstanceOf[HttpServletRequest]
    val response = res.asInstanceOf[HttpServletResponse]
    requiresAuthentication(request, response) foreach { token =>
      doAuthenticate(token, request, response)
    }
    chain.doFilter(req, res)
  }

  /** Do the actual authentication for a pre-authenticated user. */
  private def doAuthenticate(token: PreauthToken, request: HttpServletRequest, response: HttpServletResponse): Unit = {
    token.details ++= WebDetails.get(request)
    try {
      val session = securityManager.login(sessionIdPolicy.getSessionId(request), token)
      SecurityContext.session = session
      val httpSession = request.getSession(false)
      if (null != httpSession) httpSession.setMaxInactiveInterval(session.timeout)
    } catch {
      case failed: AuthenticationException => unsuccessfulAuthentication(request, response, failed)
      case e: Throwable                    => throw e
    }
  }

  protected def getTokenStr(req: HttpServletRequest): Option[String]

  protected def resovleToken(req: HttpServletRequest, res: HttpServletResponse, tokenStr: String): Option[PreauthToken]

  protected def requiresAuthentication(req: HttpServletRequest, res: HttpServletResponse): Option[PreauthToken] = {
    getTokenStr(req) match {
      case None => None
      case Some(newer) =>
        SecurityContext.getSession match {
          case None => resovleToken(req, res, newer)
          case Some(s) =>
            //FIXME account details donot contain token_name
            s.principal.details.get(PreauthToken.TokenName) match {
              case Some(token) =>
                if (newer == token) None else resovleToken(req, res, newer)
              case None => resovleToken(req, res, newer)
            }
        }
    }
  }

  /**
   * Puts the <code>Authentication</code> instance returned by the
   * authentication manager into the secure context.
   */
  protected def successfulAuthentication(request: HttpServletRequest, response: HttpServletResponse,
    session: Session): Unit = {
    logger.debug(s"PreAuthentication success: $session")
    SecurityContext.session = session
  }

  /**
   * Ensures the authentication object in the secure context is set to null when authentication
   * fails.
   * If username not found or account status exception.just let other know by throw it.
   * It will be handled by ExceptionTranslationFilter
   */
  protected def unsuccessfulAuthentication(req: HttpServletRequest, res: HttpServletResponse, failed: AuthenticationException) {
    logger.debug("Cleared security context due to exception", failed)
    SecurityContext.session = null
    if (null != failed) throw failed
  }
}

class UsernamePreauthFilter(securityManager: SecurityManager) extends AbstractPreauthFilter(securityManager) {
  var usernameSource: UsernameSource = _

  protected override def resovleToken(req: HttpServletRequest, res: HttpServletResponse, tokenStr: String): Option[PreauthToken] = {
    usernameSource.resolveUser(req, tokenStr) match {
      case Some(u) => if (Strings.isNotBlank(u.name)) Some(new PreauthToken(u.name, u.token)) else None
      case None    => None
    }
  }

  protected override def getTokenStr(request: HttpServletRequest): Option[String] = {
    usernameSource.getTokenStr(request)
  }
}
