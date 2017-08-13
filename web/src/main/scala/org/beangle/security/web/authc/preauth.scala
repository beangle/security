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
package org.beangle.security.web.authc

import org.beangle.commons.lang.{ Objects, Strings }
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.filter.GenericHttpFilter
import org.beangle.security.authc.{ Account, AuthenticationException, AuthenticationToken, PreauthToken }
import org.beangle.security.context.SecurityContext
import org.beangle.security.session.Session
import org.beangle.security.web.WebSecurityManager

import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

abstract class AbstractPreauthFilter(val securityManager: WebSecurityManager) extends GenericHttpFilter with Logging {

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
    try {
      val newSessionId = securityManager.sessionIdPolicy.newId(request, response)
      val session = securityManager.login(newSessionId, token, WebClient.get(request))
      SecurityContext.session = session
    } catch {
      case failed: AuthenticationException => unsuccessfulAuthentication(request, response, failed)
      case e: Throwable                    => throw e
    }
  }

  protected def getCredentials(req: HttpServletRequest): Option[Any]

  protected def resovleToken(req: HttpServletRequest, res: HttpServletResponse, credentials: Any): Option[PreauthToken]

  protected def requiresAuthentication(req: HttpServletRequest, res: HttpServletResponse): Option[PreauthToken] = {
    getCredentials(req) match {
      case None => None
      case Some(newer) =>
        SecurityContext.getSession match {
          case None => resovleToken(req, res, newer)
          case Some(s) =>
            s.principal.asInstanceOf[Account].remoteToken match {
              case Some(token) => if (newer == token) None else resovleToken(req, res, newer)
              case None        => resovleToken(req, res, newer)
            }
        }
    }
  }

  /**
   * Puts the <code>Authentication</code> instance returned by the
   * authentication manager into the secure context.
   */
  protected def successfulAuthentication(req: HttpServletRequest, res: HttpServletResponse, session: Session): Unit = {
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

class UsernamePreauthFilter(securityManager: WebSecurityManager) extends AbstractPreauthFilter(securityManager) {
  var usernameSource: UsernameSource = _

  protected override def resovleToken(req: HttpServletRequest, res: HttpServletResponse, credentials: Any): Option[PreauthToken] = {
    usernameSource.resolveUser(req, credentials) match {
      case Some(username) => if (Strings.isNotBlank(username)) Some(new PreauthToken(username, credentials)) else None
      case None           => None
    }
  }

  protected override def getCredentials(request: HttpServletRequest): Option[Any] = {
    usernameSource.getCredentials(request)
  }
}
