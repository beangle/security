package org.beangle.security.web

import org.beangle.commons.web.filter.GenericHttpFilter
import javax.servlet.http.HttpServletRequest
import javax.servlet.ServletResponse
import javax.servlet.FilterChain
import javax.servlet.ServletRequest
import javax.servlet.http.HttpServletResponse
import org.beangle.security.authc.AuthenticationInfo
import org.beangle.security.mgt.SecurityManager
import org.beangle.security.context.SecurityContext
import org.beangle.security.session.Session
import org.beangle.security.authc.AccountStatusException
import org.beangle.security.authc.UsernameNotFoundException
import org.beangle.security.authc.AuthenticationToken
import org.beangle.security.authc.AuthenticationException

trait PreauthAliveChecker {
  def check(session: Session, request: HttpServletRequest): Boolean

}
abstract class AbstractPreauthFilter extends GenericHttpFilter {

  var securityManager: SecurityManager
  var aliveChecker: PreauthAliveChecker = _
  /**
   * Try to authenticate a pre-authenticated user if the
   * user has not yet been authenticated.
   */
  override final def doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain): Unit = {
    val request = req.asInstanceOf[HttpServletRequest]
    val response = res.asInstanceOf[HttpServletResponse]
    val requireAuth = requiresAuthentication(request, response)
    if (requireAuth) doAuthenticate(request, response)
    chain.doFilter(req, res);
  }

  /** Do the actual authentication for a pre-authenticated user. */
  private def doAuthenticate(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    var authResult: AuthenticationInfo = null;
    val token = getPreauthToken(request, response);
    //    if (null != auth) {
    //    try {
    //      auth.setDetails(authenticationDetailsSource.buildDetails(request));
    //      authResult = securityManager.login(request, auth);
    //      successfulAuthentication(request, response, authResult);
    //      return authResult;
    //    } catch (AuthenticationException failed) {
    //      unsuccessfulAuthentication(request, response, failed);
    //      if (!continueOnFail) throw failed;
    //      else return null;
    //    }
    //     }
  }

  def getPreauthToken(request: HttpServletRequest, response: HttpServletResponse): AuthenticationToken

  protected def requiresAuthentication(request: HttpServletRequest, response: HttpServletResponse): Boolean = {
    SecurityContext.session match {
      case None => true
      case Some(s) => {
        if (null != aliveChecker && !aliveChecker.check(s, request)) {
          unsuccessfulAuthentication(request, response,null)
          true
        } else false
      }
    }
  }

  /**
   * Puts the <code>Authentication</code> instance returned by the
   * authentication manager into the secure context.
   */
  protected def successfulAuthentication(request: HttpServletRequest, response: HttpServletResponse,
    session: Session): Unit = {
    debug(s"PreAuthentication success: $session")
    SecurityContext.session = session
  }

  /**
   * Ensures the authentication object in the secure context is set to null when authentication
   * fails.
   * If username not found or account status exception.just let other know by throw it.
   * It will be handled by ExceptionTranslationFilter
   */
  protected def unsuccessfulAuthentication(request: HttpServletRequest, response: HttpServletResponse,
    failed: AuthenticationException) {
    SecurityContext.session = null
    if (null != failed) {
      debug("Cleared security context due to exception", failed)
      if (failed.isInstanceOf[UsernameNotFoundException] || failed.isInstanceOf[AccountStatusException]) throw failed
    }
  }
}