package org.beangle.security.web.access

import org.beangle.commons.http.HttpMethods.{ DELETE, GET, HEAD, OPTIONS, POST, PUT, TRACE }
import org.beangle.commons.web.filter.{ GenericHttpFilter, OncePerRequestFilter }
import org.beangle.commons.web.util.RequestUtils
import org.beangle.security.authz.AccessDeniedException
import org.beangle.security.mgt.SecurityManager
import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.HttpServletRequest
import org.beangle.security.context.SecurityContext
import org.beangle.commons.web.security.RequestConvertor

class AuthorizationFilter(val securityManager: SecurityManager, val requestConvertor: RequestConvertor) extends GenericHttpFilter {

  override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
    if (!securityManager.isPermitted(SecurityContext.principal, requestConvertor.convert(request.asInstanceOf[HttpServletRequest])))
      throw new AccessDeniedException(request, "access denied", null)
    chain.doFilter(request, response)
  }
}