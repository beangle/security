package org.beangle.security.web.access

import org.beangle.commons.http.HttpMethods.{DELETE, GET, HEAD, OPTIONS, POST, PUT, TRACE}
import org.beangle.commons.web.filter.OncePerRequestFilter
import org.beangle.commons.web.util.RequestUtils
import org.beangle.security.authz.AccessDeniedException
import org.beangle.security.context.SecurityContext
import org.beangle.security.mgt.SecurityManager

import javax.servlet.{FilterChain, ServletRequest, ServletResponse}
import javax.servlet.http.HttpServletRequest

abstract class AuthorizationFilter extends OncePerRequestFilter {

  var securityManager: SecurityManager = _

  def getResource(request: ServletRequest): Any

  def getOperation(request: ServletRequest): Any

  override def doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
    if (isFirstEnter(request)) {
      if (!securityManager.isPermitted(SecurityContext.principal, getResource(request), getOperation(request)))
        throw new AccessDeniedException(request, "access denied", null);
    } else
      chain.doFilter(request, response);
  }
}

object HttpActions {
  val Create = "create"
  val Read = "read"
  val Update = "update"
  val Delete = "delete"
  val methodActions = Map((POST, Create), (GET, Read), (HEAD, Read), (OPTIONS, Read), (TRACE, Read), (PUT, Update), (DELETE, Delete))
}

class HttpMethodPermissionFilter extends AuthorizationFilter {

  def getResource(request: ServletRequest): Any = RequestUtils.getServletPath(request.asInstanceOf[HttpServletRequest])

  import HttpActions._
  def getOperation(request: ServletRequest): Any = methodActions(request.asInstanceOf[HttpServletRequest].getMethod().toUpperCase())
}