package org.beangle.security.web

import org.beangle.security.authc.AuthenticationException

import javax.servlet.http.{HttpServletRequest, HttpServletResponse}

trait EntryPoint {

  /**
   * @throws IOException
   * @throws ServletException
   */
  def commence(request: HttpServletRequest, response: HttpServletResponse, ae: AuthenticationException)

}