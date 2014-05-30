package org.beangle.security.web

import org.beangle.security.authc.AuthenticationException

import javax.servlet.{ServletRequest, ServletResponse}

trait EntryPoint{
  
  /**
   * @throws IOException
   * @throws ServletException
   */
    def commence(request:ServletRequest ,response: ServletResponse , authException:AuthenticationException )
  
}