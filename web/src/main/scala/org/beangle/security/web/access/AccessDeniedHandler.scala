package org.beangle.security.web.access

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.beangle.security.authz.AccessDeniedException
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.RequestDispatcher
import org.beangle.commons.logging.Logging
import org.beangle.commons.bean.Initializing

/**
 * @author chaostone
 */
trait AccessDeniedHandler {

  /**
   * Handles an access denied failure.
   *
   */
  def handle(request: ServletRequest, response: ServletResponse, exception: AccessDeniedException): Unit
}

class DefaultAccessDeniedHandler(val errorPage: String) extends AccessDeniedHandler with Logging {

  def this() {
    this(null)
  }
  if (null != errorPage)
    require(errorPage.startsWith("/"), "errorPage must begin with '/'")

  def handle(request: ServletRequest, response: ServletResponse, exception: AccessDeniedException): Unit = {
    if (errorPage != null) {
      // Put exception into request scope (perhaps of use to a view)
      request.asInstanceOf[HttpServletRequest].setAttribute("403_EXCEPTION", exception);
      // Perform RequestDispatcher "forward"
      request.getRequestDispatcher(errorPage).forward(request, response)
    }

    if (!response.isCommitted()) {
      // Send 403 (we do this after response has been written)
      response.asInstanceOf[HttpServletResponse].sendError(HttpServletResponse.SC_FORBIDDEN, exception.getMessage())
    }
  }

}

