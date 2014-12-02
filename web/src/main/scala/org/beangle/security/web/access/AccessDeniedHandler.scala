package org.beangle.security.web.access

import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import org.beangle.security.authz.AccessDeniedException
import javax.servlet.http.HttpServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.RequestDispatcher
import org.beangle.commons.logging.Logging
import org.beangle.commons.bean.Initializing
import org.beangle.commons.web.context.ServletContextHolder
import java.io.File

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

class DefaultAccessDeniedHandler(var errorPage: String) extends AccessDeniedHandler with Logging {

  def this() {
    this(null)
  }
  if (null != errorPage) {
    require(errorPage.startsWith("/"), "errorPage must begin with '/'")
    val file = ServletContextHolder.context.getRealPath(errorPage)
    if (!new File(file).exists) errorPage = null
  }

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

