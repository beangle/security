package org.beangle.security.web

import org.beangle.security.authc.AuthenticationException
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }
import org.beangle.commons.web.url.UrlBuilder
import org.beangle.commons.lang.Strings
import org.beangle.commons.web.util.RedirectUtils
import javax.servlet.RequestDispatcher
import org.beangle.commons.logging.Logging

trait EntryPoint {

  /**
   * @throws IOException
   * @throws ServletException
   */
  def commence(request: HttpServletRequest, response: HttpServletResponse, ae: AuthenticationException): Unit

}

class UrlEntryPoint(val url: String) extends EntryPoint with Logging {

  var serverSideRedirect: Boolean = _

  /** Performs the redirect (or forward) to the login form URL. */
  override def commence(req: HttpServletRequest, res: HttpServletResponse, ae: AuthenticationException): Unit = {
    if (serverSideRedirect) {
      req.getRequestDispatcher(determineUrl(req, ae)).forward(req, res)
    } else {
      // redirect to login page. Use https if forceHttps true
      RedirectUtils.sendRedirect(req, res, determineUrl(req, ae))
    }
  }

  /**
   * Allows subclasses to modify the login form URL that should be applicable
   * for a given request.
   */
  protected def determineUrl(req: HttpServletRequest, ae: AuthenticationException): String = {
    if (url.contains("${goto}")) Strings.replace(url, "${goto}", UrlBuilder.url(req))
    else url
  }
}