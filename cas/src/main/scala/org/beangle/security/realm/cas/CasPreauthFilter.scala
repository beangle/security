package org.beangle.security.realm.cas

import org.beangle.commons.lang.Assert
import org.beangle.security.web.{ AbstractPreauthFilter, PreauthToken }

import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }
/**
 * Processes a CAS service ticket.
 */
class CasPreauthFilter extends AbstractPreauthFilter {

  var config: CasConfig = _

  protected override def initFilterBean() {
    super.initFilterBean()
    Assert.notNull(config, "config is a required field.")
  }

  protected override def getPreauthToken(request: HttpServletRequest, response: HttpServletResponse): PreauthToken = {
    val ticket = request.getParameter("ticket")
    if (ticket == null) {
      null
    } else {
      val url = CasEntryPoint.constructServiceUrl(request, response, null,
        CasConfig.getLocalServer(request), "ticket", config.encode)
      new CasToken(ticket)
    }
  }

}
