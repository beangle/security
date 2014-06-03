package org.beangle.security.realm.cas

import org.beangle.commons.bean.Initializing
import org.beangle.commons.lang.{ Assert, Strings }

import javax.servlet.http.HttpServletRequest

object CasConfig {

  def getLocalServer(request: HttpServletRequest): String = {
    val sb = new StringBuilder()
    val scheme = request.getScheme()
    val port = request.getServerPort()
    val serverName = request.getServerName()
    var includePort = true
    if (null != scheme) {
      sb.append(scheme).append("://")
      includePort = (port != (if (scheme.equals("http")) 80 else 443))
    }
    if (null != serverName) {
      sb.append(serverName)
      if (includePort && port > 0) {
        sb.append(':').append(port)
      }
    }
    sb.toString
  }

  val TicketName = "ticket"
}

class CasConfig(server: String) extends Initializing {
  val casServer = Strings.stripEnd(server, "/")
  /**
   * Indicates whether the <code>renew</code> parameter should be sent to the
   * CAS login URL and CAS validation URL.
   * <p>
   * If <code>true</code>, it will force CAS to authenticate the user again (even if the user has
   * previously authenticated). During ticket validation it will require the ticket was generated as
   * a consequence of an explicit login. High security applications would probably set this to
   * <code>true</code>. Defaults to <code>false</code>, providing automated single sign on.
   */
  var renew = false

  var encode = true

  var artifactName = CasConfig.TicketName

  var loginUri = "/login"

  var validateUri = "/serviceValidate"

  var checkAliveUri = "/checkAlive"

  def init() {
    Assert.notEmpty(this.loginUri, "loginUri must be specified. like /login")
    Assert.notEmpty(this.artifactName, "artifact name  must be specified.etc. ticket")
  }
  /**
   * The enterprise-wide CAS login URL. Usually something like
   * <code>https://www.mycompany.com/cas/login</code>.
   */
  def loginUrl: String = casServer + loginUri

}
