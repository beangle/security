package org.beangle.security.authc

import org.beangle.commons.logging.Logging
import org.beangle.security.session.Session
/**
 * Authentication Manager
 */
trait Authenticator {
  /**
   * authenticate
   *
   * @param auth
   * @throws AuthenticationException
   */
  def authenticate(auth: AuthenticationToken): AuthenticationInfo
}

trait AuthenticationListener {
  def onSuccess(token: AuthenticationToken, info: AuthenticationInfo)
  def onFailure(token: AuthenticationToken, cause: AuthenticationException)
  def onLogout(info: Session)
}

abstract class AbstractAuthenticator extends Authenticator with Logging {

  var listeners: List[AuthenticationListener] = List.empty

  override def authenticate(token: AuthenticationToken): AuthenticationInfo = {
    try {
      val info = doAuthenticate(token);
      if (info == null) throw new AuthenticationException("No account information found for authentication token [" + token + "]")
      notifySuccess(token, info);
      info
    } catch {
      case e: Throwable =>
        val ae = if (e.isInstanceOf[AuthenticationException]) e.asInstanceOf[AuthenticationException]
        else new AuthenticationException(s"Authentication failed for token submission [$token].  Possible unexpected error?", e)
        try {
          notifyFailure(token, ae)
        } catch {
          case e2: Throwable =>
            warn("Unable to send notification for failed authentication attempt - listener error?.  " +
              "Please check your AuthenticationListener implementation(s).  Logging sending exception " +
              "and propagating original AuthenticationException instead...", e2)
        }
        throw ae
    }
  }

  def doAuthenticate(request: AuthenticationToken): AuthenticationInfo

  @inline
  protected final def notifySuccess(token: AuthenticationToken, info: AuthenticationInfo): Unit = listeners.foreach(listener => listener.onSuccess(token, info))

  @inline
  protected final def notifyFailure(token: AuthenticationToken, ae: AuthenticationException): Unit = listeners.foreach(listener => listener.onFailure(token, ae))

}