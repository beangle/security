package org.beangle.security.authc

import org.beangle.commons.logging.Logging
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
//  def onSuccess(token: AuthenticationToken, info: AuthenticationInfo)
}
abstract class AbstractAuthenticator extends Authenticator with Logging {

  var listeners: List[AuthenticationListener] = List.empty

  override def authenticate(token: AuthenticationToken): AuthenticationInfo = {
    doAuthentication(token)
  }

  def doAuthentication(request: AuthenticationToken): AuthenticationInfo
}