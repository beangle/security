package org.beangle.security.mgt

import org.beangle.security.authc.{AuthenticationToken, Authenticator}
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.{Session, SessionRegistry}
import org.beangle.security.session.SessionKey

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def sessionRegistry: SessionRegistry

  def isPermitted(principal: Any, operation: Any, resource: Any): Boolean = authorizer.isPermitted(principal, operation, resource)
  /**
   * @throws AuthenticationException
   */
  def login(token: AuthenticationToken,key:SessionKey): Session

  def logout(session: Session): Unit = session.stop()
}

class DefaultSecurityManager extends SecurityManager {

  var sessionRegistry: SessionRegistry = _
  var authorizer: Authorizer = _
  var authenticator: Authenticator = _

  def login(token: AuthenticationToken,key:SessionKey): Session = {
    val info =authenticator.authenticate(token)
    sessionRegistry.register(info, key)
  }

}