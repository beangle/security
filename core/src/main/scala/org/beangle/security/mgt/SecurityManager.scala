package org.beangle.security.mgt

import org.beangle.security.authc.{AuthenticationToken, Authenticator}
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.{Session, SessionRegistry}

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def sessionRegistry: SessionRegistry

  def isPermitted(principal: Any, operation: Any, resource: Any): Boolean = authorizer.isPermitted(principal, operation, resource)
  /**
   * @throws AuthenticationException
   */
  def login(token: AuthenticationToken): Session

  def logout(session: Session): Unit = session.stop()
}

class DefaultSecurityManager extends SecurityManager {

  var sessionRegistry: SessionRegistry = _
  var authorizer: Authorizer = _
  var authenticator: Authenticator = _

  def login(token: AuthenticationToken): Session = {
    null
  }

}