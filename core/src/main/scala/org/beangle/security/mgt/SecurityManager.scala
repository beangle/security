package org.beangle.security.mgt

import org.beangle.commons.security.Request
import org.beangle.security.authc.{ AuthenticationException, AuthenticationToken, Authenticator }
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.{ Session, SessionKey, SessionRegistry }

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def sessionRegistry: SessionRegistry

  def isPermitted(principal: Any, request: Request): Boolean = {
    authorizer.isPermitted(principal, request)
  }

  //@throw(classOfAuthenticationException])
  def login(token: AuthenticationToken, key: SessionKey): Session

  def logout(session: Session): Unit = session.stop()
}

class DefaultSecurityManager(val authenticator: Authenticator, val authorizer: Authorizer,
  val sessionRegistry: SessionRegistry) extends SecurityManager {

  def login(token: AuthenticationToken, key: SessionKey): Session = {
    sessionRegistry.register(authenticator.authenticate(token), key)
  }

}