package org.beangle.security.mgt

import org.beangle.security.authc.Authenticator
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.SessionRegistry
import org.beangle.security.context.SecurityContext
import org.beangle.security.authc.AuthenticationToken
import javax.security.auth.Subject
import org.beangle.security.session.Session

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def sessionRegistry: SessionRegistry

  def isPermitted(principal: Any,  operation: Any,resource: Any): Boolean = authorizer.isPermitted(principal, operation,resource)
  /**
   * @throws AuthenticationException
   */
  def login(token: AuthenticationToken): Session

  def logout(session: Session)
}