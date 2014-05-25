package org.beangle.security.mgt

import org.beangle.security.authc.Authenticator
import org.beangle.security.authz.Authorizer
import org.beangle.security.session.SessionRegistry
import org.beangle.security.context.SecurityContext
import org.beangle.security.authc.AuthenticationToken
import javax.security.auth.Subject

trait SecurityManager {

  def authenticator: Authenticator

  def authorizer: Authorizer

  def sessionRegistry: SessionRegistry

  /**
   * @throw AuthenticationException
   */
  def login(token: AuthenticationToken): SecurityContext

  def logout (context:SecurityContext)
}