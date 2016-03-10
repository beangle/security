/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2016, Beangle Software.
 *
 * Beangle is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Beangle is distributed in the hope that it will be useful.
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Beangle.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.authc

import org.beangle.commons.logging.Logging
import org.beangle.security.session.Session
import org.beangle.security.realm.Realm
/**
 * Authentication Manager
 */
trait Authenticator {

  @throws(classOf[AuthenticationException])
  def authenticate(token: AuthenticationToken): Account
}

trait AuthenticationListener {
  def onSuccess(token: AuthenticationToken, info: Account)
  def onFailure(token: AuthenticationToken, cause: AuthenticationException)
  def onLogout(info: Session)
}

abstract class AbstractAuthenticator extends Authenticator with Logging {

  var listeners: List[AuthenticationListener] = List.empty

  override def authenticate(token: AuthenticationToken): Account = {
    try {
      val info = doAuthenticate(token);
      if (info == null) throw new AuthenticationException(s"No account information found for authentication token [$token]", token)
      notifySuccess(token, info)
      info
    } catch {
      case ae: AuthenticationException =>
        try {
          notifyFailure(token, ae)
        } catch {
          case e2: Throwable =>
            logger.warn("Unable to send notification for failed authentication attempt - listener error?.  " +
              "Please check your AuthenticationListener implementation(s).  Logging sending exception " +
              "and propagating original AuthenticationException instead...", e2)
        }
        throw ae
      case e: Throwable => throw e
    }
  }

  def doAuthenticate(token: AuthenticationToken): Account

  @inline
  protected final def notifySuccess(token: AuthenticationToken, info: Account): Unit = {
    listeners.foreach(listener => listener.onSuccess(token, info))
  }

  @inline
  protected final def notifyFailure(token: AuthenticationToken, ae: AuthenticationException): Unit = {
    listeners.foreach(listener => listener.onFailure(token, ae))
  }

}

/**
 * How we authenticate user within multiple realms
 */
trait RealmAuthenticationStrategy {

  @throws(classOf[AuthenticationException])
  def authenticate(realms: List[Realm], token: AuthenticationToken): Account

  protected def returnOrRaise(info: Account, token: AuthenticationToken, t: Throwable): Account = {
    if (null == info) throw if (null == t) new AuthenticationException(s"Realm not found for $token", token.principal, null) else t
    else info
  }
}

/**
 * First win,imply at least one and ignore remainders
 */
object FirstSuccessfulStrategy extends RealmAuthenticationStrategy with Logging {

  override def authenticate(realms: List[Realm], token: AuthenticationToken): Account = {
    val realmIter = realms.iterator
    var info: Account = null
    var lastException: Throwable = null
    while (null == info && realmIter.hasNext) {
      val realm = realmIter.next()
      if (realm.supports(token)) {
        try {
          info = realm.getAccount(token)
        } catch {
          case t: Throwable => {
            lastException = t
            logger.debug(s"Realm [$realm] threw an exception during a multi-realm authentication attempt:", t)
          }
        }
      }
    }
    returnOrRaise(info, token, lastException)
  }
}

/**
 * Realm Authenticator
 */
class RealmAuthenticator(val reams: List[Realm]) extends AbstractAuthenticator with Logging {
  var strategy: RealmAuthenticationStrategy = FirstSuccessfulStrategy
  override def doAuthenticate(token: AuthenticationToken): Account = {
    strategy.authenticate(reams, token)
  }
}

trait CredentialsChecker {
  def check(principal: Any, credential: Any): Boolean
}
