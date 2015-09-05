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
      notifySuccess(token, info);
      info
    } catch {
      case e: Throwable =>
        val ae = if (e.isInstanceOf[AuthenticationException]) e.asInstanceOf[AuthenticationException]
        else new AuthenticationException(s"Authentication failed for token submission [$token].  Possible unexpected error?", token, e)
        try {
          notifyFailure(token, ae)
        } catch {
          case e2: Throwable =>
            logger.warn("Unable to send notification for failed authentication attempt - listener error?.  " +
              "Please check your AuthenticationListener implementation(s).  Logging sending exception " +
              "and propagating original AuthenticationException instead...", e2)
        }
        throw ae
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

  protected def merge(info: Account, aggregate: Account): Account = {
    if (null == aggregate) info
    else aggregate.merge(info)
  }

  protected def returnOrRaise(info: Account, token: AuthenticationToken, t: Throwable): Account = {
    if (null == info) throw if (null == t) new RuntimeException(s"Realm not found for $token") else t
    else {
      info.details = info.details ++ token.details
      info
    }
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
 * Pass Through all possible realm and aggregate authentication info
 */
object AtLeastOneSuccessfulStrategy extends RealmAuthenticationStrategy with Logging {
  override def authenticate(realms: List[Realm], token: AuthenticationToken): Account = {
    val realmIter = realms.iterator
    var aggregate: Account = null
    var lastException: Throwable = null
    while (realmIter.hasNext) {
      val realm = realmIter.next()
      if (realm.supports(token)) {
        try {
          val info = realm.getAccount(token)
          if (null != info) aggregate = merge(info, aggregate)
        } catch {
          case t: Throwable => {
            lastException = t
            logger.debug(s"Realm [$realm] threw an exception during a multi-realm authentication attempt:", t)
          }
        }
      }
    }
    returnOrRaise(aggregate, token, lastException)
  }
}
/**
 * All realms should pass the authentication when it support then token and return merged authenticaiton info.
 */
object AllSuccessfulStrategy extends RealmAuthenticationStrategy with Logging {

  override def authenticate(realms: List[Realm], token: AuthenticationToken): Account = {
    val realmIter = realms.iterator
    var aggregate: Account = null
    while (realmIter.hasNext) {
      val realm = realmIter.next()
      if (realm.supports(token)) {
        try {
          val info = realm.getAccount(token)
          if (null == info) throw new AuthenticationException(s"Realm [$realm] could not find account data for [$token].", token)
          else aggregate = merge(info, aggregate)
        } catch {
          case e: Throwable => throw e
        }
      }
    }
    returnOrRaise(aggregate, token, null)
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