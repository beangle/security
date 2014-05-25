package org.beangle.security.authc

import org.beangle.commons.logging.Logging
import org.beangle.security.session.Session
import org.beangle.security.realm.Realm
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
      if (info == null) throw new AuthenticationException(s"No account information found for authentication token [$token]")
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

  def doAuthenticate(token: AuthenticationToken): AuthenticationInfo

  @inline
  protected final def notifySuccess(token: AuthenticationToken, info: AuthenticationInfo): Unit = {
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
  /**
   * @throws AuthenticationException
   */
  def authenticate(realms: List[Realm], token: AuthenticationToken): AuthenticationInfo

  protected def merge(info: AuthenticationInfo, aggregate: AuthenticationInfo): AuthenticationInfo = {
    if (null == aggregate) info
    else {
      if (aggregate.isInstanceOf[Mergable]) {
        aggregate.asInstanceOf[Mergable].merge(info)
      } else {
        throw new IllegalArgumentException("AuthenticationInfo is not of type MergableAuthenticationInfo.");
      }
    }
  }

  protected def returnOrRaise(info: AuthenticationInfo, token: AuthenticationToken, t: Throwable): AuthenticationInfo = {
    if (null == info) throw if (null == t) new RuntimeException(s"Realm not found for $token") else t
    else {
      if (info.isInstanceOf[Mergable]) info.asInstanceOf[Mergable].details = info.details ++ token.details
      info
    }
  }
}

/**
 * First win,imply at least one and ignore remainders
 */
object FirstSuccessfulStrategy extends RealmAuthenticationStrategy with Logging {

  override def authenticate(realms: List[Realm], token: AuthenticationToken): AuthenticationInfo = {
    val realmIter = realms.iterator
    var info: AuthenticationInfo = null
    var lastException: Throwable = null
    while (null != info && realmIter.hasNext) {
      val realm = realmIter.next()
      if (realm.supports(token)) {
        try {
          info = realm.getAuthenticationInfo(token)
        } catch {
          case t: Throwable => {
            lastException = t
            debug(s"Realm [$realm] threw an exception during a multi-realm authentication attempt:", t)
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
  override def authenticate(realms: List[Realm], token: AuthenticationToken): AuthenticationInfo = {
    val realmIter = realms.iterator
    var aggregate: AuthenticationInfo = null
    var lastException: Throwable = null
    while (realmIter.hasNext) {
      val realm = realmIter.next()
      if (realm.supports(token)) {
        try {
          val info = realm.getAuthenticationInfo(token)
          if (null != info) aggregate = merge(info, aggregate)
        } catch {
          case t: Throwable => {
            lastException = t
            debug(s"Realm [$realm] threw an exception during a multi-realm authentication attempt:", t)
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

  override def authenticate(realms: List[Realm], token: AuthenticationToken): AuthenticationInfo = {
    val realmIter = realms.iterator
    var aggregate: AuthenticationInfo = null
    while (realmIter.hasNext) {
      val realm = realmIter.next()
      if (realm.supports(token)) {
        try {
          val info = realm.getAuthenticationInfo(token)
          if (null == info) throw new AuthenticationException(s"Realm [$realm] could not find account data for [$token].")
          else aggregate = merge(info, aggregate)
        } catch {
          case e: AuthenticationException => throw e
          case t: Throwable => throw new AuthenticationException(s"Unable to acquire account data from [$realm].", t)
        }
      }
    }
    returnOrRaise(aggregate, token, null)
  }
}

/**
 * Realm Authenticator
 */
class RealmAuthenticator extends AbstractAuthenticator with Logging {
  var reams: List[Realm] = List.empty
  var strategy: RealmAuthenticationStrategy = _
  override def doAuthenticate(token: AuthenticationToken): AuthenticationInfo = {
    strategy.authenticate(reams, token)
  }
}