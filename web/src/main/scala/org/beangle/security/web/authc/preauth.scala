package org.beangle.security.web

import java.util.Date

import org.beangle.commons.codec.digest.Digests
import org.beangle.commons.lang.{ Objects, Strings }
import org.beangle.commons.logging.Logging
import org.beangle.commons.web.filter.GenericHttpFilter
import org.beangle.commons.web.util.RequestUtils
import org.beangle.security.authc.{ AbstractAccountRealm, Account, AccountStore, AuthenticationException, AuthenticationInfo, AuthenticationToken }
import org.beangle.security.context.SecurityContext
import org.beangle.security.mgt.SecurityManager
import org.beangle.security.session.Session
import org.beangle.security.web.authc.WebDetails
import org.beangle.security.web.session.{ DefaultSessionIdPolicy, SessionIdPolicy }

import javax.servlet.{ FilterChain, ServletRequest, ServletResponse }
import javax.servlet.http.{ HttpServletRequest, HttpServletResponse }

trait PreauthAliveChecker {
  def check(session: Session, request: HttpServletRequest): Boolean
}

/**
 * Preauth Authentication Token
 */
class PreauthToken(val principal: Any) extends AuthenticationToken {

  var details: Map[String, Any] = Map.empty

  def credentials: Any = null

  override def equals(obj: Any): Boolean = {
    obj match {
      case test: PreauthToken =>
        Objects.equalsBuilder.add(principal, test.principal)
          .add(details, test.details)
          .isEquals
      case _ => false
    }
  }

}

abstract class AbstractPreauthFilter(val securityManager: SecurityManager) extends GenericHttpFilter with Logging {

  var aliveChecker: PreauthAliveChecker = _
  var sessionIdPolicy: SessionIdPolicy = new DefaultSessionIdPolicy
  /**
   * Try to authenticate a pre-authenticated user if the
   * user has not yet been authenticated.
   */
  override final def doFilter(req: ServletRequest, res: ServletResponse, chain: FilterChain): Unit = {
    val request = req.asInstanceOf[HttpServletRequest]
    val response = res.asInstanceOf[HttpServletResponse]
    val requireAuth = requiresAuthentication(request, response)
    if (requireAuth) doAuthenticate(request, response)
    chain.doFilter(req, res)
  }

  /** Do the actual authentication for a pre-authenticated user. */
  private def doAuthenticate(request: HttpServletRequest, response: HttpServletResponse): Unit = {
    var authResult: AuthenticationInfo = null
    val token = getPreauthToken(request, response)
    if (null != token) {
      token.details ++= WebDetails.get(request)
      try {
        val session = securityManager.login(token, sessionIdPolicy.getSessionId(request))
        SecurityContext.session = session
        val httpSession = request.getSession(false)
        if (null != httpSession) httpSession.setMaxInactiveInterval(session.timeout)
      } catch {
        case failed: AuthenticationException => unsuccessfulAuthentication(request, response, failed)
        case e: Throwable => throw e
      }
    }
  }

  protected def getPreauthToken(request: HttpServletRequest, response: HttpServletResponse): PreauthToken

  protected def requiresAuthentication(request: HttpServletRequest, response: HttpServletResponse): Boolean = {
    SecurityContext.getSession match {
      case None => true
      case Some(s) => {
        if (null != aliveChecker && !aliveChecker.check(s, request)) {
          unsuccessfulAuthentication(request, response, null)
          true
        } else false
      }
    }
  }

  /**
   * Puts the <code>Authentication</code> instance returned by the
   * authentication manager into the secure context.
   */
  protected def successfulAuthentication(request: HttpServletRequest, response: HttpServletResponse,
    session: Session): Unit = {
    debug(s"PreAuthentication success: $session")
    SecurityContext.session = session
  }

  /**
   * Ensures the authentication object in the secure context is set to null when authentication
   * fails.
   * If username not found or account status exception.just let other know by throw it.
   * It will be handled by ExceptionTranslationFilter
   */
  protected def unsuccessfulAuthentication(request: HttpServletRequest, response: HttpServletResponse,
    failed: AuthenticationException) {
    debug("Cleared security context due to exception", failed)
    SecurityContext.session = null
    if (null != failed) throw failed
    //if (failed.isInstanceOf[UsernameNotFoundException] || failed.isInstanceOf[AccountStatusException]) throw failed
  }
}

/**
 * Source of the username supplied with pre-authenticated authentication
 * request. The username can be supplied in the request: in cookie, request
 * header, request parameter or as ServletRequest.getRemoteUser().
 */
trait UsernameSource {
  /**
   * Obtain username supplied in the request.
   */
  def obtainUsername(request: HttpServletRequest): Option[String]
}

/**
 * Abtain username by cookie
 */
class CookieUsernameSource extends UsernameSource {

  var cookieName: String = _

  def obtainUsername(request: HttpServletRequest): Option[String] = {
    val cookies = request.getCookies
    if (cookies != null) {
      cookies.find(c => c.getName == cookieName) match {
        case Some(c) => Some(c.getValue)
        case None => None
      }
    }
    None
  }
}

/**
 * Source of the username supplied with pre-authenticated authentication request
 * as remote user header value. Optionally can strip prefix: "domain\\username"
 * -> "username", if <tt>stripPrefix</tt> property value is "true".
 */
class RemoteUsernameSource extends UsernameSource with Logging {

  var stripPrefix = true

  def obtainUsername(request: HttpServletRequest): Option[String] = {
    var username: String = null
    val p = request.getUserPrincipal()
    if (null != p) username = p.getName()
    if (Strings.isEmpty(username)) username = request.getRemoteUser()
    if (null != username && stripPrefix) username = stripPrefix(username)
    if (null != username) debug(s"Obtained username=[${username}] from remote user")
    if (null == username) None else Some(username)
  }

  private def stripPrefix(userName: String): String = {
    val index = userName.lastIndexOf("\\")
    if (-1 == index) userName else userName.substring(index + 1)
  }
}

class ParameterUsernameSource extends UsernameSource with Logging {

  var enableExpired = true

  // default 10min second
  var expiredTime = 600

  var timeParam = "t"

  var userParam = "cid"

  var digestParam = "s"

  var extra = "123456!"

  def obtainUsername(request: HttpServletRequest): Option[String] = {
    val ip = RequestUtils.getIpAddr(request)
    val cid = request.getParameter(userParam)
    val timeParamStr = request.getParameter(timeParam)
    var t: Long = 0
    if (null != timeParamStr) t = java.lang.Long.valueOf(timeParamStr)

    val s = request.getParameter(digestParam)
    if (0 == t || null == s || null == cid || null == ip) None
    else {
      val full = cid + "," + ip + "," + t + "," + extra
      val digest = Digests.md5Hex(full)
      if (debugEnabled) {
        debug(s"user $cid at :$ip")
        debug(s"time:$t digest:$s ")
        debug(s"full:$full")
        debug(s"my_digest:$digest")
      }
      if (digest.equals(s)) {
        val time = t * 1000
        val now = new Date()
        if (enableExpired && (Math.abs(now.getTime() - time) > (expiredTime * 1000))) {
          debug(s"user $cid time expired:server time:${now} and given time :${new java.util.Date(time)}")
          None
        } else {
          debug(s"user $cid login at server time:$now")
          Some(cid)
        }
      } else None
    }
  }
}

class UsernamePreauthFilter(securityManager: SecurityManager) extends AbstractPreauthFilter(securityManager) {
  var usernameSource: UsernameSource = _

  protected override def getPreauthToken(request: HttpServletRequest, response: HttpServletResponse): PreauthToken = {
    usernameSource.obtainUsername(request) match {
      case Some(name) => if (Strings.isNotBlank(name)) new PreauthToken(name) else null
      case None => null
    }
  }
}

class PreauthRealm extends AbstractAccountRealm {
  var accountStore: AccountStore = _

  protected override def credentialsCheck(token: AuthenticationToken, account: Account): Unit = {}

  protected override def loadAccount(principal: Any): Option[Account] = accountStore.load(principal)

  override def supports(token: AuthenticationToken): Boolean = token.isInstanceOf[PreauthToken]
}