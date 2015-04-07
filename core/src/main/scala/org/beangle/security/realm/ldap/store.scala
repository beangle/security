package org.beangle.security.realm.ldap

import java.{ util => jl }
import org.beangle.commons.bean.Disposable
import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import javax.naming.{ CompositeName, NamingException }
import javax.naming.directory.{ Attribute, Attributes, DirContext, InitialDirContext, SearchControls }
import org.beangle.security.authc.AccountStore
import org.beangle.security.authc.DefaultAccount
import org.beangle.security.authc.Account

/**
 * Ldap User Store (RFC 4510)
 * @see http://tools.ietf.org/html/rfc4510
 * @see http://www.rfc-base.org/rfc-4510.html
 */
trait LdapUserStore extends AccountStore {

  def getUserDN(uid: String): String

  def getPassword(uid: String): String

  def getAttributes(uid: String, attrName: String): Set[Any]

  def url: String
}

class SimpleLdapUserStore extends LdapUserStore with Disposable with Logging {
  var url: String = _
  var userName: String = _
  var password: String = _
  var base: String = _
  var ctx: DirContext = _

  private var uidName = "uid"
  private var properties = new jl.Hashtable[String, String]

  def this(url: String, userName: String, password: String, base: String) {
    this()
    assert(null != url)
    assert(null != userName)
    assert(null != password)
    assert(null != base)
    this.url = url
    this.userName = userName
    this.password = password
    this.base = base
  }

  def getUserDN(uid: String): String = {
    val ctx = context
    if (ctx == null) return null
    var result: String = null
    val condition = Strings.concat(uidName, "=", uid)
    try {
      val attrList = Array(uidName)
      val constraints = new SearchControls()
      constraints.setSearchScope(2)
      constraints.setReturningAttributes(attrList)
      var results = ctx.search(base, condition, constraints)
      if (results.hasMore()) {
        val si = results.next()
        result = Strings.concat(si.getName(), ",", base)
      }
      results.close()
      results = null
    } catch {
      case e: Throwable => logger.error("Ldap search error,uid=" + uid, e)
    }
    return result
  }

  def getPassword(uid: String): String = {
    val passwords = getAttributes(uid, "userPassword")
    if (passwords.isEmpty) return null
    else new String(passwords.head.asInstanceOf[Array[Byte]])
  }

  def getAttributes(uid: String, attrName: String): Set[Any] = {
    val values = new collection.mutable.HashSet[Any]
    val ctx = context
    if (ctx != null) {
      try {
        val dn = getUserDN(uid)
        if (dn == null) logger.debug(s"User $uid not found")
        else {
          val userID = new CompositeName(dn)
          var attrs: Attributes = null
          if (null != attrName) {
            attrs = ctx.getAttributes(userID, Array(attrName))
          } else {
            attrs = ctx.getAttributes(userID)
          }
          val attrEnum = attrs.getAll()
          while (attrEnum.hasMoreElements()) {
            values += attrEnum.nextElement().asInstanceOf[Attribute].get()
          }
        }
      } catch {
        case e: NamingException => e.printStackTrace()
      }
    }
    values.toSet
  }

  private def enviroment: jl.Hashtable[String, String] = {
    val env = new jl.Hashtable[String, String]
    env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory")
    env.put("java.naming.provider.url", url)
    env.put("java.naming.security.authentication", "simple")
    env.put("java.naming.security.principal", userName)
    env.put("java.naming.security.credentials", password)
    env
  }

  private def connect(): DirContext = {
    synchronized {
      val env = enviroment
      env.putAll(properties)
      try {
        ctx = new InitialDirContext(env)
        logger.debug("Ldap server connect success.")
      } catch {
        case e: Exception => logger.error("Ldap server connect failure", e)
      }
      ctx
    }
  }

  def disConnect() {
    synchronized {
      if (ctx != null) try {
        ctx.close()
        ctx = null
        logger.debug("Ldap connect closed.")
      } catch {
        case e: Exception => logger.error("Failure to close ldap connection.", e)
      }
    }
  }

  private def context: DirContext = if (null == ctx) connect() else ctx

  override def destroy(): Unit = this.disConnect()

  override def load(principal: Any): Option[Account] = {
    val dn = getUserDN(principal.toString)
    if (null != dn) {
      val account = new DefaultAccount(principal, dn)
      Some(account)
    } else None
  }
}