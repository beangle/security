/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2017, Beangle Software.
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
package org.beangle.security.realm.ldap

import scala.collection.mutable.Buffer

import org.beangle.commons.collection.Collections
import org.beangle.commons.lang.Strings
import org.beangle.commons.logging.Logging
import org.beangle.security.authc.{ Account, AccountStore, DefaultAccount }
import org.beangle.security.codec.DefaultPasswordEncoder

import javax.naming.{ CompositeName, NamingException }
import javax.naming.directory.{ Attribute, BasicAttributes, DirContext, SearchControls }

/**
 * Ldap User Store (RFC 4510)
 * @see http://tools.ietf.org/html/rfc4510
 * @see http://www.rfc-base.org/rfc-4510.html
 * @see http://directory.apache.org/api/java-api.html
 */
trait LdapUserStore extends AccountStore {

  def getUserDN(uid: String): Option[String]

  def getPassword(userDN: String): Option[String]

  def getAttribute(userDN: String, attrName: String): Option[Any]

  def getAttributes(userDN: String, attributeNames: String*): collection.Map[String, Any]

  def updateAttribute(dn: String, attribute: String, value: AnyRef): Unit

  def updatePassword(userDN: String, passwd: String): Unit

  //def create(user: Account): Unit
}

object LdapUserStore {
  val CommonName = "cn"
  val UserPassword = "userPassword"
}

class SimpleLdapUserStore(contextSource: ContextSource, base: String) extends LdapUserStore with Logging {

  var uidName = "uid"

  override def getUserDN(uid: String): Option[String] = {
    val ctx = contextSource.get()
    var result: String = null
    val condition = Strings.concat(uidName, "=", uid)
    try {
      val attrList = Array(uidName)
      val constraints = new SearchControls()
      constraints.setSearchScope(2)
      constraints.setReturningAttributes(attrList)
      //this must be false
      //@see http://stackoverflow.com/questions/11955041/why-doesnt-dircontext-close-return-the-ldap-connection-to-the-pool
      constraints.setReturningObjFlag(false)
      var results = ctx.search(base, condition, constraints)
      if (results.hasMore()) {
        val si = results.next()
        result = Strings.concat(si.getName(), ",", base)
      }
      results.close()
      results = null
    } catch {
      case e: Throwable => logger.error("Ldap search error,uid=" + uid, e)
    } finally {
      contextSource.release(ctx)
    }
    Option(result)
  }

  override def getPassword(userDN: String): Option[String] = {
    getAttribute(userDN, LdapUserStore.UserPassword).map(p => new String(p.asInstanceOf[Array[Byte]]))
  }

  override def getAttribute(userDN: String, attrName: String): Option[Any] = {
    getAttributes(userDN, attrName).get(attrName)
  }

  override def getAttributes(userDN: String, attributeNames: String*): collection.Map[String, Any] = {
    val result = Collections.newMap[String, Buffer[Any]]
    val ctx = contextSource.get()
    try {
      val userID = new CompositeName(userDN)
      val attrs =
        if (attributeNames.length > 0) ctx.getAttributes(userID, attributeNames.toArray)
        else ctx.getAttributes(userID)
      val attrEnum = attrs.getAll()
      while (attrEnum.hasMoreElements) {
        val attr = attrEnum.nextElement.asInstanceOf[Attribute]
        val values = result.getOrElseUpdate(attr.getID, new collection.mutable.ArrayBuffer[Any])
        values += attr.get()
      }
    } catch {
      case e: NamingException => e.printStackTrace()
    } finally {
      contextSource.release(ctx)
    }
    result.map(e => (e._1, if (e._2.size == 1) e._2.head else e._2))
  }

  override def updatePassword(userDN: String, passwd: String): Unit = {
    updateAttribute(userDN, LdapUserStore.UserPassword, DefaultPasswordEncoder.generate(passwd, null, "sha").getBytes)
  }

  override def updateAttribute(userDN: String, attribute: String, value: AnyRef): Unit = {
    val ctx = contextSource.get()
    try {
      val userID = new CompositeName(userDN)
      val attrs = new BasicAttributes
      attrs.put(attribute, value)
      val action = if (null == value) DirContext.REMOVE_ATTRIBUTE else DirContext.REPLACE_ATTRIBUTE
      ctx.modifyAttributes(userID, action, attrs)
    } catch {
      case e: NamingException => e.printStackTrace()
    } finally {
      contextSource.release(ctx)
    }
  }

  override def load(principal: Any): Option[Account] = {
    getUserDN(principal.toString).map(dn => new DefaultAccount(principal.toString, dn))
  }

  //FIXME 
  def create(user: Account, password: String): Unit = {
    val attrs = new BasicAttributes();
    attrs.put("cn", user.description)
    attrs.put("sn", user.description)
    attrs.put(uidName, user.name)
    attrs.put(LdapUserStore.UserPassword, password.getBytes)
  }
}
