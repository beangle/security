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

import javax.naming.{ CompositeName, NamingException }
import javax.naming.directory.{ Attribute, SearchControls }

/**
 * Ldap User Store (RFC 4510)
 * @see http://tools.ietf.org/html/rfc4510
 * @see http://www.rfc-base.org/rfc-4510.html
 * @see http://directory.apache.org/api/java-api.html
 */
trait LdapUserService {

  def getUserDN(uid: String): Option[String]

  def getAttributes(userDN: String, attributeNames: String*): collection.Map[String, Any]

  def getPassword(userDN: String): Option[String]
}

object LdapUserService {
  val CommonName = "cn"
  val UserPassword = "userPassword"
}

class DefaultLdapUserService(contextSource: ContextSource, base: String) extends LdapUserService with Logging {
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

  override def getPassword(userDN: String): Option[String] = {
    val attrs = getAttributes(userDN, LdapUserService.UserPassword)
    if (attrs.isEmpty) {
      None
    } else {
      Some(new String(attrs.head._2.asInstanceOf[Array[Byte]]))
    }
  }
}