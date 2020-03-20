/*
 * Beangle, Agile Development Scaffold and Toolkits.
 *
 * Copyright © 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.beangle.security.realm.ldap

import java.{ util => jl }

import org.beangle.security.authc.CredentialChecker

import javax.naming.Context
import javax.naming.directory.InitialDirContext

/**
 * @author chaostone
 */
class BindCredentialChecker(contextSource: ContextSource) extends CredentialChecker {

  var properties = new jl.Hashtable[String, String]

  private def enviroment(userName: String, password: String): jl.Hashtable[String, String] = {
    val env = new jl.Hashtable[String, String]
    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(Context.PROVIDER_URL, contextSource.url)
    env.put(Context.SECURITY_AUTHENTICATION, "simple")
    env.put(Context.SECURITY_PRINCIPAL, userName)
    env.put(Context.SECURITY_CREDENTIALS, password)
    env
  }

  override def check(principal: Any, credential: Any): Boolean = {
    val name = principal.toString
    val password = credential.toString
    val env = enviroment(name, password)
    env.putAll(properties)
    try {
      new InitialDirContext(env).close()
      true
    } catch {
      case _: javax.naming.AuthenticationException => false
    }
  }
}
