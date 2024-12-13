/*
 * Copyright (C) 2005, The Beangle Software.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.beangle.security.realm.ldap

import org.beangle.commons.bean.{Disposable, Initializing}
import org.beangle.commons.logging.Logging

import java.util as jl
import javax.naming.Context.*
import javax.naming.directory.{DirContext, InitialDirContext}

/**
 * @author chaostone
 */
trait ContextSource {
  def get(): DirContext

  def release(context: DirContext): Unit

  def url: String
}

/**
 * 使用jdk自带的缓冲池的源
 *
 * @see http://docs.oracle.com/javase/jndi/tutorial/ldap/connect/pool.html
 * @see http://blog.pierreroudier.net/2013/10/jndi-ldap-pools-unlimited-size-and-no-timeout-by-default/
 */
class PoolingContextSource(val url: String, userName: String, password: String) extends ContextSource, Initializing, Disposable, Logging {

  private var properties = new jl.Hashtable[String, String]

  override def init(): Unit = {
    val env = enviroment
    env.putAll(properties)
    properties = env
  }

  private def enviroment: jl.Hashtable[String, String] = {
    val env = new jl.Hashtable[String, String]
    env.put(INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory")
    env.put(PROVIDER_URL, url)
    env.put(SECURITY_AUTHENTICATION, "simple")
    env.put(SECURITY_PRINCIPAL, userName)
    env.put(SECURITY_CREDENTIALS, password)
    env.put("com.sun.jndi.ldap.connect.pool", "true")
    env.put("com.sun.jndi.ldap.connect.pool.timeout", "300000")
    env.put("com.sun.jndi.ldap.connect.pool.maxsize", "100")
    env
  }

  def get(): DirContext = {
    new InitialDirContext(properties)
  }

  def release(ctx: DirContext): Unit = {
    if (ctx != null) ctx.close()
  }

  def destroy(): Unit = {

  }
}
