/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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

import java.io.{ BufferedReader, InputStreamReader }

import org.beangle.commons.lang.{ Consoles, Strings }

object Main {

  private def getStore(url: String, username: String, password: String, base: String): LdapUserService = {
    val ctx = new PoolingContextSource(url, username, password)
    ctx.init()
    new DefaultLdapUserService(ctx, base)
  }

  private def tryGet(store: LdapUserService, name: String) {
    val dn = store.getUserDN(name) match {
      case Some(dn) =>
        val details = store.getAttributes(dn)
        println("Find:" + name)
        println("dn:" + dn)
        println("detail:" + details)
      case None =>
        println("Cannot find :" + name)
    }
  }

  private def tryTestPassword(store: LdapUserService, name: String, password: String) {
    val checker = new DefaultCredentialsChecker(store)
    val isTrue = checker.check(name, password)
    println("password " + (if (isTrue) " ok! " else " WRONG!"))
  }

  def main(args: Array[String]): Unit = {
    var host, username, password, base = ""
    if (args.length < 4) {
      println("Usage: LdapMain host:port base username password")
      host = Consoles.prompt("host:port = ")
      base = Consoles.prompt("base DN = ")
      username = Consoles.prompt("username = ")
      password = Consoles.prompt("password = ")
    } else {
      host = args(0)
      base = args(1)
      username = args(2)
      password = args(3)
    }

    println("Connecting to ldap://" + host)
    println("Using base:" + base)
    val store = getStore("ldap://" + host, username, password, base)
    println("Enter query user[/password]: ")
    val stdin = new BufferedReader(new InputStreamReader(System.in))
    var value = stdin.readLine()
    while (Strings.isNotBlank(value)) {
      var myname = value
      var mypass: String = null
      if (value.contains("/")) {
        myname = Strings.substringBefore(value, "/")
        mypass = Strings.substringAfter(value, "/")
      }
      try {
        tryGet(store, myname)
        if (null != mypass) {
          tryTestPassword(store, myname, mypass)
        }
      } catch {
        case e: Exception => e.printStackTrace()
      } finally {
        println("Enter query user[/password]: ")
      }
      value = stdin.readLine()
    }
  }

}
