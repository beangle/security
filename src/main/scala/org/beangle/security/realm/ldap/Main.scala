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

import org.beangle.commons.lang.{Consoles, Strings}
import org.beangle.security.codec.DefaultPasswordEncoder

import java.io.{BufferedReader, InputStreamReader}

object Main {

  private def getStore(url: String, username: String, password: String, base: String): LdapUserStore = {
    val ctx = new PoolingContextSource(url, username, password)
    ctx.init()
    new SimpleLdapUserStore(ctx, base)
  }

  private def tryGet(store: LdapUserStore, name: String): Option[String] = {
    store.getUserDN(name) match {
      case Some(dname) =>
        val details = store.getAttributes(dname)
        println("Find:" + name)
        println("dn:" + dname)
        println("detail:" + details)
        Some(dname)
      case None =>
        println("Cannot find :" + name)
        None
    }
  }

  private def tryTestPassword(store: LdapCredentialStore, uid: String, password: String): Unit = {
    val rs = store.getPassword(uid) match {
      case Some(p) => DefaultPasswordEncoder.verify(p, password)
      case None => false
    }
    println("password " + (if (rs) " ok! " else " WRONG!"))
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
    val userStore = getStore("ldap://" + host, username, password, base)
    val credentialStore = new LdapCredentialStore(userStore)
    println("display/verify/change user/password: ")
    val stdin = new BufferedReader(new InputStreamReader(System.in))
    var value = stdin.readLine()
    while (Strings.isNotBlank(value)) {
      if (value == "quit" || value == "q" || value == "exit") System.exit(0)
      val action = Strings.substringBefore(value, " ")
      value = Strings.substringAfterLast(value, " ")
      var myname: String = value
      var mypass: String = null
      if (value.contains("/")) {
        myname = Strings.substringBefore(value, "/")
        mypass = Strings.substringAfter(value, "/")
      }
      if (action == "verify") {
        tryTestPassword(credentialStore, myname, mypass)
      } else if (action == "change") {
        val mypassRaw = DefaultPasswordEncoder.generate(mypass, null, "sha")
        credentialStore.updatePassword(myname, mypassRaw)
        tryTestPassword(credentialStore, myname, mypass)
      } else if (action == "display") {
        userStore.getUserDN(myname) match
          case Some(dn) =>
            println(s"dn:${dn}")
            userStore.getAttributes(dn).foreach(e => println(e._1 + ":" + e._2))
          case None => println(s"Cannot find user ${myname}")
      }
      println("display/verify/change user[/password]: ")
      value = stdin.readLine()
    }

  }

}
