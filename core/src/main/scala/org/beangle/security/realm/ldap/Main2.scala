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

import java.io.{ BufferedReader, InputStreamReader }

import org.beangle.commons.lang.{ Consoles, Strings }
import org.beangle.security.codec.DefaultPasswordEncoder
import java.io.FileReader
import java.io.File
import org.beangle.commons.csv.CsvReader
import java.io.FileWriter
import org.beangle.commons.csv.CsvWriter

object Main2 {

  private def getStore(url: String, username: String, password: String, base: String): LdapUserStore = {
    val ctx = new PoolingContextSource(url, username, password)
    ctx.init()
    new SimpleLdapUserStore(ctx, base)
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

    val store = getStore("ldap://" + host, username, password, base)
    val accountReader = new FileReader(new File("/Users/chaostone/data-1497760352517.csv"))
    val accountWriter = new FileWriter(new File("/Users/chaostone/data-1497760352517_new.csv"))
    val accountCsvReader = new CsvReader(accountReader)
    val accountCsvWriter = new CsvWriter(accountWriter)
    accountCsvReader.readNext()
    var result = accountCsvReader.readNext()
    var i = 1
    while (null != result) {
      val name = result(0)
      println(s"processing $i")
      val pwd = store.getUserDN(name) match {
        case Some(dn) =>
          val p = store.getPassword(dn).getOrElse("??1")
          if (p == "??1") println(s"$i $name missing passwd")
          p
        case None =>
          println(s"processing $i $name and entry is missing")
          "???"
      }
      accountCsvWriter.write(Array(result(0), pwd))
      result = accountCsvReader.readNext()
      i += 1
    }
    accountCsvWriter.close();
  }

}
