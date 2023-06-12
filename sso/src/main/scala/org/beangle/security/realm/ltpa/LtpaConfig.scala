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

package org.beangle.security.realm.ltpa

import org.beangle.commons.codec.binary.Base64
import org.beangle.commons.lang.Strings

object LtpaConfig {
  def apply(server: String, key: String, cookieName: String, usernameDns: String): LtpaConfig = {
    val s = if !server.startsWith("http://") && !server.startsWith("https://") then "http://" + server else server
    val ck = if Strings.isBlank(cookieName) then "LtpaToken" else cookieName
    val prefixes = if (Strings.isBlank(usernameDns)) Array.empty[String] else usernameDns.trim.split("\\s*[,;]\\s*")
    new LtpaConfig(s, Base64.decode(key), ck, prefixes)
  }
}

class LtpaConfig(val server: String, val key: Array[Byte], val cookieName: String, val usernameDns: Array[String]) {

}
