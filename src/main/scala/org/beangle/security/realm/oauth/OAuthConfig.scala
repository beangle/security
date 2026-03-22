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

package org.beangle.security.realm.oauth

import org.beangle.commons.lang.Strings

class OAuthConfig(val server: String,val clientId: String) {

  val oauthServer: String = Strings.stripEnd(server, "/")

  var authorizeUri = "/oauth/authorize"

  var tokenUri = "/oauth/token"

  var clientSecret: String = _

  var scope: Option[String] = None

  def authorizeUrl: String = oauthServer + authorizeUri

  def tokenUrl: String = oauthServer + tokenUri

}
