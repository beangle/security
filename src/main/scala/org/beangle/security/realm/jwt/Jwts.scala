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

package org.beangle.security.realm.jwt

import org.beangle.commons.json.JsonObject

import java.time.{Duration, Instant}

object Jwts {

  def getClaims(token: String): JsonObject = {
    JwtDigest.getClaims(token)
  }

  def digest(key: String): JwtDigest = {
    new JwtDigest(key)
  }

  def generateToken(secret: String, data: collection.Map[String, String]): String = {
    Jwts.builder().claims(data).sign(secret)
  }

  def validateToken(secret: String, token: String): Boolean = {
    new JwtDigest(secret).validateToken(token)
  }

  class JwtBuider {

    private var _claims: Map[String, String] = Map.empty

    def expiredAfter(d: Duration): JwtBuider = {
      val issuedAt = Instant.now
      _claims = _claims.updated("iat", issuedAt.getEpochSecond.toString)
      _claims = _claims.updated("exp", issuedAt.plusSeconds(d.getSeconds).getEpochSecond.toString)
      this
    }

    def claims(content: collection.Map[String, String]): JwtBuider = {
      this._claims = this._claims ++ content
      this
    }

    def sign(key: String): String = {
      if !_claims.contains("exp") then expiredAfter(Duration.ofHours(2))
      new JwtDigest(key).generateToken(_claims)
    }
  }

  def builder(): JwtBuider = {
    new JwtBuider
  }
}
