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

import org.beangle.commons.collection.Collections
import org.beangle.commons.json.{Json, JsonObject}
import org.beangle.commons.lang.Charsets

import java.time.{Duration, Instant}
import java.util.Base64
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Mac, SecretKey}

object JwtDigest {
  private val URL_ENCODER = Base64.getUrlEncoder
  private val URL_DECODER = Base64.getUrlDecoder

  /** URL 安全的 Base64编码
   *
   * @param jsonStr
   * @return
   */
  def urlEncode(jsonStr: String): String = {
    urlEncode(jsonStr.getBytes(Charsets.UTF_8))
  }

  def urlEncode(bytes: Array[Byte]): String = {
    URL_ENCODER.encodeToString(bytes).replace("=", "")
  }

  def urlDecode(base64UrlStr: String): String = {
    val padding = (4 - base64UrlStr.length % 4) % 4
    val sb = new StringBuilder(base64UrlStr)
    for (i <- 0 until padding) {
      sb.append("=")
    }
    val decodedBytes = URL_DECODER.decode(sb.toString)
    new String(decodedBytes, Charsets.UTF_8)
  }

  def getClaims(token: String): JsonObject = {
    val parts = token.split("\\.")
    if (parts.length < 2) throw new RuntimeException("JWT 格式非法，缺少 Payload 部分")
    val json = JwtDigest.urlDecode(parts(1))
    Json.parseObject(new String(json))
  }
}

class JwtDigest(secret: String) {
  private val key = buildKey(secret.getBytes)
  private var length = 256

  def generateToken(claims: collection.Map[String, Any], expiresIn: Duration): String = {
    var payload: String = null
    if (claims.contains("exp")) {
      payload = Json.toJson(claims)
    } else {
      val newClaims = Collections.newMap[String, Any]
      newClaims.addAll(claims)
      newClaims.put("exp", Instant.now.plusSeconds(expiresIn.toSeconds).getEpochSecond.intValue)
    }

    val header = s"""{"alg":"${jwtAlgo}"}"""
    val body = JwtDigest.urlEncode(header) + "." + JwtDigest.urlEncode(payload)
    body + "." + JwtDigest.urlEncode(digest(body.getBytes))
  }

  def generateToken(claims: collection.Map[String, Any]): String = {
    generateToken(claims, Jwts.DefaultExpiresIn)
  }

  def validateToken(token: String): Boolean = {
    val lastDot = token.lastIndexOf('.')
    if (lastDot == -1) {
      false
    } else {
      val claims = JwtDigest.getClaims(token)
      val exp = claims.getInt("exp", 0)
      if (exp == 0 || exp < Instant.now.getEpochSecond) {
        false
      } else {
        val body = token.substring(0, lastDot)
        val signature = token.substring(lastDot + 1)
        JwtDigest.urlEncode(digest(body.getBytes)) == signature
      }
    }
  }

  def digest(s: String): String = {
    new String(digest(s.getBytes()), Charsets.UTF_8)
  }

  def digest(bytes: Array[Byte]): Array[Byte] = {
    val mac = Mac.getInstance(s"HmacSHA${length}")
    mac.init(key)
    mac.update(bytes, 0, bytes.length)
    mac.doFinal()
  }

  def jwtAlgo: String = {
    s"HS$length"
  }

  private def buildKey(bytes: Array[Byte]): SecretKey = {
    require(bytes != null && bytes.length * 8 >= 256, "HMAC-SHA need at least 256 bytes")

    val len = bytes.length * 8
    if (len >= 512) {
      length = 512
      new SecretKeySpec(bytes, "HmacSHA512")
    } else if (len >= 384) {
      length = 384
      new SecretKeySpec(bytes, "HmacSHA384")
    } else {
      length = 256
      new SecretKeySpec(bytes, "HmacSHA256")
    }
  }
}
