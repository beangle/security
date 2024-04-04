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
import org.beangle.commons.logging.{Logger, Logging}
import org.beangle.security.realm.ltpa.LtpaTokenGenerator.*

import java.lang.System.arraycopy
import java.security.MessageDigest
import java.util.{Calendar, TimeZone}

object LtpaTokenGenerator {
  private val DominoHeader = Array[Byte](0, 1, 2, 3)

  def apply(base64EncodedKey: String, usernameDns: Array[String] = null): LtpaTokenGenerator = {
    new LtpaTokenGenerator(Base64.decode(base64EncodedKey), usernameDns)
  }
}

class LtpaTokenGenerator(securityKey: Array[Byte], usernameDns: Array[String]) extends Logging {

  var maxAge: Long = 43200L //12hours

  def generate(username: String): LtpaToken = {
    if (null == username) then null
    else try {
      val cal = Calendar.getInstance(TimeZone.getTimeZone("GMT0"))
      val createTime = cal.getTimeInMillis / 1000L
      val expireTime = createTime + maxAge
      val create = java.lang.Long.toHexString(createTime).toUpperCase.getBytes
      val expire = java.lang.Long.toHexString(expireTime).toUpperCase.getBytes
      val user = username.getBytes("UTF-8")
      val bytes = new Array[Byte](20 + user.length)
      arraycopy(DominoHeader, 0, bytes, 0, 4)
      arraycopy(create, 0, bytes, 4, 8)
      arraycopy(expire, 0, bytes, 12, 8)
      arraycopy(user, 0, bytes, 20, user.length)
      val md = MessageDigest.getInstance("SHA-1")
      md.update(bytes)
      val digest = md.digest(this.securityKey)
      val token = new Array[Byte](bytes.length + digest.length)
      arraycopy(bytes, 0, token, 0, bytes.length)
      arraycopy(digest, 0, token, bytes.length, digest.length)
      val tokenString = new String(Base64.encode(token))
      LtpaToken(expireTime * 1000L, username, tokenString)
    } catch {
      case var15: Exception => logger.error("加密Token信息发生错误：" + var15.getMessage)
        null
    }
  }

  def parse(tokenString: String): LtpaToken = {
    if (null != tokenString && "\"\"" != tokenString) {
      try {
        val token = Base64.decode(tokenString)
        if (!this.verify(token)) null
        else {
          var bytes = new Array[Byte](8)
          arraycopy(token, 12, bytes, 0, 8)
          val expire = java.lang.Long.parseLong(new String(bytes), 16) * 1000L
          val length = token.length - 40 //(header+c+e=20 + sha1_digest=20)
          bytes = new Array[Byte](length)
          arraycopy(token, 20, bytes, 0, length)
          val username = this.extractUser(new String(bytes, "UTF-8"))
          LtpaToken(expire, username, tokenString)
        }
      } catch {
        case var10: Exception => logger.info("解密Token信息发生错误：" + var10.getMessage)
          null
      }
    } else null
  }

  private def extractUser(user: String): String = {
    val userInfo = user.split("\\s*[/,;]\\s*")
    if (userInfo.length > 1 && this.usernameDns != null && this.usernameDns.length > 0) {
      var i = 0
      while (i < this.usernameDns.length) {
        val key = (this.usernameDns(i) + "=").toUpperCase
        userInfo.find(_.toUpperCase.startsWith(key)) match
          case None =>
          case Some(ui) => return ui.substring(key.length)
        i += 1
      }
    }
    val i = userInfo(0).indexOf('=')
    if (i == -1) userInfo(0) else userInfo(0).substring(i + 1)
  }

  /** Verify token
   * header(4)+creation(8)+expiration(8)+username(n)+sha1_digest(20)
   *
   * @param token raw token bytes
   * @return true when token is valid
   */
  private def verify(token: Array[Byte]) = {
    //last digest is 20bytes
    val length = token.length - 20
    val curDigest = new Array[Byte](20)
    arraycopy(token, length, curDigest, 0, 20)

    //sha1 header+creation+expiration+username
    val bytes = new Array[Byte](length + this.securityKey.length)
    arraycopy(token, 0, bytes, 0, length)
    arraycopy(this.securityKey, 0, bytes, length, this.securityKey.length)

    val newDigest = MessageDigest.getInstance("SHA-1").digest(bytes)
    MessageDigest.isEqual(curDigest, newDigest)
  }
}
