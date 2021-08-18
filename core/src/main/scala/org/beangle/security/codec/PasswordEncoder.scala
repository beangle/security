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

package org.beangle.security.codec

import java.security.MessageDigest

import org.beangle.commons.codec.binary.{Base64, Hex}
import org.beangle.commons.lang.Arrays

/**
 * @author chaostone
 */
trait PasswordEncoder {
  def verify(digest: String, password: String): Boolean

  def generate(password: String, saltHex: String, algorithm: String): String
}

object DefaultPasswordEncoder extends PasswordEncoder {

  override def verify(digest: String, password: String): Boolean = {
    var alg: String = null
    var size = 0
    var digestContent = digest
    if (digest.regionMatches(true, 0, "{SHA}", 0, 5)) {
      digestContent = digest.substring(5)
      alg = "SHA-1"
      size = 20
    } else if (digest.regionMatches(true, 0, "{SSHA}", 0, 6)) {
      digestContent = digest.substring(6)
      alg = "SHA-1"
      size = 20
    } else if (digest.regionMatches(true, 0, "{MD5}", 0, 5)) {
      digestContent = digest.substring(5)
      alg = "MD5"
      size = 16
    } else if (digest.regionMatches(true, 0, "{SMD5}", 0, 6)) {
      digestContent = digest.substring(6)
      alg = "MD5"
      size = 16
    } else {
      return digestContent.equals(password)
    }

    val msgDigest = MessageDigest.getInstance(alg)

    val hs =
      if (alg.contains("MD5")) {
        if (digestContent.length == 32 && !digestContent.contains("=")) {
          split(Hex.decode(digestContent), size)
        } else {
          split(Base64.decode(digestContent.toCharArray), size)
        }
      } else {
        split(Base64.decode(digestContent.toCharArray), size)
      }

    msgDigest.reset()
    msgDigest.update(password.getBytes)
    msgDigest.update(hs._2)
    MessageDigest.isEqual(hs._1, msgDigest.digest())
  }

  def generate(password: String, salts: String, algorithm: String): String = {
    val alg =
      if (algorithm.equalsIgnoreCase("sha")) "SHA-1"
      else if (algorithm.equalsIgnoreCase("md5")) "MD5"
      else algorithm

    val msgDigest = MessageDigest.getInstance(alg)
    val salt = if (salts == null) new Array[Byte](0) else salts.getBytes
    val label =
      if (alg.startsWith("SHA")) {
        if (salt.length <= 0) "{SHA}" else "{SSHA}"
      }
      else if (alg.startsWith("MD5")) {
        if (salt.length <= 0) "{MD5}" else "{SMD5}"
      }
      else null
    msgDigest.reset()
    msgDigest.update(password.getBytes)
    msgDigest.update(salt)
    val pwhash = msgDigest.digest()
    val digest = new StringBuilder(if (null == label) "" else label)
    val hash =
      if (alg.contains("MD5")) {
        Hex.encode(Arrays.concat(pwhash, salt))
      } else {
        Base64.encode(Arrays.concat(pwhash, salt))
      }
    digest.append(hash)
    digest.toString
  }

  private def split(src: Array[Byte], n: Int): (Array[Byte], Array[Byte]) = {
    var l: Array[Byte] = null
    var r: Array[Byte] = null
    if (src.length <= n) {
      l = src
      r = new Array(0)
    } else {
      l = new Array[Byte](n)
      r = new Array[Byte](src.length - n)
      System.arraycopy(src, 0, l, 0, n)
      System.arraycopy(src, n, r, 0, r.length)
    }
    (l, r)
  }

}
