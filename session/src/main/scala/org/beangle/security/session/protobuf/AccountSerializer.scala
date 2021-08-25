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

package org.beangle.security.session.protobuf

import java.io.{InputStream, OutputStream}

import org.beangle.commons.io.ObjectSerializer
import org.beangle.commons.lang.Strings
import org.beangle.security.authc.{DefaultAccount, Profile}

object AccountSerializer extends ObjectSerializer {

  def toMessage(account: DefaultAccount): Model.Account = {
    val builder = Model.Account.newBuilder()
    builder.setName(account.name)
    builder.setDescription(account.description)
    builder.setStatus(account.status)
    builder.setCategoryId(account.categoryId)
    account.remoteToken foreach { t =>
      builder.setRemoteToken(t)
    }
    if (null != account.authorities) {
      account.authorities foreach { a =>
        builder.addAuthorities(a)
      }
    }
    if (null != account.permissions) {
      account.permissions foreach { a =>
        builder.addPermissions(a)
      }
    }
    if (null != account.profiles) {
      account.profiles foreach { profile =>
        builder.addProfiles(ProfileSerializer.toMessage(profile))
      }
    }
    account.details foreach {
      case (k, v) =>
        builder.putDetails(k, v)
    }
    builder.build()
  }

  def fromMessage(pa: Model.Account): DefaultAccount = {
    val account = new DefaultAccount(pa.getName, pa.getDescription)
    account.status = pa.getStatus
    account.categoryId = pa.getCategoryId
    val rt = pa.getRemoteToken
    if (Strings.isNotBlank(rt)) {
      account.remoteToken = Some(rt)
    }
    val dk = pa.getDetailsMap.entrySet().iterator()
    while (dk.hasNext) {
      val entry = dk.next()
      account.details += (entry.getKey -> entry.getValue)
    }
    if (pa.getAuthoritiesCount > 0) {
      val authorities = Array.ofDim[String](pa.getAuthoritiesCount)
      (0 until pa.getAuthoritiesCount) foreach { i =>
        authorities(i) = pa.getAuthorities(i)
      }
      account.authorities = authorities
    } else {
      account.authorities = Array.empty[String]
    }
    if (pa.getPermissionsCount > 0) {
      val permissions = Array.ofDim[String](pa.getPermissionsCount)
      (0 until pa.getPermissionsCount) foreach { i =>
        permissions(i) = pa.getPermissions(i)
      }
      account.permissions = permissions
    } else {
      account.permissions = Array.empty[String]
    }
    if (pa.getProfilesCount > 0) {
      val profiles = Array.ofDim[Profile](pa.getProfilesCount)
      (0 until pa.getProfilesCount) foreach { i =>
        profiles(i) = ProfileSerializer.fromMessage(pa.getProfiles(i))
      }
      account.profiles = profiles
    }
    account
  }

  override def serialize(data: Any, os: OutputStream, params: Map[String, Any]): Unit = {
    toMessage(data.asInstanceOf[DefaultAccount]).writeTo(os)
  }

  override def deserialize(is: InputStream, params: Map[String, Any]): Any = {
    fromMessage(Model.Account.parseFrom(is))
  }
}
