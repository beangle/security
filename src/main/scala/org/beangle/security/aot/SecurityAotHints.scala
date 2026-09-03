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

package org.beangle.security.aot

import org.beangle.commons.aot.AotHintRegistrar
import org.beangle.security.authc.*
import org.beangle.security.authz.*
import org.beangle.security.mgt.*
import org.beangle.security.realm.*
import org.beangle.security.session.*
import org.beangle.security.web.*

/** beangle-security 的 GraalVM native-image 反射提示。 */
class SecurityAotHints extends AotHintRegistrar {

  override def registering(): Unit = {
    // authc
    hints.registerType(
      classOf[AbstractAuthenticator],
      classOf[AccountStore],
      classOf[AuthenticationListener],
      classOf[Authenticator],
      classOf[CredentialChecker],
      classOf[CredentialStore],
      classOf[DBCredentialStore],
      classOf[PasswordPolicy],
      classOf[PasswordPolicyProvider])

    // authz
    hints.registerType(
      classOf[AbstractRoleBasedAuthorizer],
      classOf[Authorizer])

    // mgt
    hints.registerType(
      classOf[SecurityManager])

    // realm
    hints.registerType(
      classOf[Realm],
      classOf[org.beangle.security.realm.ldap.LdapCredentialStore])

    // session
    hints.registerType(
      classOf[SessionProfileProvider],
      classOf[SessionRegistry],
      classOf[SessionRepo],
      classOf[org.beangle.security.session.cache.CacheSessionRepo],
      classOf[org.beangle.security.session.jdbc.DomainProvider])

    // web
    hints.registerType(
      classOf[EntryPoint],
      classOf[UrlEntryPoint],
      classOf[org.beangle.security.web.access.AccessDeniedHandler],
      classOf[org.beangle.security.web.access.SecurityContextBuilder],
      classOf[org.beangle.security.web.access.SecurityFilter],
      classOf[org.beangle.security.web.session.CookieSessionIdPolicy],
      classOf[org.beangle.security.web.session.SessionIdPolicy],
      classOf[org.beangle.security.web.session.SessionIdReader])

    hints.registerType(classOf[org.beangle.security.authc.DefaultAccount])
    hints.registerType(classOf[org.beangle.security.authc.Profile])
    // Scala 3 枚举（实体/会话模型属性类型）
    hints.registerEnum(classOf[EventType])
    hints.registerEnum(classOf[Scope])
  }

}
