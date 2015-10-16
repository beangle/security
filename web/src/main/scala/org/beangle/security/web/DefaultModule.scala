/*
 * Beangle, Agile Development Scaffold and Toolkit
 *
 * Copyright (c) 2005-2015, Beangle Software.
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
package org.beangle.security.web

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.authc.RealmAuthenticator
import org.beangle.security.mgt.DefaultSecurityManager
import org.beangle.security.web.access.{ AuthorizationFilter, DefaultAccessDeniedHandler, SecurityInterceptor }
import org.beangle.security.web.session.DefaultSessionIdPolicy

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind("security.SecurityManager.default", classOf[DefaultSecurityManager])
    bind("security.Filter.authorization", classOf[AuthorizationFilter])

    bind("security.EntryPoint.url", classOf[UrlEntryPoint]).constructor($("security.login.url"))
    bind("security.Authenticator.realm", classOf[RealmAuthenticator])
    bind(classOf[DefaultAccessDeniedHandler]).constructor($("security.access.errorPage", "/403.html"))

    bind("web.Interceptor.security", classOf[SecurityInterceptor])
    bind("security.SessionIdPolicy.default", classOf[DefaultSessionIdPolicy])
  }
}