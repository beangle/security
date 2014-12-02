package org.beangle.security.web

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.authc.RealmAuthenticator
import org.beangle.security.mgt.DefaultSecurityManager
import org.beangle.security.session.{ DefaultSessionBuilder, MemSessionRegistry }
import org.beangle.security.web.access.{ AuthorizationFilter, DefaultAccessDeniedHandler, SecurityInterceptor }
import org.beangle.security.web.session.DefaultSessionIdPolicy

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind("security.SecurityManager.default", classOf[DefaultSecurityManager])
    bind(classOf[MemSessionRegistry], classOf[DefaultSessionBuilder])
    bind("security.Filter.authorization", classOf[AuthorizationFilter])

    bind("security.EntryPoint.url", classOf[UrlEntryPoint]).constructor($("security.login.url"))
    bind("security.Authenticator.realm", classOf[RealmAuthenticator])
    bind(classOf[DefaultAccessDeniedHandler]).constructor($("security.access.errorPage", "/403.html"))

    bind("web.Interceptor.security", classOf[SecurityInterceptor])
    bind("security.SessionIdPolicy.default", classOf[DefaultSessionIdPolicy])
  }
}