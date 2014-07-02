package org.beangle.security.web

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.authc.RealmAuthenticator
import org.beangle.security.mgt.DefaultSecurityManager
import org.beangle.security.session.{DefaultSessionBuilder, MemSessionRegistry}
import org.beangle.security.web.access.{DefaultAccessDeniedHandler, HttpMethodPermissionFilter, SecurityFilter}

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind(classOf[DefaultSecurityManager])
    bind(classOf[MemSessionRegistry], classOf[DefaultSessionBuilder])
    bind(classOf[HttpMethodPermissionFilter])

    bind(classOf[UrlEntryPoint]).constructor($("security.login.url"))
    bind(classOf[RealmAuthenticator],classOf[SecurityFilter])
    bind(classOf[DefaultAccessDeniedHandler]).constructor($("security.access.errorPage"))
  }
}