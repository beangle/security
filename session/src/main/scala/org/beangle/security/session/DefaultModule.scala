package org.beangle.security.session

import org.beangle.commons.inject.bind.AbstractBindModule

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind(classOf[DefaultSessionBuilder])
    bind(classOf[SessionCleaner])
  }
}