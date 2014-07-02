package org.beangle.security.realm.cas

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.realm.cas.vendor.NeusoftCasTicketValidator

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind(classOf[CasConfig]).constructor($("security.cas.server"))
    bind(classOf[CasEntryPoint])
    bind(classOf[DefaultCasRealm], classOf[CasPreauthFilter])
    bind(classOf[Cas20ServiceTicketValidator], classOf[NeusoftCasTicketValidator])
  }
}