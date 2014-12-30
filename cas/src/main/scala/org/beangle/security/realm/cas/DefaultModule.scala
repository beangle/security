package org.beangle.security.realm.cas

import org.beangle.commons.inject.bind.AbstractBindModule
import org.beangle.security.realm.cas.vendor.NeusoftCasTicketValidator

class DefaultModule extends AbstractBindModule {

  protected override def binding() {
    bind(classOf[CasConfig]).constructor($("security.cas.server"))
    bind("security.EntryPoint.cas", classOf[CasEntryPoint])
    bind("security.Realm.cas", classOf[DefaultCasRealm])
    bind("security.Filter.cas", classOf[CasPreauthFilter])
    bind("security.TicketValidator.cas20", classOf[Cas20ServiceTicketValidator])
    bind("security.TicketValidator.neusoft", classOf[NeusoftCasTicketValidator])
  }
}