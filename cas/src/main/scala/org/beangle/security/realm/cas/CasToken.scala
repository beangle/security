package org.beangle.security.realm.cas

import org.beangle.security.web.PreauthToken

class CasToken(t: String) extends PreauthToken(t) {

  def ticket: String = principal.toString

  details += (CasConfig.TicketName -> principal.toString)
}