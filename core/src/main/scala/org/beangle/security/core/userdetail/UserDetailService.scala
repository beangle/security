package org.beangle.security.core.userdetail

trait UserDetailService {

  def loadDetail(principle: String): UserDetail
}
