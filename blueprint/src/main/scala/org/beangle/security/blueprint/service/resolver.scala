package org.beangle.security.blueprint.service

import org.beangle.commons.bean.PropertyUtils
import org.beangle.commons.lang.Strings
import org.beangle.commons.conversion.impl.DefaultConversion
import org.beangle.security.blueprint.Field

trait DataResolver {
  def marshal(field: Field, items: Seq[Any]): String
  def unmarshal[T](field: Field, text: String): Seq[T]
}

trait DataProvider {
  def getData[T](field: Field, source: String, keys: Any*): Seq[T]
}
