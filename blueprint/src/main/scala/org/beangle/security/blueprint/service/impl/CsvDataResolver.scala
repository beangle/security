package org.beangle.security.blueprint.service.impl

import org.beangle.commons.bean.Properties
import org.beangle.commons.conversion.impl.DefaultConversion
import org.beangle.commons.lang.Strings
import org.beangle.security.blueprint.Dimension
import org.beangle.security.blueprint.service.DataResolver

object CsvDataResolver extends DataResolver {

  def marshal(field: Dimension, items: Seq[Any]): String = {
    if (null == items || items.isEmpty) return ""
    val properties = new collection.mutable.ListBuffer[String]
    if (null != field.keyName) properties += field.keyName
    if (null != field.properties) properties ++= Strings.split(field.properties, ",")
    val sb = new StringBuilder()
    if (properties.isEmpty) {
      for (obj <- items) if (null != obj) sb.append(String.valueOf(obj)).append(',')
    } else {
      for (prop <- properties) sb.append(prop).append(';')
      sb.deleteCharAt(sb.length() - 1).append(',')

      for (obj <- items) {
        for (prop <- properties) {
          try {
            val value: Any = Properties.get(obj, prop);
            sb.append(String.valueOf(value)).append(';')
          } catch {
            case e: Exception => e.printStackTrace()
          }
        }
        sb.deleteCharAt(sb.length() - 1)
        sb.append(',')
      }
    }
    if (sb.length() > 0) sb.deleteCharAt(sb.length() - 1)
    sb.toString()
  }

  def unmarshal[T](field: Dimension, source: String): Seq[T] = {
    if (Strings.isEmpty(source)) return List.empty

    val properties = new collection.mutable.ListBuffer[String]
    if (null != field.keyName) properties += field.keyName
    if (null != field.properties) properties ++= Strings.split(field.properties, ",")

    val datas = Strings.split(source, ",")
    val clazz = Class.forName(field.typeName).asInstanceOf[Class[T]]
    val rs = new collection.mutable.ListBuffer[T];
    if (properties.isEmpty) {
      val conversion = DefaultConversion.Instance;
      for (data <- datas) rs += conversion.convert(data, clazz)
      return rs
    } else {
      properties.clear()
      var startIndex = 0
      var names = Array(field.keyName)
      if (-1 != datas(0).indexOf(';')) {
        names = Strings.split(datas(0), ";")
        startIndex = 1
      }
      properties ++= names
      (startIndex until datas.length) foreach { i =>
        val obj = clazz.newInstance().asInstanceOf[AnyRef]
        val dataItems = Strings.split(datas(i), ";")
        (0 until properties.size) foreach { j =>
          Properties.copy(obj, properties(j), dataItems(j))
        }
        rs += obj.asInstanceOf[T]
      }
    }
    rs
  }
}