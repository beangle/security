import Dependencies._
import BuildSettings._
import sbt.url

ThisBuild / organization := "org.beangle.webmvc"
ThisBuild / version := "4.2.30"

ThisBuild / scmInfo := Some(
  ScmInfo(
    url("https://github.com/beangle/webmvc"),
    "scm:git@github.com:beangle/webmvc.git"
  )
)

ThisBuild / developers := List(
  Developer(
    id    = "chaostone",
    name  = "Tihua Duan",
    email = "duantihua@gmail.com",
    url   = url("http://github.com/duantihua")
  )
)

ThisBuild / description := "The Beangle Data Library"
ThisBuild / homepage := Some(url("https://beangle.github.io/webmvc/index.html"))
ThisBuild / resolvers += Resolver.mavenLocal

lazy val root = (project in file("."))
  .settings()
  .aggregate(core,cas,session,web)

lazy val core = (project in file("core"))
  .settings(
    name := "beangle-security-core",
    commonSettings,
    libraryDependencies ++= commonDeps
  )

lazy val session = (project in file("session"))
  .settings(
    name := "beangle-security-session",
    commonSettings,
    libraryDependencies ++= (commonDeps ++ Seq(cacheApi,dataJdbc,serializerProtobuf))
  ).dependsOn(core)

lazy val web = (project in file("web"))
  .settings(
    name := "beangle-security-web",
    commonSettings,
    libraryDependencies ++= (commonDeps ++ Seq(webServlet))
  ).dependsOn(core)

lazy val cas = (project in file("cas"))
  .settings(
    name := "beangle-security-cas",
    commonSettings,
    libraryDependencies ++= (commonDeps ++ Seq(mockito))
  ).dependsOn(web)

publish / skip := true
