## generate session's protobuf file

    wget -x -P ~/bin/ https://repo.maven.apache.org/maven2/com/google/protobuf/protoc/3.25.1/protoc-3.25.1-linux-x86_64.exe

    ~/bin/protoc-3.25.1-linux-x86_64.exe  --java_out=src/main/java -Isrc/main/resources src/main/resources/org/beangle/security/session/protobuf/model.proto
