security
========

Beangle Security Framework


## generate session's protobuf file

    wget -P ~/bin  https://maven.aliyun.com/repository/public/com/google/protobuf/protoc/3.25.1/protoc-3.25.1-linux-x86_64.exe
    chmod +x ~/bin/protoc-3.25.1-linux-x86_64.exe
    ~/bin/protoc-3.25.1-linux-x86_64.exe  --java_out=src/main/java -Isrc/main/resources src/main/resources/org/beangle/security/session/protobuf/model.proto
