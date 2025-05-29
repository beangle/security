security
========

Beangle Security Library


## generate session's protobuf file

    wget -P ~/bin  https://maven.aliyun.com/repository/public/com/google/protobuf/protoc/4.31.1/protoc-4.31.1-linux-x86_64.exe
    chmod +x ~/bin/protoc-4.31.1-linux-x86_64.exe
    ~/bin/protoc-4.31.1-linux-x86_64.exe  --java_out=src/main/java -Isrc/main/resources src/main/resources/org/beangle/security/session/protobuf/model.proto
