cmake_minimum_required(VERSION 3.15)
project(roni_client CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(client_app
    main.cpp
    client/Client.cpp
    client/Config.cpp
    client/User.cpp
    protocol/Request.cpp
    protocol/Response.cpp
    transport/TCP.cpp
    crypto/AESWrapper.cpp
    crypto/Base64Wrapper.cpp
    crypto/RSAWrapper.cpp
    crypto/cksum.cpp
)

# CryptoPP (libcrypto++-dev) and pthread (needed by Boost.Asio). Boost.Asio is
# header-only; its headers come from the system include path.
target_link_libraries(client_app PRIVATE cryptopp pthread)

# The IDE runs the binary from the build folder, so put the input files next to
# it (transfer.info and the file it points to). me.info is written here too.
add_custom_command(TARGET client_app POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/transfer.json $<TARGET_FILE_DIR:client_app>/transfer.json
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_SOURCE_DIR}/sample.txt $<TARGET_FILE_DIR:client_app>/sample.txt)
