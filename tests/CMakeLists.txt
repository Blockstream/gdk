#test json
add_executable(test_json test_json.cpp)
target_include_directories(test_json PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_json PRIVATE greenaddress-static)

# test networks
add_executable(test_networks test_networks.cpp)
target_include_directories(test_networks PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_networks PRIVATE greenaddress-static)

# test session
add_executable(test_session test_session.cpp)
target_include_directories(test_session PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_session PRIVATE greenaddress-static)

# test multisession
add_executable(test_multi_session test_multi_session.cpp)
target_include_directories(test_multi_session PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_multi_session PRIVATE greenaddress-static)

# test aes gcm
add_executable(test_aes_gcm test_aes_gcm.cpp)
target_include_directories(test_aes_gcm PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_aes_gcm PRIVATE greenaddress-static)


add_test(NAME test_json COMMAND test_json)
add_test(NAME test_networks COMMAND test_networks)

