#test json
add_executable(test_json test_json.cpp)
target_include_directories(test_json PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_json PRIVATE greenaddress nlohmann_json::nlohmann_json)

# test networks
add_executable(test_networks test_networks.cpp)
target_include_directories(test_networks PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_networks PRIVATE greenaddress nlohmann_json::nlohmann_json)

# test session
add_executable(test_session test_session.cpp)
target_include_directories(test_session PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_session PRIVATE greenaddress nlohmann_json::nlohmann_json)

# test multisession
add_executable(test_multi_session test_multi_session.cpp)
target_include_directories(test_multi_session PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_multi_session PRIVATE greenaddress nlohmann_json::nlohmann_json pthread)

# test aes gcm
add_executable(test_aes_gcm test_aes_gcm.cpp)
target_include_directories(test_aes_gcm PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(test_aes_gcm PRIVATE greenaddress nlohmann_json::nlohmann_json)

# test gdk commit
add_executable(test_gdk_commit test_gdk_commit.cpp)
get_target_property(ga_build_dir greenaddress BINARY_DIR)
get_target_property(ga_src_dir greenaddress SOURCE_DIR)
target_include_directories(test_gdk_commit PRIVATE ${ga_build_dir} ${ga_src_dir})
target_link_libraries(test_gdk_commit PRIVATE greenaddress)

add_test(NAME test_json COMMAND test_json)
add_test(NAME test_networks COMMAND test_networks)
add_test(NAME test_gdk_commit COMMAND test_gdk_commit)
