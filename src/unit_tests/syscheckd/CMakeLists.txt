# Generate syscheck library
file(GLOB sysfiles ${SRC_FOLDER}/syscheckd/*.o ${SRC_FOLDER}/syscheckd/*/*.o)
list(REMOVE_ITEM sysfiles ${SRC_FOLDER}/syscheckd/main.o)

file(GLOB rootfiles ${SRC_FOLDER}/rootcheck/*.o)

if(${TARGET} STREQUAL "winagent")
  # Exclude winagent files
  list(FILTER sysfiles EXCLUDE REGEX ".*-event.o$")
  list(FILTER rootfiles EXCLUDE REGEX ".*_rk.o$")

  # Add test wrappers
  file(GLOB test_wrapper_files
       ${SRC_FOLDER}/unit_tests/wrappers/externals/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/audit/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/bzip2/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/cJSON/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/openssl/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/procpc/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/externals/sqlite/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/libc/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/linux/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/posix/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_crypto/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_net/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/os_regex/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/syscheckd/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/wazuh_db/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/wazuh/wazuh_modules/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/windows/*.o
       ${SRC_FOLDER}/unit_tests/wrappers/windows/libc/*.o
       )
  list(APPEND sysfiles ${test_wrapper_files})
endif()

add_library(SYSCHECK_O STATIC ${sysfiles})
add_library(ROOTCHECK_O STATIC ${rootfiles})

set_source_files_properties(
  ${sysfiles}
  ${rootfiles}
  PROPERTIES
  EXTERNAL_OBJECT true
  GENERATED true
  )

set_target_properties(
  SYSCHECK_O
  ROOTCHECK_O
  PROPERTIES
  LINKER_LANGUAGE C
  )

target_link_libraries(SYSCHECK_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

# Add fim_tools library to compilation
include_directories((${SRC_FOLDER}/syscheckd))
include_directories((${SRC_FOLDER}/unit_tests))
include_directories((${SRC_FOLDER}/unit_tests/syscheckd))
include_directories((${SRC_FOLDER}/config))

add_library(fim_shared STATIC expect_run_check.c
                              expect_fim_diff_changes.c
                              db/expect_fim_db.c
                              db/expect_fim_db_files.c
                              db/expect_fim_db_registries.c
                              utils.c)

set_target_properties(fim_shared PROPERTIES LINKER_LANGUAGE C )


#include wrappers
include(${SRC_FOLDER}/unit_tests/wrappers/wazuh/shared/shared.cmake)

# Generate syscheckd-event library
if(${TARGET} STREQUAL "winagent")
  file(GLOB syscheck_event_files ${SRC_FOLDER}/syscheckd/*-event.o ${SRC_FOLDER}/syscheckd/*/*-event.o)

  add_library(SYSCHECK_EVENT_O STATIC ${syscheck_event_files})

  set_source_files_properties(
    ${syscheck_event_files}
    PROPERTIES
    EXTERNAL_OBJECT true
    GENERATED true
    )

  set_target_properties(
    SYSCHECK_EVENT_O
    ROOTCHECK_O
    PROPERTIES
    LINKER_LANGUAGE C
    )

  target_link_libraries(SYSCHECK_EVENT_O ROOTCHECK_O ${WAZUHLIB} ${WAZUHEXT} -lpthread)

  add_subdirectory(registry)
endif()

add_subdirectory(db)
add_subdirectory(whodata)

# Generate Syscheckd tests
list(APPEND syscheckd_tests_names "test_syscom")
list(APPEND syscheckd_tests_flags "-Wl,--wrap,getSyscheckConfig -Wl,--wrap,getRootcheckConfig \
                                   -Wl,--wrap,getSyscheckInternalOptions -Wl,--wrap,fim_sync_push_msg \
                                   -Wl,--wrap,getpid ${DEBUG_OP_WRAPPERS}")

# create_db.c tests
add_executable(test_create_db test_create_db.c)

target_compile_options(test_create_db PRIVATE "-Wall")

set(CREATE_DB_BASE_FLAGS "-Wl,--wrap,fim_send_scan_info -Wl,--wrap,send_syscheck_msg \
                          -Wl,--wrap,readdir -Wl,--wrap,opendir -Wl,--wrap,closedir -Wl,--wrap,realtime_adddir \
                          -Wl,--wrap,HasFilesystem -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_get_paths_from_inode \
                          -Wl,--wrap,delete_target_file -Wl,--wrap,OS_MD5_SHA1_SHA256_File \
                          -Wl,--wrap,seechanges_addfile -Wl,--wrap,fim_db_delete_not_scanned \
                          -Wl,--wrap,fim_db_set_all_unscanned -Wl,--wrap,fim_db_set_scanned \
                          -Wl,--wrap,get_group -Wl,--wrap,fim_db_remove_path \
                          -Wl,--wrap,fim_db_get_not_scanned -Wl,--wrap,fim_db_set_all_unscanned \
                          -Wl,--wrap,fim_db_get_count_file_entry -Wl,--wrap,fim_db_get_path_range \
                          -Wl,--wrap,fim_db_process_missing_entry -Wl,--wrap,send_log_msg -Wl,--wrap,IsDir \
                          -Wl,--wrap,DirSize -Wl,--wrap,seechanges_get_diff_path -Wl,--wrap,stat \
                          -Wl,--wrap,fim_file_diff -Wl,--wrap,fim_diff_process_delete_file \
                          -Wl,--wrap,fim_db_get_count_entries -Wl,--wrap,fim_db_get_path_from_pattern \
                          -Wl,--wrap,fim_db_file_is_scanned -Wl,--wrap,fim_db_data_exists \
                          -Wl,--wrap,fim_db_append_paths_from_inode -Wl,--wrap,pthread_rwlock_wrlock \
                          -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,pthread_rwlock_rdlock \
                          -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                          -Wl,--wrap,expand_wildcards -Wl,--wrap,fim_add_inotify_watch \
                          -Wl,--wrap,fim_db_remove_wildcard_entry -Wl,--wrap,fim_db_file_update \
                          -Wl,--wrap,fim_db_is_full -Wl,--wrap,realtime_sanitize_watch_map ${DEBUG_OP_WRAPPERS}")

target_link_libraries(test_create_db SYSCHECK_O ${TEST_DEPS} fim_shared)
if(${TARGET} STREQUAL "winagent")
    target_link_libraries(test_create_db "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=w_get_file_permissions -Wl,--wrap,getpid \
                                          -Wl,--wrap=decode_win_acl_json,--wrap=w_get_file_attrs,--wrap=os_winreg_check \
                                          -Wl,--wrap,get_file_user -Wl,--wrap,fim_registry_scan \
                                          -Wl,--wrap,get_UTC_modification_time")
else()
    target_link_libraries(test_create_db "${CREATE_DB_BASE_FLAGS} -Wl,--wrap=lstat -Wl,--wrap=count_watches \
                                          -Wl,--wrap,get_user -Wl,--wrap,realpath -Wl,--wrap,add_whodata_directory \
                                          -Wl,--wrap,atexit -Wl,--wrap,remove_audit_rule_syscheck")
endif()

add_test(NAME test_create_db COMMAND test_create_db)


set(FIM_DIFF_CHANGES_BASE_FLAGS "-Wl,--wrap,lstat -Wl,--wrap,stat \
                           -Wl,--wrap,wfopen -Wl,--wrap,fread -Wl,--wrap,fopen -Wl,--wrap,fclose -Wl,--wrap,fwrite \
                           -Wl,--wrap,w_compress_gzfile -Wl,--wrap,IsDir -Wl,--wrap,mkdir_ex -Wl,--wrap,fflush \
                           -Wl,--wrap,w_uncompress_gzfile -Wl,--wrap,OS_MD5_File -Wl,--wrap,File_DateofChange \
                           -Wl,--wrap,rename -Wl,--wrap,system -Wl,--wrap,fseek -Wl,--wrap,remove,--wrap=fprintf \
                           -Wl,--wrap=fgets -Wl,--wrap,atexit -Wl,--wrap,getpid,--wrap=_mdebug2,--wrap=rmdir_ex,--wrap=rename_ex \
                           -Wl,--wrap=DirSize,--wrap=remove_empty_folders,--wrap=abspath,--wrap=getpid \
                           -Wl,--wrap,fgetpos -Wl,--wrap=fgetc -Wl,--wrap=pthread_rwlock_wrlock -Wl,--wrap=pthread_mutex_lock \
                           -Wl,--wrap=pthread_mutex_unlock -Wl,--wrap=pthread_rwlock_unlock -Wl,--wrap=pthread_rwlock_rdlock \
                           ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "test_fim_diff_changes")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${FIM_DIFF_CHANGES_BASE_FLAGS} -Wl,--wrap=unlink -Wl,--wrap=FileSize")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${FIM_DIFF_CHANGES_BASE_FLAGS} -Wl,--wrap=FileSizeWin")
else()
  list(APPEND syscheckd_tests_flags "${FIM_DIFF_CHANGES_BASE_FLAGS} -Wl,--wrap=unlink,--wrap=FileSize")
endif()

set(RUN_REALTIME_BASE_FLAGS "-Wl,--wrap,inotify_init -Wl,--wrap,inotify_add_watch \
                             -Wl,--wrap,read -Wl,--wrap,rbtree_insert \
                             -Wl,--wrap,W_Vector_insert_unique -Wl,--wrap,send_log_msg \
                             -Wl,--wrap,rbtree_keys -Wl,--wrap,fim_realtime_event -Wl,--wrap=pthread_mutex_lock \
                             -Wl,--wrap=pthread_mutex_unlock -Wl,--wrap=getpid -Wl,--wrap=atexit -Wl,--wrap=os_random \
                             -Wl,--wrap,inotify_rm_watch -Wl,--wrap,pthread_rwlock_wrlock -Wl,--wrap,pthread_rwlock_unlock \
                             -Wl,--wrap,pthread_rwlock_rdlock ${HASH_OP_WRAPPERS} ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "test_run_realtime")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS}")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=fim_configuration_directory")

  # Create event channel tests for run_realtime
  list(APPEND syscheckd_event_tests_names "test_run_realtime_event")
  list(APPEND syscheckd_event_tests_flags "${RUN_REALTIME_BASE_FLAGS} -Wl,--wrap=whodata_audit_start \
                                           -Wl,--wrap=check_path_type,--wrap=set_winsacl,--wrap=w_directory_exists")
else()
  list(APPEND syscheckd_tests_flags "${RUN_REALTIME_BASE_FLAGS}")
endif()

set(SYSCHECK_CONFIG_BASE_FLAGS "-Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,pthread_rwlock_unlock \
                                -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_rwlock_wrlock \
                                -Wl,--wrap,pthread_mutex_unlock ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "test_syscheck_config")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS}")
else()
  list(APPEND syscheckd_tests_flags "${SYSCHECK_CONFIG_BASE_FLAGS} -Wl,--wrap,getpid")
endif()

set(SYSCHECK_BASE_FLAGS "-Wl,--wrap,fim_db_init -Wl,--wrap,getDefine_Int ${DEBUG_OP_WRAPPERS}")
list(APPEND syscheckd_tests_names "test_syscheck")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${SYSCHECK_BASE_FLAGS} \
                                    -Wl,--wrap=Read_Syscheck_Config \
                                    -Wl,--wrap=os_wait \
                                    -Wl,--wrap=rootcheck_init \
                                    -Wl,--wrap=start_daemon \
                                    -Wl,--wrap=File_DateofChange \
                                    -Wl,--wrap,getpid, -Wl,--wrap,realtime_start \
                                    -Wl,--wrap,pthread_rwlock_rdlock -Wl,--wrap,pthread_rwlock_unlock \
                                    -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_rwlock_wrlock \
                                    -Wl,--wrap,pthread_mutex_unlock")

else()
  list(APPEND syscheckd_tests_flags "${SYSCHECK_BASE_FLAGS}")
endif()

set(FIM_SYNC_BASE_FLAGS "-Wl,--wrap,queue_push_ex \
                         -Wl,--wrap,fim_db_get_row_path -Wl,--wrap,fim_db_get_data_checksum \
                         -Wl,--wrap,dbsync_check_msg -Wl,--wrap,fim_db_get_count_range \
                         -Wl,--wrap,fim_db_get_path -Wl,--wrap,fim_db_get_checksum_range \
                         -Wl,--wrap,dbsync_state_msg -Wl,--wrap,fim_db_sync_path_range \
                         -Wl,--wrap,fim_db_get_path_range -Wl,--wrap,fim_db_get_first_path \
                         -Wl,--wrap,fim_db_get_last_path -Wl,--wrap,fim_db_get_entry_from_sync_msg \
                         -Wl,--wrap,fim_db_read_line_from_file -Wl,--wrap,fim_db_clean_file \
                         -Wl,--wrap,free_entry -Wl,--wrap,fim_sync_check_eps -Wl,--wrap,fim_send_sync_state \
                         -Wl,--wrap,fim_send_sync_control ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "test_fim_sync")
if(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${FIM_SYNC_BASE_FLAGS} -Wl,--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock -Wl,--wrap,getpid")
else()
  list(APPEND syscheckd_tests_flags "${FIM_SYNC_BASE_FLAGS} -Wl,--wrap,time -Wl,--wrap=pthread_mutex_lock \
                                     -Wl,--wrap=pthread_mutex_unlock")
endif()

set(RUN_CHECK_BASE_FLAGS "-Wl,--wrap,sleep -Wl,--wrap,SendMSG -Wl,--wrap,StartMQ \
                          -Wl,--wrap,realtime_adddir -Wl,--wrap,audit_set_db_consistency -Wl,--wrap,fim_checker \
                          -Wl,--wrap,fim_db_get_path_range -Wl,--wrap,fim_db_delete_range -Wl,--wrap,lstat \
                          -Wl,--wrap,fim_configuration_directory -Wl,--wrap,inotify_rm_watch -Wl,--wrap,os_random \
                          -Wl,--wrap,stat -Wl,--wrap,getpid -Wl,--wrap,fim_db_get_path_from_pattern -Wl,--wrap,gettime \
                          -Wl,--wrap,remove_audit_rule_syscheck -Wl,--wrap,realtime_process -Wl,--wrap,FOREVER \
                          -Wl,--wrap,select -Wl,--wrap,pthread_mutex_lock -Wl,--wrap,pthread_mutex_unlock \
                          ${DEBUG_OP_WRAPPERS}")

list(APPEND syscheckd_tests_names "test_run_check")
if(${TARGET} STREQUAL "agent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=sleep -Wl,--wrap,time")
elseif(${TARGET} STREQUAL "winagent")
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=realtime_start \
                                     -Wl,--wrap,WaitForSingleObjectEx -Wl,--wrap,pthread_rwlock_rdlock \
                                     -Wl,--wrap,pthread_rwlock_unlock -Wl,--wrap,pthread_rwlock_wrlock")

  # Create event channel tests for run_check
  list(APPEND syscheckd_event_tests_names "test_run_check_event")
  list(APPEND syscheckd_event_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=realtime_start,--wrap=run_whodata_scan \
                                                                   -Wl,--wrap=audit_restore
                                                                   -Wl,--wrap,pthread_rwlock_rdlock \
                                                                   -Wl,--wrap,pthread_rwlock_unlock \
                                                                   -Wl,--wrap,pthread_mutex_lock \
                                                                   -Wl,--wrap,pthread_rwlock_wrlock \
                                                                   -Wl,--wrap,pthread_mutex_unlock")
else()
  list(APPEND syscheckd_tests_flags "${RUN_CHECK_BASE_FLAGS} -Wl,--wrap=sleep,--wrap,time")
endif()

# Compiling tests
list(LENGTH syscheckd_tests_names count)
math(EXPR count "${count} - 1")
foreach(counter RANGE ${count})
    list(GET syscheckd_tests_names ${counter} test_name)
    list(GET syscheckd_tests_flags ${counter} test_flags)

    add_executable(${test_name} ${test_name}.c)

    target_link_libraries(
      ${test_name}
      SYSCHECK_O
      ${TEST_DEPS}
    )

    if(NOT test_flags STREQUAL " ")
        target_link_libraries(
            ${test_name}
            ${test_flags}
        )
    endif()
    add_test(NAME ${test_name} COMMAND ${test_name})
endforeach()

if(${TARGET} STREQUAL "winagent")
  # Compile event channel tests
  list(LENGTH syscheckd_event_tests_names count)
  math(EXPR count "${count} - 1")
  foreach(counter RANGE ${count})
      list(GET syscheckd_event_tests_names ${counter} test_name)
      list(GET syscheckd_event_tests_flags ${counter} test_flags)

      string(REPLACE "_event" ".c" test_file ${test_name})
      add_executable(${test_name} ${test_file})

      target_link_libraries(
        ${test_name}
        SYSCHECK_EVENT_O
        ${TEST_EVENT_DEPS}
      )

      target_compile_definitions(${test_name} PUBLIC WIN_WHODATA)

      if(NOT test_flags STREQUAL " ")
          target_link_libraries(
              ${test_name}
              ${test_flags}
          )
      endif()
      add_test(NAME ${test_name} COMMAND ${test_name})
  endforeach()
endif()
