/**
 * @file fim_db_files.c
 * @brief Definition of FIM database for files library.
 * @date 2020-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#include "json.hpp"
#include "db.hpp"
#include "fimDBHelper.hpp"
#ifdef __cplusplus
extern "C" {
#endif

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when unit testing */
#define static

/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression, const char* const file, const int line);
#undef assert
#define assert(expression) mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

extern const char* SQL_STMT[];
const auto fileColumnList = R"({"column_list":"[path, mode, last_event, scanned, options, checksum, dev, inode, size,
                                                perm, attributes, uid, gid, user_name, group_name, hash_md5, hash_sha1,
                                                hash_sha256, mtime]"})"_json;

int fim_db_get_not_scanned(fdb_t* fim_sql, fim_tmp_file** file, int storage)
{

    int ret = 0;
    /* TODO: Add c++ code to get all files unscanned from DB. If we use DBSync transactions
       for that this function should be deleted (using get_deleted_rows())
    */
    return ret;
}

// LCOV_EXCL_START eliminar
int fim_db_delete_not_scanned(fdb_t* fim_sql, fim_tmp_file* file, pthread_mutex_t* mutex, int storage)
{
    /* TODO: Add c++ code to delete files unscanned from DB
    */
    return FIMDB_OK;
}
//eliminar
int fim_db_delete_range(fdb_t* fim_sql,
                        fim_tmp_file* file,
                        pthread_mutex_t* mutex,
                        int storage,
                        event_data_t* evt_data,
                        directory_t* configuration)
{
    /* TODO: Add c++ code to delete files with some configuration from DB
    */
    return FIMDB_OK;
}
//eliminar
int fim_db_process_missing_entry(fdb_t* fim_sql,
                                 fim_tmp_file* file,
                                 pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data)
{
    /* TODO: Add c++ code to delete files from DB if these don't have a specific monitoring mode
    */
    return FIMDB_OK;
}
//eliminar
int fim_db_remove_wildcard_entry(fdb_t* fim_sql,
                                 fim_tmp_file* file,
                                 pthread_mutex_t* mutex,
                                 int storage,
                                 event_data_t* evt_data,
                                 directory_t* configuration)
{
    /* TODO: Add c++ code to remove wildcard directory from DB
    */
    return FIMDB_OK;
}
// LCOV_EXCL_STOP

fim_entry* fim_db_get_path(fdb_t* fim_sql, const char* file_path)
{
    fim_entry* entry = NULL;
    auto filter = std::string("WHERE path=") + std::string(file_path);
    auto entry_from_path = FIMDBHelper::dbQuery(FIMBD_FILE_TABLE_NAME, fileColumnList, filter, "path");
    std::unique_ptr<FileItem> file(new FileItem(entry_from_path));

    return file->toFimEntry();
}

char** fim_db_get_paths_from_inode(fdb_t* fim_sql, unsigned long int inode, unsigned long int dev)
{
    char** paths = NULL;

    /* TODO: Add c++ code to manage this function 
    */
    
    return paths;
}

int fim_db_remove_path(const char* path)
{
    nlohmann::json removeFile;
    removeFile["path"] = path;

    return FIMDBHelper::removeFromDB<FIMDB>(FIMBD_FILE_TABLE_NAME, removeFile);
}


int fim_db_get_count_file_inode(fdb_t* fim_sql)
{
    int res = 0;
    /* TODO: Add c++ code to implement fim_db_get_count 
    */
    return res;
}

int fim_db_get_count_file_entry(fdb_t* fim_sql)
{
    int res = 0;
    /* TODO: Add c++ code to implement fim_db_get_count 
    */
    return res;
}

int fim_db_get_path_from_pattern(fdb_t* fim_sql, const char* pattern, fim_tmp_file** file, int storage)
{
    int ret = 0;
    /* TODO: Add c++ code to get some files from a pattern in DB 
    */
    return ret;
}

int fim_db_file_update(fdb_t* fim_sql, const char* path, const fim_file_data* data, fim_entry** saved)
{
    int retval;
    /* TODO: Add c++ code to update a file in DB, We should add a logic to add a new entry if this entry doesn't exists
    */
    return retval;
}
#ifdef __cplusplus
}
#endif
