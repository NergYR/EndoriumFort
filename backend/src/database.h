#pragma once
// ─── EndoriumFort — SQLite database wrapper ─────────────────────────────

#include <sqlite3.h>
#include <iostream>
#include <mutex>
#include <string>

struct SqliteDb {
  sqlite3 *db = nullptr;
  std::mutex mutex;

  bool open(const std::string &path, std::string &error) {
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
      error = sqlite3_errmsg(db ? db : nullptr);
      return false;
    }
    return true;
  }

  bool exec(const std::string &sql, std::string &error) {
    char *errmsg = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &errmsg) != SQLITE_OK) {
      if (errmsg) {
        error = errmsg;
        sqlite3_free(errmsg);
      } else {
        error = "SQLite exec failed";
      }
      return false;
    }
    return true;
  }

  ~SqliteDb() {
    if (db) sqlite3_close(db);
  }
};
