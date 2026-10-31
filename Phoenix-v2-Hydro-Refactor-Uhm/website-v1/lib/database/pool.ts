import mysql from "mysql2/promise";
import { config } from "@/lib/core/config";

const global_for_db = globalThis as unknown as { _phoenixac_pool?: mysql.Pool };

export const pool: mysql.Pool =
  global_for_db._phoenixac_pool ??
  mysql.createPool({
    host: config.db_host,
    port: config.db_port,
    user: config.db_user,
    password: config.db_password,
    database: config.db_name,
    waitForConnections: true,
    connectionLimit: 10,
    charset: "utf8mb4_unicode_ci",
  });

if (process.env.NODE_ENV !== "production") {
  global_for_db._phoenixac_pool = pool;
}