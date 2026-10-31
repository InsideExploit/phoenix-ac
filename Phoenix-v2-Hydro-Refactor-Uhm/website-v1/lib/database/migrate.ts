import fs from "node:fs";
import path from "node:path";
import mysql from "mysql2/promise";
import { config } from "@/lib/core/config";

let ready: Promise<void> | null = null;

function db_config() {
  return {
    host: config.db_host,
    port: config.db_port,
    user: config.db_user,
    password: config.db_password,
    charset: "utf8mb4_unicode_ci" as const,
  };
}

function schema_path() {
  return path.join(process.cwd(), "database", "schema.sql");
}

export async function ensure_database() {
  if (!ready) {
    ready = run_migrate();
  }

  await ready;
}

async function run_migrate() {
  const cfg = db_config();
  const database = config.db_name;

  const bootstrap = await mysql.createConnection({
    ...cfg,
    multipleStatements: true,
  });

  await bootstrap.query(
    "CREATE DATABASE IF NOT EXISTS `" + database + "` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci",
  );
  await bootstrap.end();

  const connection = await mysql.createConnection({
    ...cfg,
    database,
    multipleStatements: true,
  });

  const schema = fs.readFileSync(schema_path(), "utf8");
  await connection.query(schema);
  await connection.end();
}