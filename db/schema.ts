import {
  mysqlTable,
  mysqlEnum,
  serial,
  varchar,
  text,
  timestamp,
  int,
  boolean,
  json,
} from "drizzle-orm/mysql-core";

export const users = mysqlTable("users", {
  id: serial("id").primaryKey(),
  unionId: varchar("unionId", { length: 255 }).notNull().unique(),
  name: varchar("name", { length: 255 }),
  email: varchar("email", { length: 320 }),
  avatar: text("avatar"),
  role: mysqlEnum("role", ["user", "admin"]).default("user").notNull(),
  createdAt: timestamp("createdAt").defaultNow().notNull(),
  updatedAt: timestamp("updatedAt")
    .defaultNow()
    .notNull()
    .$onUpdate(() => new Date()),
  lastSignInAt: timestamp("lastSignInAt").defaultNow().notNull(),
});

export type User = typeof users.$inferSelect;
export type InsertUser = typeof users.$inferInsert;

export const scanHistory = mysqlTable("scan_history", {
  id: serial("id").primaryKey(),
  userId: varchar("user_id", { length: 255 }).notNull(),
  url: varchar("url", { length: 500 }).notNull(),
  domain: varchar("domain", { length: 200 }),
  riskScore: int("risk_score").default(0),
  isThreat: boolean("is_threat").default(false),
  reason: varchar("reason", { length: 300 }),
  country: varchar("country", { length: 100 }),
  scannedAt: timestamp("scanned_at").defaultNow().notNull(),
});

export type ScanHistory = typeof scanHistory.$inferSelect;

export const stats = mysqlTable("stats", {
  id: serial("id").primaryKey(),
  totalScanned: int("total_scanned").default(0),
  threatsDetected: int("threats_detected").default(0),
  updatedAt: timestamp("updated_at").defaultNow().notNull(),
});

export type Stats = typeof stats.$inferSelect;

export const reputationCache = mysqlTable("reputation_cache", {
  id: serial("id").primaryKey(),
  url: varchar("url", { length: 500 }).notNull().unique(),
  riskScore: int("risk_score").default(0),
  isThreat: boolean("is_threat").default(false),
  verdict: varchar("verdict", { length: 50 }),
  reasons: json("reasons").$type<string[]>(),
  infoNotes: json("info_notes").$type<string[]>(),
  lastScanned: timestamp("last_scanned").defaultNow().notNull(),
  scanCount: int("scan_count").default(1),
});

export type ReputationCache = typeof reputationCache.$inferSelect;
