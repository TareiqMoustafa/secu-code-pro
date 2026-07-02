import { authRouter } from "./auth-router";
import { scanRouter } from "./scan-router";
import { createRouter, publicQuery } from "./middleware";

export const appRouter = createRouter({
  ping: publicQuery.query(() => ({ ok: true, ts: Date.now() })),
  auth: authRouter,
  scan: scanRouter,
});

export type AppRouter = typeof appRouter;
