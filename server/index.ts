import { createApp } from "./app.js";

const port = Number(process.env.PORT || 3001);
const host = process.env.HOST || "127.0.0.1";
const app = createApp();
void app.locals.proxy.start().catch((error: unknown) => console.error(`Could not start local proxy: ${error instanceof Error ? error.message : error}`));
app.listen(port, host, () => console.log(`Local HTTP Lab API listening on http://${host}:${port}`));
