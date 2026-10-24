import type { AuxSidecarWorkerEnv } from "./src/index";

declare global {
  namespace Cloudflare {
    interface Env extends AuxSidecarWorkerEnv {}

    interface GlobalProps {
      mainModule: typeof import("./src/index");
    }
  }
}

export {};
