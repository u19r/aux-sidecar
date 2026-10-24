import { withAuxSidecar } from "./middleware.js";
import type { AuxSidecarWorkerEnv } from "./runtime.server.js";

export { AuxSidecar, type AuxSidecarWorkerEnv } from "./runtime.server.js";
export { withAuxSidecar } from "./middleware.js";

export {
  AuxFnOAuthClient,
  type AuxFnOAuthOptions,
  type OAuthTokenSet,
  type OAuthAttempt,
  type OAuthResources,
} from "./oauth-client.server.js";

export { AuxFnClientError } from "./account-client.server.js";

export default {
  fetch: withAuxSidecar(async () => new Response("ok")),
} satisfies ExportedHandler<AuxSidecarWorkerEnv>;
