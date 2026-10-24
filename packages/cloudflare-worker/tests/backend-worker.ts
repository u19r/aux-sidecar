import { AuxSidecar, type AuxSidecarWorkerEnv } from "../src/index";

export default {
  async fetch(_request: Request, env: AuxSidecarWorkerEnv): Promise<Response> {
    const runtime = new AuxSidecar(env);
    const response = await runtime.run((client) =>
      client.sync({
        protocol_version: 1,
        known: {},
        want: ["rate_limit_config"],
        entitlements: [],
        blocklist_policy_refs: [],
      }),
    );
    return Response.json(response);
  },
} satisfies ExportedHandler<AuxSidecarWorkerEnv>;
