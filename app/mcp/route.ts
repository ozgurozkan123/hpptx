import { createMcpHandler } from "mcp-handler";
import { z } from "zod";
import { spawn } from "child_process";

export const runtime = "nodejs";

function removeAnsiCodes(input: string): string {
  return input.replace(/\x1B\[[0-9;]*m/g, "");
}

async function runHttpx(args: string[]) {
  return new Promise((resolve, reject) => {
    const child = spawn("httpx", args, {
      env: process.env,
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("error", (err) => {
      reject(new Error(`Failed to start httpx: ${err.message}`));
    });

    child.on("close", (code) => {
      if (code === 0 || typeof code === "undefined") {
        resolve({
          content: [
            {
              type: "text",
              text: removeAnsiCodes(stdout.trim() || "(no output)"),
            },
          ],
        });
      } else {
        reject(
          new Error(
            `httpx exited with code ${code}. stderr: ${stderr || "(empty)"}`
          )
        );
      }
    });
  });
}

const handler = createMcpHandler(
  async (server) => {
    server.tool(
      "httpx",
      "Scan target domains and detect active HTTP/HTTPS services using projectdiscovery/httpx.",
      {
        target: z
          .array(z.string())
          .min(1)
          .describe(
            "List of domains/hosts (e.g., example.com) to scan for live HTTP/HTTPS services."
          ),
        ports: z
          .array(z.number())
          .optional()
          .describe("Optional list of ports to probe (e.g., 80, 443, 8080)."),
        probes: z
          .array(z.string())
          .optional()
          .describe(
            "Optional list of probe flags (e.g., status-code, title, web-server, tech-detect)."
          ),
      },
      async ({ target, ports, probes }) => {
        const args: string[] = ["-u", target.join(","), "-silent"];

        if (ports && ports.length > 0) {
          args.push("-p", ports.join(","));
        }

        if (probes && probes.length > 0) {
          for (const probe of probes) {
            if (probe.startsWith("-")) {
              args.push(probe);
            } else {
              args.push(`-${probe}`);
            }
          }
        }

        return await runHttpx(args);
      }
    );
  },
  {
    capabilities: {
      tools: {
        httpx: {
          description:
            "Scan target domains and detect active HTTP/HTTPS services using projectdiscovery/httpx.",
        },
      },
    },
  },
  {
    basePath: "",
    verboseLogs: true,
    maxDuration: 300,
    disableSse: false,
  }
);

export { handler as GET, handler as POST, handler as DELETE };
