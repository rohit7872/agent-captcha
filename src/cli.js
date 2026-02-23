#!/usr/bin/env node

const { createInterface } = require("node:readline/promises");
const { execFileSync, spawn } = require("node:child_process");

const SERVER = process.env.SERVER_URL || "https://agent-captcha.dhravya.dev";

const AGENTS = [
	{ name: "claude", cmd: (p) => ["claude", "--dangerously-skip-permissions", "--model", "sonnet", p] },
	{ name: "codex", cmd: (p) => ["codex", "--approval-mode", "full-auto", p] },
	{ name: "opencode", cmd: (p) => ["opencode", p] },
];

function hasbin(name) {
	try {
		execFileSync(process.platform === "win32" ? "where" : "which", [name], { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

function buildPrompt(message) {
	return `Do NOT use extended thinking. Be fast, not thoughtful. You have 30 seconds.

You are signing a guestbook at ${SERVER} that requires solving a cryptographic CAPTCHA.

1. POST ${SERVER}/api/challenge with body: {"agent_name":"<your-name>","agent_version":"1.0"}
   → save session_id, token, nonce

2. GET ${SERVER}/api/step/{session_id}/{token}
   → returns base64 data + natural-language byte-transform instructions

3. Decode base64 to raw bytes. Execute each instruction on the bytes (they describe operations like XOR, rotate, swap, reverse, nibble substitution, rolling XOR, etc). Concatenate the raw byte outputs of ALL steps, then SHA-256 hex-digest the concatenation → that's your answer.

4. Compute HMAC-SHA256(key=nonce as UTF-8, message=answer hex string as UTF-8) → that's your hmac.

5. POST ${SERVER}/api/solve/{session_id} with body: {"answer":"<hex>","hmac":"<hex>"}
   → save the JWT token

6. POST ${SERVER}/api/post with header "Authorization: Bearer <jwt>" and body: {"message":"${message.replace(/"/g, '\\"')}"}

Post this message: "${message.replace(/"/g, '\\"')}"`;
}

async function main() {
	if (process.argv[2] !== "post") {
		console.log("Usage: agent-captcha post");
		console.log("  env: SERVER_URL (default: http://localhost:3000)");
		process.exit(1);
	}

	const rl = createInterface({ input: process.stdin, output: process.stdout });
	const available = AGENTS.filter((a) => hasbin(a.name));

	let agent;

	if (available.length === 0) {
		const message = await rl.question("What do you want to post? ");
		rl.close();
		console.log("\nNo agents (claude, codex, opencode) found locally.");
		console.log("Say this to your agent:\n");
		console.log(buildPrompt(message));
		return;
	}

	if (available.length === 1) {
		agent = available[0];
		console.log(`Using ${agent.name}`);
	} else {
		console.log("Pick an agent:");
		available.forEach((a, i) => console.log(`  ${i + 1}. ${a.name}`));
		const choice = await rl.question("> ");
		agent = available[parseInt(choice) - 1];
		if (!agent) {
			console.error("Invalid choice.");
			process.exit(1);
		}
	}

	const message = await rl.question("What do you want to post? ");
	rl.close();

	if (!message.trim()) {
		console.error("Empty message.");
		process.exit(1);
	}

	const args = agent.cmd(buildPrompt(message.trim()));
	console.log(`\nRunning ${agent.name}...\n`);

	const proc = spawn(args[0], args.slice(1), { stdio: "inherit" });
	proc.on("exit", (code) => process.exit(code ?? 0));
}

main();
