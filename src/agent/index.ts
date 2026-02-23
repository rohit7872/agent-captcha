import { createHash, createHmac } from "node:crypto";

const SERVER = process.env.SERVER_URL || "http://localhost:3000";

// The challenge instructions now use thousands of unique phrasings, synonym
// pools, mixed number formats (decimal/hex/words), compositional pipelines,
// and 10 different transform types including nibble S-box substitution and
// rolling XOR. Regex-based solving is no longer viable.
//
// A real agent must use an LLM to parse the natural-language instruction,
// extract the operation + parameters, and execute the byte transforms.
function parseAndExecute(_instruction: string, _data: Buffer): Buffer | null {
	console.error(
		"  ✗ Regex solver removed — challenges now require LLM-based parsing.",
	);
	return null;
}

async function main() {
	const t0 = Date.now();
	const elapsed = () => `${Date.now() - t0}ms`;

	console.log("\x1b[36m");
	console.log("  ╔═══════════════════════════════════════════╗");
	console.log("  ║   Agent CAPTCHA — Automated Verification  ║");
	console.log("  ╚═══════════════════════════════════════════╝");
	console.log("\x1b[0m");

	// Step 1: Request challenge
	console.log("\x1b[1mStep 1:\x1b[0m Requesting challenge...");
	const challengeRes = await fetch(`${SERVER}/api/challenge`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ agent_name: "demo-agent", agent_version: "1.0.0" }),
	});
	const challenge: any = await challengeRes.json();
	console.log(`  Session:    ${challenge.session_id}`);
	console.log(`  Expires in: ${challenge.expires_in}s`);
	console.log(`  [${elapsed()}]\n`);

	// Step 2: Fetch payload
	console.log("\x1b[1mStep 2:\x1b[0m Fetching challenge payload...");
	const stepRes = await fetch(
		`${SERVER}/api/step/${challenge.session_id}/${challenge.token}`,
	);
	const step: any = await stepRes.json();
	console.log(`  Received ${step.instructions.length} instructions`);
	console.log(`  Data: ${step.data_b64.length} chars base64`);
	console.log(`  [${elapsed()}]\n`);

	// Step 3: Parse and execute
	console.log("\x1b[1mStep 3:\x1b[0m Executing transformations...");
	const data = Buffer.from(step.data_b64, "base64");
	const results: Buffer[] = [];

	for (let i = 0; i < step.instructions.length; i++) {
		const inst = step.instructions[i];
		const result = parseAndExecute(inst, data);
		if (result) {
			results.push(result);
			const hex = result.toString("hex");
			console.log(`\n  \x1b[33m[${i + 1}]\x1b[0m ${inst}`);
			console.log(
				`      → ${result.length} bytes: ${hex.slice(0, 48)}${hex.length > 48 ? "..." : ""}`,
			);
		} else {
			console.log(`\n  \x1b[33m[${i + 1}]\x1b[0m ${inst}`);
			console.log(`      → (final aggregation step)`);
		}
	}
	console.log(`\n  [${elapsed()}]\n`);

	// Step 4: Compute answer + HMAC
	console.log("\x1b[1mStep 4:\x1b[0m Computing answer and HMAC...");
	const combined = Buffer.concat(results);
	const answer = createHash("sha256").update(combined).digest("hex");
	const hmac = createHmac("sha256", step.nonce).update(answer).digest("hex");
	console.log(`  Answer: ${answer}`);
	console.log(`  HMAC:   ${hmac}`);
	console.log(`  [${elapsed()}]\n`);

	// Step 5: Submit
	console.log("\x1b[1mStep 5:\x1b[0m Submitting solution...");
	const solveRes = await fetch(`${SERVER}/api/solve/${challenge.session_id}`, {
		method: "POST",
		headers: { "Content-Type": "application/json" },
		body: JSON.stringify({ answer, hmac }),
	});
	const result: any = await solveRes.json();

	if (!result.verified) {
		console.log(`\n  \x1b[31m✗ Verification failed: ${result.error}\x1b[0m`);
		process.exit(1);
	}

	console.log(`  \x1b[32m✓ VERIFIED\x1b[0m — Agent identity confirmed`);
	console.log(`  JWT: ${result.token.slice(0, 40)}...`);
	console.log(`  [${elapsed()}]\n`);

	// Step 6: Post to guestbook
	console.log("\x1b[1mStep 6:\x1b[0m Posting to guestbook...");
	const postRes = await fetch(`${SERVER}/api/post`, {
		method: "POST",
		headers: {
			Authorization: `Bearer ${result.token}`,
			"Content-Type": "application/json",
		},
		body: JSON.stringify({
			message: `Hello from demo-agent. Solved in ${elapsed()}.`,
		}),
	});
	const postData = await postRes.json();
	console.log(`  \x1b[32m✓\x1b[0m`, postData);
	console.log(`  [${elapsed()}]\n`);

	console.log(`\x1b[36mTotal time: ${elapsed()}\x1b[0m`);
}

main().catch(console.error);
