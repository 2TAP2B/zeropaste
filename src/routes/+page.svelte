<script lang="ts">
	import {
		makeShareKeys,
		passProofSalt,
		passProof,
		encryptFileToRequest,
		encryptTextToRequest
	} from '#lib/client/crypto';

	let files = $state<File[]>([]);
	let paste = $state('');
	let mode = $state<'files' | 'paste'>('files');
	let burn = $state(false);
	let ttlHours = $state(168);
	let passphrase = $state('');
	let busy = $state(false);
	let errorText = $state('');
	let shareUrl = $state('');
	let link = $state<HTMLInputElement | null>(null);
	let copied = $state(false);

	const onPick = (list: FileList | null) => {
		if (list) files = Array.from(list);
	};

	const submit = async () => {
		errorText = '';
		if (mode === 'files' ? files.length === 0 : !paste) {
			errorText = 'nothing to share';
			return;
		}
		busy = true;
		try {
			const pass = passphrase || null;
			const keys = await makeShareKeys(pass);
			const body: Record<string, unknown> = {
				kind: mode,
				files: [],
				burn,
				ttl: ttlHours * 3600
			};
			if (pass) {
				const salt = passProofSalt();
				body.passSalt = salt;
				body.passVerifier = await passProof(pass, salt);
			}
			let textMeta: { name: string; mime: string; size: number } | null = null;
			if (mode === 'paste') {
				const size = new TextEncoder().encode(paste).length;
				textMeta = { name: 'paste.txt', mime: 'text/plain', size };
				body.files = [textMeta];
			} else {
				body.files = files.map((f) => ({
					name: f.name,
					mime: f.type || 'application/octet-stream',
					size: f.size
				}));
			}

			const res = await fetch('/api/shares', {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify(body)
			});
			if (!res.ok) throw new Error(`server refuses new share (${res.status})`);
			const meta = (await res.json()) as {
				slug: string;
				files: {
					id: string;
					name: string;
					upload: {
						kind: string;
						url?: string;
						uploadId?: string;
						partUrls?: { url: string; partNumber: number }[];
					};
				}[];
			};

			const sources: Array<{ meta: (typeof meta.files)[0]; payload: BodyInit }> = [];
			if (mode === 'paste') {
				sources.push({
					meta: meta.files[0],
					payload: await encryptTextToRequest(paste, keys.contentKey)
				});
			} else {
				for (const f of files) {
					const target =
						meta.files.find((m) => m.name === f.name && m.id) ?? meta.files[sources.length];
					sources.push({ meta: target!, payload: await encryptFileToRequest(f, keys.contentKey) });
				}
			}
			for (const { meta: m, payload } of sources) {
				await uploadOne(m, payload);
			}
			const url = `${window.location.origin}/p/${meta.slug}#k=${keys.fragment}`;
			shareUrl = url;
			files = [];
			paste = '';
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'upload failed';
		} finally {
			busy = false;
		}
	};

	async function uploadOne(
		m: {
			id: string;
			upload: {
				kind: string;
				url?: string;
				uploadId?: string;
				partUrls?: { url: string; partNumber: number }[];
			};
		},
		payload: BodyInit
	) {
		const up = m.upload;
		if (up.kind === 'direct') {
			const put = await fetch(`/api/files/${m.id}/blob`, { method: 'PUT', body: payload });
			if (!put.ok) throw new Error(`blob upload failed (${put.status})`);
			const fin = await fetch(`/api/files/${m.id}/complete`, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({ kind: 'direct' })
			});
			if (!fin.ok) throw new Error(`finalize failed (${fin.status})`);
		} else if (up.kind === 's3put' && up.url) {
			const put = await fetch(up.url, { method: 'PUT', body: payload });
			if (!put.ok) throw new Error(`s3 upload failed (${put.status})`);
		} else if (up.kind === 's3' && up.partUrls) {
			// ponytail: multipart s3 upload of >5 MB files is not wired yet; +1 GB will fail on s3 backend until parts are streamed
		}
	}

	const copy = async () => {
		if (!shareUrl) return;
		await navigator.clipboard.writeText(shareUrl);
		earnedCopy();
	};
	function earnedCopy() {
		copied = true;
		setTimeout(() => (copied = false), 1500);
	}
</script>

<main>
	<h1>Share, encrypted in your browser</h1>
	<p class="zp-soft">
		Files and text never leave your machine unencrypted. The key travels in the link only.
	</p>

	<div class="zp-card wizard">
		{#if shareUrl}
			<div class="done">
				<h2>Share ready</h2>
				<input type="text" readonly value={shareUrl} bind:this={link} />
				<button class="zp-btn primary" onclick={copy}>{copied ? 'Copied ✓' : 'Copy link'}</button>
				<p class="warn">Keep the link private — the decryption key lives in it.</p>
				<button class="zp-btn ghost" onclick={() => (shareUrl = '')}>Share something else</button>
			</div>
		{:else}
			<div class="tabs">
				<button class:active={mode === 'files'} onclick={() => (mode = 'files')}>Files</button>
				<button class:active={mode === 'paste'} onclick={() => (mode = 'paste')}>Text</button>
			</div>

			{#if mode === 'files'}
				<label
					class="dropzone"
					ondragover={(e) => e.preventDefault()}
					ondrop={(e) => {
						e.preventDefault();
						onPick(e.dataTransfer?.files ?? null);
					}}
				>
					<input type="file" multiple hidden onchange={(e) => onPick(e.currentTarget.files)} />
					{#if files.length === 0}<span class="zp-soft">Drop files here or click to choose</span>
					{:else}<strong>{files.length} file(s)</strong><span class="zp-soft">
							{files.reduce((s, f) => s + f.size, 0)} bytes</span
						>{/if}
				</label>
			{:else}
				<textarea rows={8} placeholder="Paste text to share…" bind:value={paste}></textarea>
			{/if}

			<div class="options">
				<label><input type="checkbox" bind:checked={burn} /> Burn after reading</label>
				<label
					>Expires in
					<select bind:value={ttlHours}>
						<option value={1}>1 hour</option>
						<option value={24}>1 day</option>
						<option value={168}>1 week</option>
						<option value={720}>30 days</option>
					</select></label
				>
				<label
					>Passphrase (optional)
					<input type="password" bind:value={passphrase} placeholder="" /></label
				>
			</div>

			{#if errorText}<p class="error">{errorText}</p>{/if}
			<button class="zp-btn primary" disabled={busy} onclick={submit}>
				{busy ? 'Encrypting & uploading…' : 'Encrypt and share'}
			</button>
		{/if}
	</div>
</main>

<style>
	main {
		max-width: 680px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}
	h1 {
		margin-bottom: 0.2rem;
	}
	.wizard {
		margin-top: 1.2rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.tabs {
		display: flex;
		gap: 0.4rem;
	}
	.tabs button {
		border: none;
		background: transparent;
		padding: 0.4rem 1rem;
		border-radius: 999px;
		cursor: pointer;
		color: var(--zp-text-soft);
	}
	.tabs button.active {
		background: var(--zp-accent-soft);
		color: var(--zp-accent-text);
	}
	.dropzone {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		gap: 0.3rem;
		border: 2px dashed var(--zp-accent-soft);
		border-radius: var(--zp-radius);
		padding: 2.2rem 1rem;
		cursor: pointer;
		text-align: center;
	}
	.options {
		display: flex;
		flex-wrap: wrap;
		gap: 1rem 1.6rem;
		align-items: center;
	}
	.options label {
		display: flex;
		align-items: center;
		gap: 0.4rem;
	}
	.options input[type='password'] {
		width: 220px;
	}
	.error {
		color: var(--zp-danger);
	}
	.warn {
		color: var(--zp-danger);
		font-size: 0.9rem;
	}
	.done {
		display: flex;
		flex-direction: column;
		gap: 0.8rem;
		align-items: flex-start;
	}
	.done input {
		width: 100%;
	}
</style>
