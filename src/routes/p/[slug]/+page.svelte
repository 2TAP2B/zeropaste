<script lang="ts">
	import { page } from '$app/state';
	import { contentKeyFromFragment, passProof, decryptFetched, saveBlob } from '#lib/client/crypto';

	const slug = $derived(page.params.slug);
	const fragKey = $derived(new URLSearchParams(window.location.hash.slice(1)).get('k') ?? '');

	type ShareMeta = {
		status: string;
		kind?: string;
		burn?: boolean;
		needsPassphrase?: boolean;
		passSalt?: string | null;
		expiresAt?: number;
		files?: { id: string; name: string; mime: string; size: number }[];
	};

	let meta = $state<ShareMeta | null>(null);
	let passphrase = $state('');
	let needPass = $state(false);
	let busy = $state(false);
	let errorText = $state('');
	let contentKey = $state<CryptoKey | null>(null);
	let previews = $state<Record<string, string>>({});
	let textViews = $state<Record<string, string>>({});
	let srvPassProof = $state('');
	let srvProofSalt = $state<string | null>(null);

	const IMAGES = new Set(['image/png', 'image/jpeg', 'image/webp', 'image/gif']);

	$effect(() => {
		void slug;
		void fragKey;
		loadMeta();
	});

	async function loadMeta() {
		const res = await fetch(`/api/p/${slug}`);
		const data = (await res.json()) as ShareMeta;
		meta = data;
		if (data.status !== 'available') return;
		if (data.needsPassphrase) {
			needPass = true;
			srvProofSalt = data.passSalt ?? null;
			return;
		}
		if (fragKey) contentKey = await contentKeyFromFragment(fragKey, null);
	}

	async function unlock() {
		if (!meta || !meta.needsPassphrase || !srvProofSalt) return;
		busy = true;
		errorText = '';
		try {
			contentKey = await contentKeyFromFragment(fragKey, passphrase);
			// verify prefix proof BEFORE first download: derive then compare via a HEAD-ish light call
			srvPassProof = await passProof(passphrase, srvProofSalt);
			needPass = false;
		} catch {
			errorText = 'wrong passphrase';
			contentKey = null;
		} finally {
			busy = false;
		}
	}

	async function contentFor(file: { id: string }, proofHeader: string): Promise<Response> {
		return fetch(`/api/files/${file.id}/content`, {
			headers: proofHeader ? { 'x-zp-pass': proofHeader } : {}
		});
	}

	async function preview(file: { id: string; mime: string }) {
		if (!contentKey) return;
		busy = true;
		errorText = '';
		try {
			const res = await contentFor(file, srvPassProof);
			if (!res.ok)
				throw new Error(
					res.status === 410 ? 'already burned or expired' : `fetch failed (${res.status})`
				);
			const bytes = await decryptFetched(res, contentKey);
			if (file.mime.startsWith('text/')) {
				textViews[file.id] = new TextDecoder().decode(bytes);
				textViews = { ...textViews };
				return;
			}
			const blob = new Blob([bytes as unknown as BlobPart], { type: file.mime });
			previews = { ...previews, [file.id]: URL.createObjectURL(blob) };
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'decrypt failed';
		} finally {
			busy = false;
		}
	}

	async function download(file: { id: string; name: string }) {
		if (!contentKey) return;
		busy = true;
		errorText = '';
		try {
			const res = await contentFor(file, srvPassProof);
			if (!res.ok)
				throw new Error(
					res.status === 410 ? 'already burned or expired' : `fetch failed (${res.status})`
				);
			const bytes = await decryptFetched(res, contentKey);
			saveBlob(bytes, file.name);
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'decrypt failed';
		} finally {
			busy = false;
		}
	}
</script>

<main>
	{#if !meta}
		<p class="zp-soft">Loading…</p>
	{:else if meta.status !== 'available'}
		<div class="zp-card">
			<h1>{meta.status === 'burned' ? 'This share has been burned' : 'This share expired'}</h1>
			<p class="zp-soft">Nothing to see here anymore.</p>
		</div>
	{:else if needPass}
		<div class="zp-card">
			<h1>Passphrase needed</h1>
			<input
				type="password"
				bind:value={passphrase}
				placeholder="passphrase"
				onkeydown={(e) => e.key === 'Enter' && unlock()}
			/>
			<button class="zp-btn primary" onclick={unlock}>{busy ? 'Unlocking…' : 'Unlock'}</button>
			{#if errorText}<p class="error">{errorText}</p>{/if}
		</div>
	{:else if meta.files}
		<div class="zp-card">
			<h1>{meta.kind === 'paste' ? 'Shared text' : 'Shared files'}</h1>
			<p class="zp-soft">
				Encrypted in the browser, decrypted in your browser. {meta.burn
					? 'This link burns after reading.'
					: ''}
			</p>
			{#if !contentKey}
				<p class="error">Missing decryption key fragment — link is incomplete.</p>
			{/if}
			{#each meta.files as file (file.id)}
				<div class="file">
					<div class="row">
						<strong>{file.name}</strong>
						<span class="zp-soft">{(file.size / 1024 / 1024).toFixed(2)} MB</span>
						<div>
							<button
								class="zp-btn primary"
								onclick={() => download(file)}
								disabled={!contentKey || busy}>Download + decrypt</button
							>
							{#if file.mime.startsWith('text/') && !textViews[file.id]}
								<button
									class="zp-btn ghost"
									onclick={() => preview(file)}
									disabled={!contentKey || busy}>View text</button
								>
							{/if}
							{#if IMAGES.has(file.mime) && !previews[file.id]}
								<button
									class="zp-btn ghost"
									onclick={() => preview(file)}
									disabled={!contentKey || busy}>Preview</button
								>
							{/if}
						</div>
					</div>
					{#if previews[file.id]}
						<img src={previews[file.id]} alt={file.name} />
					{/if}
					{#if textViews[file.id]}
						<pre class="paste">{textViews[file.id]}</pre>
					{/if}
				</div>
			{/each}
			{#if errorText}<p class="error">{errorText}</p>{/if}
		</div>
	{/if}
</main>

<style>
	main {
		max-width: 680px;
		margin: 0 auto;
		padding: 2rem 1rem;
	}
	.file {
		border-top: 1px solid var(--zp-surface2);
		padding: 0.8rem 0;
	}
	.row {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 1rem;
	}
	img {
		max-width: 100%;
		border-radius: var(--zp-radius);
		margin-top: 0.7rem;
	}
	.paste {
		white-space: pre-wrap;
		word-break: break-word;
		background: var(--zp-surface2);
		border-radius: var(--zp-radius);
		padding: 1rem;
		margin: 0.7rem 0 0;
		font-family: ui-monospace, monospace;
		font-size: 0.92rem;
		max-height: 60vh;
		overflow: auto;
	}
	.error {
		color: var(--zp-danger);
	}
</style>
