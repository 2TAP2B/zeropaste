<script lang="ts">
	import { page } from '$app/state';
	import { contentKeyFromFragment, encryptFileToRequest } from '#lib/client/crypto';

	const lsug = $derived(page.params.lsug);
	const fragKey = $derived(new URLSearchParams(window.location.hash.slice(1)).get('k') ?? '');

	type RevMeta = {
		status: string;
		lsug?: string;
		files?: { id: string; name: string; mime: string; size: number }[];
	};

	let meta = $state<RevMeta | null>(null);
	let files = $state<File[]>([]);
	let busy = $state(false);
	let errorText = $state('');
	let uploaded = $state<number>(0);

	$effect(() => {
		void lsug;
		load();
	});

	const KEY_CHECK = fragKey ? '' : 'no key fragment';

	async function load() {
		const res = await fetch(`/api/r/${lsug}`);
		meta = (await res.json()) as RevMeta;
	}

	const onPick = (list: FileList | null) => {
		if (list) files = Array.from(list);
	};

	const submit = async () => {
		if (!fragKey) {
			errorText = KEY_CHECK;
			return;
		}
		if (files.length === 0) {
			errorText = 'choose files first';
			return;
		}
		busy = true;
		errorText = '';
		try {
			const contentKey = await contentKeyFromFragment(fragKey, null);
			// authorize upload entries server-side
			const auth = await fetch(`/api/r/${lsug}/upload`, {
				method: 'POST',
				headers: { 'content-type': 'application/json' },
				body: JSON.stringify({
					files: files.map((f) => ({
						name: f.name,
						mime: f.type || 'application/octet-stream',
						size: f.size
					}))
				})
			}).catch(() => null);
			if (!auth || !auth.ok) throw new Error('upload not authorized (gone or site passphrase?)');
			const authorized = (await auth.json()) as {
				files: {
					id: string;
					upload: {
						kind: string;
						url?: string;
						uploadId?: string;
						partUrls?: { url: string; partNumber: number }[];
					};
				}[];
			};
			for (let i = 0; i < files.length; i++) {
				const up = authorized.files[i].upload;
				const payload = await encryptFileToRequest(files[i], contentKey);
				if (up.kind === 'direct') {
					const put = await fetch(`/api/files/${authorized.files[i].id}/blob`, {
						method: 'PUT',
						body: payload
					});
					if (!put.ok) throw new Error(`upload failed (${put.status})`);
					await fetch(`/api/files/${authorized.files[i].id}/complete`, {
						method: 'POST',
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify({ kind: 'direct' })
					});
				} else if (up.kind === 's3put' && up.url) {
					const put = await fetch(up.url, { method: 'PUT', body: payload });
					if (!put.ok) throw new Error(`s3 upload failed (${put.status})`);
				}
				uploaded = i + 1;
			}
			files = [];
			await load();
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'upload failed';
		} finally {
			busy = false;
		}
	};
</script>

<main>
	{#if !meta}
		<p class="zp-soft">Loading…</p>
	{:else if meta.status !== 'available'}
		<div class="zp-card"><h1>This drop is closed</h1></div>
	{:else}
		<div class="zp-card">
			<h1>Secure drop for {lsug}</h1>
			<p class="zp-soft">
				Files are encrypted in your browser before upload. The recipient can only decrypt them.
			</p>
			<label
				class="dropzone"
				ondragover={(e) => e.preventDefault()}
				ondrop={(e) => {
					e.preventDefault();
					onPick(e.dataTransfer?.files ?? null);
				}}
			>
				<input type="file" multiple hidden onchange={(e) => onPick(e.currentTarget.files)} />
				{#if files.length === 0}<span class="zp-soft">Drop files here or click</span>
				{:else}<strong>{files.length} chosen</strong>{/if}
			</label>
			{#if errorText}<p class="error">{errorText}</p>{/if}
			<button class="zp-btn primary" disabled={busy} onclick={submit}
				>{busy ? `Encrypting… ${uploaded + 1}/${files.length}` : 'Encrypt and upload'}</button
			>
		</div>
		{#if meta.files?.length}
			<div class="zp-card existing">
				<h2>Already delivered ({meta.files.length})</h2>
				<ul>
					{#each meta.files as file (file.id)}
						<li>{file.name} <span class="zp-soft">({file.size} bytes)</span></li>
					{/each}
				</ul>
			</div>
		{/if}
	{/if}
</main>

<style>
	main {
		max-width: 680px;
		margin: 0 auto;
		padding: 2rem 1rem;
		display: flex;
		flex-direction: column;
		gap: 1rem;
	}
	.dropzone {
		display: flex;
		align-items: center;
		justify-content: center;
		border: 2px dashed var(--zp-accent-soft);
		border-radius: var(--zp-radius);
		padding: 2.2rem 1rem;
		cursor: pointer;
		text-align: center;
	}
	.error {
		color: var(--zp-danger);
	}
	.card-existing ul {
		margin: 0;
		padding-left: 1.2rem;
	}
</style>
