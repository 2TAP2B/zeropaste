<script lang="ts">
	import { goto } from '$app/navigation';
	import { unwrapWithAccountKey, accountKeyFromPrfSecret } from '#lib/crypto/prf';
	import { b64urlEncode, b64urlDecode } from '#lib/crypto/encode';

	type Share = {
		id: string;
		slug: string;
		kind: string;
		burn: boolean;
		status: string;
		fileCount: number;
		totalSize: number;
		expiresAt: number;
	};
	type Reverse = { id: string; lsug: string; fileCount: number; expiresAt: number };

	let account = $state<string | null>(null);
	let shares = $state<Share[]>([]);
	let reverse = $state<Reverse[]>([]);
	let newLsug = $state('');
	let newTtlDays = $state(7);
	let errorText = $state('');
	let copyNote = $state('');

	const SALT_KEY = 'zp_prf_salt';

	const load = async () => {
		const res = await fetch('/api/dashboard');
		if (res.status === 401) {
			await goto('/login');
			return;
		}
		const data = (await res.json()) as { account: string; shares: Share[]; reverse: Reverse[] };
		account = data.account;
		shares = data.shares;
		reverse = data.reverse;
	};

	$effect(() => {
		load();
	});

	const fmtDate = (ms: number) => new Date(ms < 1e12 ? ms : ms).toLocaleString();

	const revokeShare = async (id: string) => {
		await fetch(`/api/dashboard?shareId=${id}`, { method: 'DELETE' });
		load();
	};

	const revokeReverse = async (id: string) => {
		await fetch(`/api/dashboard?reverseId=${id}`, { method: 'DELETE' });
		load();
	};

	const createReverse = async () => {
		errorText = '';
		const res = await fetch('/api/reverse', {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify({ lsug: newLsug || undefined, ttl: newTtlDays * 24 * 3600 })
		});
		if (!res.ok) {
			errorText = (await res.text()).replace(/^.*?"message":"(.*?)".*$/, '$1') || 'failed';
			return;
		}
		newLsug = '';
		load();
	};

	const copyReverseLink = async (rev: Reverse) => {
		errorText = '';
		try {
			const salt = localStorage.getItem(SALT_KEY);
			if (!salt) throw new Error('no passkey PRF salt cached for this device');
			const start = (await (await fetch('/api/auth/login/start', { method: 'POST' })).json()) as {
				id: string;
				options: { challenge: string };
			};
			const cred = (await navigator.credentials.get({
				publicKey: {
					challenge: b64urlBytes(start.options.challenge) as unknown as BufferSource,
					rpId: window.location.hostname,
					userVerification: 'required',
					extensions: { prf: { eval: { first: b64urlBytes(salt) as unknown as BufferSource } } }
				}
			})) as PublicKeyCredential | null;
			if (!cred) throw new Error('authenticator cancelled');
			const ext = cred.getClientExtensionResults() as {
				prf?: { results?: { first?: ArrayBuffer } };
			};
			if (!ext?.prf?.results?.first)
				throw new Error('this device/passkey cannot derive the account key');
			const accountKey = await accountKeyFromPrfSecret(new Uint8Array(ext.prf.results.first));
			const wrapRes = await fetch(`/api/reverse/${rev.id}`);
			if (!wrapRes.ok) throw new Error('no passkey wrap found for this reverse share');
			const { wraps } = (await wrapRes.json()) as {
				wraps: { credentialId: string; nonce: string; wrapped: string }[];
			};
			if (!wraps.length) throw new Error('no passkey wrap stored');
			const raw = await unwrapWithAccountKey(accountKey, b64urlDecode(wraps[0].wrapped));
			const url = `${window.location.origin}/r/${rev.lsug}#k=${b64urlEncode(raw)}`;
			await navigator.clipboard.writeText(url);
			copyNote = `Invite link for /r/${rev.lsug} copied — it contains the decryption key, share it with the intended friend only.`;
			setTimeout(() => (copyNote = ''), 6000);
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'copy failed';
		}
	};

	function b64urlBytes(b64: string): Uint8Array {
		return b64urlDecode(b64);
	}
</script>

<main>
	{#if errorText}<p class="error">{errorText}</p>{/if}
	{#if copyNote}<p class="note">{copyNote}</p>{/if}

	<section class="zp-card">
		<h1>Your shares</h1>
		{#if shares.length === 0}<p class="zp-soft">Nothing created yet.</p>{/if}
		{#each shares as share (share.id)}
			<div class="item">
				<div>
					<strong class="badge {share.status}">{share.status}</strong>
					<span class="mono link-part">/p/{share.slug}</span>
				</div>
				<div class="zp-soft">
					{share.fileCount} file(s) · {share.kind} · {share.burn ? 'burn-after-read · ' : ''}
					{fmtDate(share.expiresAt)}
				</div>
				<div class="actions">
					<a
						class="zp-btn ghost small"
						href={`/p/${share.slug}${share.status === 'active' ? '#expired' : ''}`}>Open</a
					>
					<button class="zp-btn danger small" onclick={() => revokeShare(share.id)}>Revoke</button>
				</div>
			</div>
		{/each}
	</section>

	<section class="zp-card">
		<h1>Reverse shares</h1>
		<div class="new-reverse">
			<input type="text" placeholder="custom slug (optional)" bind:value={newLsug} maxlength="64" />
			<select bind:value={newTtlDays}>
				<option value={1}>1 day</option>
				<option value={7}>1 week</option>
				<option value={30}>30 days</option>
			</select>
			<button class="zp-btn primary" onclick={createReverse}>Create</button>
		</div>
		{#if reverse.length === 0}<p class="zp-soft">No reverse shares yet.</p>{/if}
		{#each reverse as rev (rev.id)}
			<div class="item">
				<div>
					<span class="mono link-part">/r/{rev.lsug}</span>
				</div>
				<div class="zp-soft">
					{rev.fileCount} received · expires {fmtDate(rev.expiresAt)}
				</div>
				<div class="actions">
					<button class="zp-btn ghost small" onclick={() => copyReverseLink(rev)}
						>Copy invite link</button
					>
					<button class="zp-btn danger small" onclick={() => revokeReverse(rev.id)}>Revoke</button>
				</div>
			</div>
		{/each}
	</section>

	<footer>
		Signed in as <span class="mono">{account}</span> ·
		<button
			class="zp-btn danger small"
			onclick={async () => {
				await fetch('/api/auth/logout', { method: 'POST' });
				goto('/');
			}}>Sign out</button
		>
	</footer>
</main>

<style>
	main {
		max-width: 760px;
		margin: 0 auto;
		padding: 2rem 1rem;
		display: flex;
		flex-direction: column;
		gap: 1.4rem;
	}
	.item {
		display: flex;
		flex-direction: column;
		gap: 0.35rem;
		border-top: 1px solid var(--zp-surface2);
		padding: 0.8rem 0;
	}
	.item:first-of-type {
		border-top: none;
	}
	.badge {
		font-size: 0.75rem;
		padding: 0.15rem 0.55rem;
		border-radius: 999px;
		background: var(--zp-accent-soft);
		color: var(--zp-accent-text);
		margin-right: 0.5rem;
		text-transform: uppercase;
	}
	.badge.burned,
	.badge.expired {
		background: var(--zp-surface2);
		color: var(--zp-text-soft);
	}
	.mono {
		font-family: ui-monospace, monospace;
	}
	.actions {
		display: flex;
		gap: 0.5rem;
	}
	.small {
		font-size: 0.85rem;
		padding: 0.3rem 0.8rem;
	}
	.new-reverse {
		display: flex;
		gap: 0.5rem;
		flex-wrap: wrap;
		align-items: center;
		margin-bottom: 0.8rem;
	}
	footer {
		display: flex;
		gap: 0.6rem;
		align-items: center;
		justify-content: flex-end;
	}
	.error {
		color: var(--zp-danger);
	}
	.note {
		color: var(--zp-accent-text);
		background: var(--zp-accent-soft);
		border-radius: var(--zp-radius);
		padding: 0.6rem 1rem;
	}
</style>
