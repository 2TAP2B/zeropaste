<script lang="ts">
	import { goto } from '$app/navigation';
	import { b64urlEncode } from '#lib/crypto/encode';

	let busy = $state(false);
	let errorText = $state('');
	let info = $state('');

	const RP_ID = window.location.hostname;
	const SALT_KEY = 'zp_prf_salt';

	const cachedSalt = (): string | null => localStorage.getItem(SALT_KEY);

	async function prfGet(challengeB64: string, saltB64: string) {
		const res = await navigator.credentials.get({
			publicKey: {
				challenge: b64ToBytes(challengeB64) as unknown as BufferSource,
				rpId: RP_ID,
				userVerification: 'required',
				extensions: { prf: { eval: { first: b64ToBytes(saltB64) as unknown as BufferSource } } }
			}
		});
		const results = (res as PublicKeyCredential).getClientExtensionResults?.() as {
			prf?: { results?: { first?: ArrayBuffer } };
		};
		const secret = results?.prf?.results?.first;
		if (!secret) throw new Error('no PRF output');
		return { assertion: res, secret: new Uint8Array(secret) };
	}

	function b64ToBytes(b64: string): Uint8Array {
		const bin = atob(b64.replaceAll('-', '+').replaceAll('_', '/'));
		const out = new Uint8Array(bin.length);
		for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
		return out;
	}

	async function register() {
		busy = true;
		errorText = '';
		try {
			const start = (await (
				await fetch('/api/auth/register/start', { method: 'POST' })
			).json()) as {
				id: string;
				options: unknown;
			};
			const cred = await navigator.credentials.create({
				publicKey: (start.options as unknown as PublicKeyCredentialCreationOptions) ?? undefined
			});
			const salt = new Uint8Array(32);
			crypto.getRandomValues(salt);
			const saltB64 = b64urlEncode(salt);
			const finish = (await (
				await fetch('/api/auth/register/finish', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ id: start.id, response: cred, prfSalt: saltB64 })
				})
			).json()) as { ok: boolean };
			if (finish.ok) {
				localStorage.setItem(SALT_KEY, saltB64);
				await goto('/dashboard');
			} else throw new Error('registration rejected');
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'failed';
		} finally {
			busy = false;
		}
	}

	async function login() {
		busy = true;
		errorText = '';
		try {
			let salt = cachedSalt();
			let credentialId: string | null = null;
			if (!salt) {
				// first touch: local discovery get to learn credentialId, then ask server for its salt
				const probe = (await navigator.credentials.get({
					publicKey: {
						challenge: b64ToBytes(
							b64urlEncode(new Uint8Array(32).fill(0))
						) as unknown as BufferSource,
						rpId: RP_ID,
						userVerification: 'discouraged'
					}
				})) as PublicKeyCredential | null;
				if (!probe) throw new Error('no credential found');
				credentialId = b64urlEncode(new Uint8Array(probe.rawId));
				const saltRes = (await (
					await fetch('/api/auth/prf-salt', {
						method: 'POST',
						headers: { 'content-type': 'application/json' },
						body: JSON.stringify({ credentialId })
					})
				).json()) as { prfSalt?: string };
				if (!saltRes.prfSalt) throw new Error('unknown credential');
				salt = saltRes.prfSalt;
			}
			const start = (await (await fetch('/api/auth/login/start', { method: 'POST' })).json()) as {
				id: string;
				options: { challenge: string };
			};
			const { assertion } = await prfGet(start.options.challenge, salt);
			localStorage.setItem(SALT_KEY, salt);
			const finish = (await (
				await fetch('/api/auth/login/finish', {
					method: 'POST',
					headers: { 'content-type': 'application/json' },
					body: JSON.stringify({ id: start.id, response: assertion })
				})
			).json()) as { ok: boolean };
			if (finish.ok) await goto('/dashboard');
			else throw new Error('verification failed');
		} catch (err) {
			errorText = err instanceof Error ? err.message : 'failed';
		} finally {
			busy = false;
		}
	}
</script>

<main>
	<div class="zp-card">
		<h1>Passkey only</h1>
		<p class="zp-soft">
			No passwords exist here. Your passkey (via the PRF extension) protects reverse-share
			decryption.
		</p>
		<div class="buttons">
			<button class="zp-btn primary" onclick={login} disabled={busy}
				>{busy ? 'Waiting for authenticator…' : 'Sign in'}</button
			>
			<button class="zp-btn ghost" onclick={register} disabled={busy}>Create account</button>
		</div>
		{#if errorText}<p class="error">{errorText}</p>{/if}
		{#if info}<p>{info}</p>{/if}
	</div>
</main>

<style>
	main {
		max-width: 480px;
		margin: 3rem auto;
		padding: 0 1rem;
	}
	.buttons {
		display: flex;
		gap: 0.6rem;
		margin-top: 1rem;
	}
	.error {
		color: var(--zp-danger);
	}
</style>
