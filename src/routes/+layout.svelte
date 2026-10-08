<script lang="ts">
	import { page } from '$app/state';
	import type { Snippet } from 'svelte';
	import '../app.css';

	let { children }: { children?: Snippet } = $props();

	let theme = $state<'light' | 'dark'>('light');
	let ready = $state(false);

	$effect(() => {
		if (!ready) return;
		document.documentElement.setAttribute('data-theme', theme);
		localStorage.setItem('zp_theme', theme);
	});

	if (typeof window !== 'undefined') {
		const stored = localStorage.getItem('zp_theme');
		const prefers = window.matchMedia('(prefers-color-scheme: dark)').matches;
		theme =
			stored === 'dark' || stored === 'light'
				? (stored as 'light' | 'dark')
				: prefers
					? 'dark'
					: 'light';
		document.documentElement.setAttribute('data-theme', theme);
		ready = true;
	}
</script>

<header>
	<a class="logo" href="/">
		<span class="dot"></span> ZeroPaste
	</a>
	<nav>
		<a href="/" class:active={page.url.pathname === '/'}>New share</a>
		<a href="/dashboard" class:active={page.url.pathname === '/dashboard'}>Dashboard</a>
		<button
			class="zp-btn ghost"
			aria-label="toggle theme"
			onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')}
		>
			{theme === 'dark' ? '☾' : '☀'}
		</button>
	</nav>
</header>

{@render children?.()}

<style>
	header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 0.9rem 1.4rem;
	}
	.logo {
		display: flex;
		align-items: center;
		gap: 0.5rem;
		font-weight: 700;
		text-decoration: none;
		color: var(--zp-text);
	}
	.dot {
		width: 14px;
		height: 14px;
		border-radius: 50%;
		background: var(--zp-accent);
		box-shadow: 0 0 10px var(--zp-ring);
	}
	nav {
		display: flex;
		align-items: center;
		gap: 1rem;
	}
	nav a {
		text-decoration: none;
		color: var(--zp-text-soft);
		padding: 0.3rem 0.6rem;
		border-radius: 999px;
	}
	nav a.active {
		color: var(--zp-accent-text);
		background: var(--zp-accent-soft);
	}
	button.zp-btn {
		font-size: 1.1rem;
		padding: 0.35rem 0.8rem;
	}
</style>
