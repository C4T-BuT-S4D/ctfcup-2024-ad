<script>
	import { PUBLIC_API_URL } from '$env/static/public';
	import { onMount } from 'svelte';

	let organizations = [];
	let loading = true;
	let error = null;

	onMount(async () => {
		try {
			const response = await fetch(`${PUBLIC_API_URL}/organizations`);
			if (!response.ok) throw new Error('Failed to fetch organizations');
			organizations = await response.json();
		} catch (e) {
			error = e.message;
		} finally {
			loading = false;
		}
	});
</script>

<div class="container mx-auto p-4">
	<h1 class="text-2xl font-bold mb-6">Organizations</h1>

	{#if loading}
		<p>Loading organizations...</p>
	{:else if error}
		<p class="text-red-500">Error: {error}</p>
	{:else if organizations.length === 0}
		<p>No organizations found.</p>
	{:else}
		<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
			{#each organizations as org}
				<div class="card">
					<div class="has-text-centered mt-4">
						<h2 class="text-xl font-semibold break-words" title="ID: {org.id}">{org.domain}</h2>
					</div>
				</div>
			{/each}
		</div>
	{/if}
</div>

<style>
	/* .card {
		@apply bg-white p-6 rounded-lg shadow-md;
	}

	.btn {
		@apply bg-blue-500 text-white px-4 py-2 rounded hover:bg-blue-600 inline-block;
	} */
</style>
