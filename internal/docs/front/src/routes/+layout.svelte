<script>
	import { page } from '$app/stores';
	import 'bulma/css/bulma.min.css';
	import { goto } from '$app/navigation';

	let isAuthenticated = false;

	$: {
		isAuthenticated = typeof localStorage !== 'undefined' && !!localStorage.getItem('token');
	}

	function logout() {
		localStorage.removeItem('token');
		goto('/login');
	}
</script>

<nav class="navbar" role="navigation" aria-label="main navigation">
	<div class="navbar-brand">
		<a class="navbar-item has-text-weight-bold" href="/"> Docs </a>
	</div>
	<div class="navbar-end">
		<div class="navbar-item">
			<div class="buttons">
				{#if !isAuthenticated}
					<a class="button is-light" href="/organization/create">Create Organization</a>
					<a class="button is-light" href="/create-user">Create User</a>
					<a class="button is-primary" href="/login">Login</a>
				{:else}
					<a class="button is-light" href="/dashboard">Dashboard</a>
					<button class="button is-danger" on:click={logout}>Logout</button>
				{/if}
			</div>
		</div>
	</div>
</nav>

<main>
	<slot />
</main>

<style>
	main {
		padding: 1rem;
		/* background-color: white; */
		min-height: calc(100vh - 3.25rem);
	}
</style>
