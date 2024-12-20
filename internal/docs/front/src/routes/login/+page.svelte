<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';
	import 'bulma/css/bulma.min.css';
	import { PUBLIC_API_URL } from '$env/static/public';
	import { onMount } from 'svelte';

	let loading = false;
	let error = '';
	let showCreatedUser = false;
	let createdUser = null;
	let emailValue = '';

	onMount(() => {
		emailValue = localStorage.getItem('created_user_email') || '';
	});

	async function handleSubmit(event: SubmitEvent) {
		loading = true;
		error = '';

		try {
			const form = event.target as HTMLFormElement;
			const formData = new FormData(form);

			const response = await fetch(`${PUBLIC_API_URL}/login`, {
				method: 'POST',
				body: JSON.stringify({
					email: formData.get('email'),
					password: formData.get('password')
				}),
				headers: {
					'Content-Type': 'application/json'
				}
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(JSON.stringify(data.detail) || 'Failed to login');
			}

			const data = await response.json();
			localStorage.setItem('token', data.token);
			await goto('/dashboard');
		} catch (e) {
			error = e.message;
		} finally {
			loading = false;
		}
	}
</script>

<div class="section">
	<div class="container">
		<div class="columns is-centered">
			<div class="column is-half">
				<div class="box">
					<h1 class="title has-text-centered">Login</h1>

					{#if error}
						<div class="notification is-danger">
							{error}
						</div>
					{/if}

					<form on:submit|preventDefault={handleSubmit}>
						<div class="field">
							<label class="label" for="email">Email</label>
							<div class="control">
								<input
									class="input"
									type="email"
									name="email"
									id="email"
									placeholder="user@example.com"
									value={emailValue}
									required
								/>
							</div>
						</div>

						<div class="field">
							<label class="label" for="password">Password</label>
							<div class="control">
								<input class="input" type="password" name="password" id="password" required />
							</div>
						</div>

						<div class="field mt-5">
							<div class="control">
								<button
									class="button is-primary is-fullwidth {loading ? 'is-loading' : ''}"
									type="submit"
									disabled={loading}
								>
									Login
								</button>
							</div>
						</div>
					</form>
				</div>
			</div>
		</div>
	</div>
</div>

<style>
	.box {
		margin-top: 2rem;
	}

	.title {
		margin-bottom: 2rem;
	}

	.field {
		margin-bottom: 1.5rem;
	}

	.button.is-primary {
		background-color: #00d1b2;
		transition: background-color 0.2s ease;
	}

	.button.is-primary:hover {
		background-color: #00c4a7;
	}

	.mt-4 {
		margin-top: 1.5rem;
	}

	.mt-5 {
		margin-top: 2rem;
	}
</style>
