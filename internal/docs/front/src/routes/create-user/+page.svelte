<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';
	import 'bulma/css/bulma.min.css';
	import { PUBLIC_API_URL } from '$env/static/public';

	let loading = false;
	let error = '';
	let showCreatedUser = false;
	let createdUser = null;

	async function handleSubmit(event: SubmitEvent) {
		loading = true;
		error = '';

		try {
			const form = event.target as HTMLFormElement;
			const formData = new FormData(form);

			const response = await fetch(`${PUBLIC_API_URL}/users`, {
				method: 'POST',
				body: JSON.stringify({
					username: formData.get('username'),
					password: formData.get('password'),
					token: formData.get('token')
				}),
				headers: {
					'Content-Type': 'application/json'
				}
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(JSON.stringify(data.detail) || 'Failed to create user');
			}

			createdUser = await response.json();
			showCreatedUser = true;
			localStorage.setItem('created_user_email', createdUser.email);
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
					<h1 class="title has-text-centered">Create User</h1>

					{#if error}
						<div class="notification is-danger">
							{error}
						</div>
					{/if}

					<form on:submit|preventDefault={handleSubmit}>
						<div class="field">
							<label class="label" for="username">Username</label>
							<div class="control">
								<input
									class="input"
									type="text"
									name="username"
									id="username"
									placeholder="user"
									required
								/>
							</div>
						</div>

						<div class="field">
							<label class="label" for="name">Password</label>
							<div class="control">
								<input
									class="input"
									type="password"
									name="password"
									id="password"
									placeholder="John Doe"
									required
								/>
							</div>
						</div>

						<div class="field">
							<label class="label" for="token">Organization Token</label>
							<div class="control">
								<input
									class="input"
									type="text"
									name="token"
									id="token"
									placeholder="looong string"
									value={localStorage.getItem('org_token') || ''}
									required
								/>
							</div>
						</div>

						<div class="field mt-5">
							<div class="control">
								<button
									class="button is-primary is-fullwidth {loading ? 'is-loading' : ''}"
									type="submit"
									disabled={loading}
								>
									Create User
								</button>
							</div>
						</div>
					</form>
				</div>

				{#if showCreatedUser}
					<div class="card">
						<div class="has-text-centered mt-4">
							<p>User ID: {createdUser.id}</p>
							<p>Email: {createdUser.email}</p>
							<p>Password: {createdUser.password}</p>
						</div>
					</div>
					<div class="has-text-centered mt-4">
						<a href="/login" class="has-text-grey"> Login </a>
					</div>
				{/if}
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
