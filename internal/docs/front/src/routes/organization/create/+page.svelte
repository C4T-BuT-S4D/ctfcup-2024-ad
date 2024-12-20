<script lang="ts">
	import { enhance } from '$app/forms';
	import { goto } from '$app/navigation';
	import 'bulma/css/bulma.min.css';
	import { PUBLIC_API_URL } from '$env/static/public';

	let loading = false;
	let error = '';
	let showCreatedOrg = false;
	let createdOrg: { id: string; token: string; domain: string } | null = null;

	async function handleSubmit(event: SubmitEvent) {
		loading = true;
		error = '';

		try {
			const form = event.target as HTMLFormElement;
			const formData = new FormData(form);

			const response = await fetch(`${PUBLIC_API_URL}/organizations`, {
				method: 'POST',
				body: JSON.stringify({
					domain: formData.get('domain')
				}),
				headers: {
					'Content-Type': 'application/json'
				}
			});

			const data = await response.json();

			if (!response.ok) {
				throw new Error(JSON.stringify(data.detail) || 'Failed to create organization');
			}

			createdOrg = data;
			showCreatedOrg = true;
			localStorage.setItem('org_token', data.token);
		} catch (e: any) {
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
				<div class="card">
					<div class="card-content">
						<h1 class="title has-text-centered">Create Organization</h1>

						{#if error}
							<div class="notification is-danger">
								{error}
							</div>
						{/if}

						<form on:submit|preventDefault={handleSubmit}>
							<div class="field">
								<label class="label" for="domain">Domain</label>
								<div class="control">
									<input
										class="input"
										type="text"
										name="domain"
										id="domain"
										placeholder="example.com"
										required
									/>
								</div>
								<p class="help">Enter your organization's domain name</p>
							</div>

							<div class="field mt-5">
								<div class="control">
									<button
										class="button is-primary is-fullwidth {loading ? 'is-loading' : ''}"
										type="submit"
										disabled={loading}
									>
										Create Organization
									</button>
								</div>
							</div>
						</form>
					</div>
				</div>

				{#if showCreatedOrg && createdOrg}
					<div class="card mt-4">
						<div class="card-content">
							<div class="content">
								<h2 class="subtitle has-text-centered">Organization Created!</h2>
								<div class="notification is-info is-light">
									<p><strong>Organization ID:</strong> {createdOrg.id}</p>
									<p><strong>Domain:</strong> {createdOrg.domain}</p>
									<p class="has-text-weight-bold">Token: {createdOrg.token}</p>
									<p class="help has-text-danger">
										Please save this token - you'll need it to create users for your organization.
									</p>
								</div>
							</div>
						</div>
					</div>
				{/if}

				<div class="has-text-centered mt-4">
					<a href="/organizations" class="button is-light">
						Back to Organizations
					</a>
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
