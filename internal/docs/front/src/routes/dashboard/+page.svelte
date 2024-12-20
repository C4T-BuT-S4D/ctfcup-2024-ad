<script>
	import { onMount } from 'svelte';
	import { PUBLIC_API_URL } from '$env/static/public';
	import 'bulma/css/bulma.min.css';

	let searchQuery = '';
	let documents = [];
	let error = null;

	let newDocumentTitle = '';
	let newDocumentContent = '';

	onMount(async () => {
		await fetchDocuments();
	});

	async function fetchDocuments() {
		try {
			const queryParams = new URLSearchParams();
			if (searchQuery) {
				queryParams.append('query', searchQuery);
			}
			const response = await fetch(`${PUBLIC_API_URL}/documents?` + queryParams.toString(), {
				method: 'GET',
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${localStorage.getItem('token')}`
				}
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(JSON.stringify(data.detail) || 'Failed to search for documents');
			}

			documents = await response.json();
		} catch (err) {
			error = err.message;
		}
	}

	async function handleSearch() {
		await fetchDocuments();
	}

	async function createDocument(title) {
		try {
			const response = await fetch(`${PUBLIC_API_URL}/documents`, {
				method: 'POST',
				body: JSON.stringify({
					title: title,
                    content: "",
				}),
				headers: {
					'Content-Type': 'application/json',
					Authorization: `Bearer ${localStorage.getItem('token')}`
				}
			});

			if (!response.ok) {
				const data = await response.json();
				throw new Error(JSON.stringify(data.detail) || 'Failed to create document');
			}

			return await response.json();
		} catch (err) {
			error = err.message;
			throw err;
		}
	}

	async function handleCreateDocument() {
		try {
			await createDocument(newDocumentTitle, newDocumentContent);
			await fetchDocuments();
		} catch (err) {
			error = err.message;
		}
	}
</script>

<div class="section">
	<div class="container">
		<h1 class="title">Dashboard</h1>

		<div class="box">
			<div class="field has-addons">
				<div class="control is-expanded">
					<input
						class="input"
						type="text"
						bind:value={searchQuery}
						placeholder="Search documents..."
					/>
				</div>
				<div class="control">
					<button class="button is-primary" on:click={handleSearch}>Search</button>
				</div>
			</div>
		</div>

		<div class="box">
			<h2 class="title is-4">Create New Document</h2>
			<div class="field">
				<div class="control">
					<input class="input" bind:value={newDocumentTitle} placeholder="Document Title" />
				</div>
			</div>
			<div class="field">
				<div class="control">
					<button class="button is-primary" on:click={handleCreateDocument}>Create Document</button>
				</div>
			</div>
		</div>

		<div class="box">
			<h2 class="title is-4">Documents</h2>
			{#if documents.length > 0}
				<div class="content">
					<ul>
						{#each documents as doc}
							<li>
								<a href={`/document/${doc.id}`} class="is-size-5">{doc.title}</a>
							</li>
						{/each}
					</ul>
				</div>
			{:else}
				<p class="has-text-grey">No documents found.</p>
			{/if}
		</div>

		{#if error}
			<div class="notification is-danger">
				{error}
			</div>
		{/if}
	</div>
</div>

<style>
	.box {
		margin-bottom: 1.5rem;
	}

	ul {
		list-style-type: none !important;
		margin: 0 !important;
		padding: 0 !important;
	}

	li {
		padding: 0.5rem 0;
		border-bottom: 1px solid #f5f5f5;
	}

	li:last-child {
		border-bottom: none;
	}
</style>
