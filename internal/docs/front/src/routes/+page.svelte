<script lang="ts">
    import { onMount } from 'svelte';
    import { goto } from '$app/navigation';

    onMount(() => {
        const isAuthenticated = typeof localStorage !== 'undefined' && !!localStorage.getItem('token');
        if (isAuthenticated) {
            goto('/dashboard');
        }
    });
</script>

<div class="container has-text-centered">
    <h1 class="title is-1">Welcome to Docs</h1>
    <p class="subtitle">
        Please <a href="/login">login</a> to continue or <a href="/create-user">create an account</a>
    </p>
</div>
