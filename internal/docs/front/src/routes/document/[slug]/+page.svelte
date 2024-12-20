<script lang="ts">
    import { onMount } from "svelte";
    import { page } from '$app/stores';
    import { goto } from '$app/navigation';
    import { PUBLIC_API_URL } from '$env/static/public';
    import Editor from '@toast-ui/editor';
    
    interface Document {
        id: string;
        title: string;
        content: string;
        // Add other document properties as needed
    }
    
    let doc: Document | null = null;
    let error: string | null = null;
    let editor: Editor;
    let titleInput: HTMLInputElement;
    let editorElement: HTMLElement;
  
    function initializeEditor() {
        if (doc && editorElement) {
            editor = new Editor({
                el: editorElement,
                height: '500px',
                initialValue: doc.content,
                previewStyle: 'vertical',
                usageStatistics: false,
            });
        }
    }
  
    onMount(async () => {
        await fetchDocument();
    });
  
    async function fetchDocument() {
        try {
            const response = await fetch(`${PUBLIC_API_URL}/documents/${$page.params.slug}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(JSON.stringify(data.detail) || 'Failed to fetch document');
            }

            doc = await response.json();
            // Initialize editor after document is loaded
            initializeEditor();
        } catch (error: any) {
            error = error.message;
        }
    }

    // Use reactive statement to initialize editor when both doc and element are ready
    $: if (doc && editorElement) {
        initializeEditor();
    }

    async function updateDocument() {
        if (!doc) return;
        
        try {
            const response = await fetch(`${PUBLIC_API_URL}/documents/${$page.params.slug}`, {
                method: 'PATCH',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${localStorage.getItem('token')}`
                },
                body: JSON.stringify({
                    title: doc.title,
                    content: editor.getMarkdown()
                })
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(JSON.stringify(data.detail) || 'Failed to update document');
            }

            // Show success message or handle successful update
        } catch (error: any) {
            error = error.message;
        }
    }

    async function deleteDocument() {
        if (!doc || !confirm('Are you sure you want to delete this document?')) return;
        
        try {
            const response = await fetch(`${PUBLIC_API_URL}/documents/${$page.params.slug}`, {
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${localStorage.getItem('token')}`
                }
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(JSON.stringify(data.detail) || 'Failed to delete document');
            }

            // Redirect to dashboard after successful deletion
            goto('/dashboard');
        } catch (error: any) {
            error = error.message;
        }
    }

    async function downloadDocument(slug: string) {
        try {
            const token = localStorage.getItem('token');
            const response = await fetch(`${PUBLIC_API_URL}/documents/${slug}/text`, {
                headers: {
                    'Authorization': `Bearer ${token}`
                }
            });

            if (!response.ok) throw new Error('Download failed');

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `document-${slug}.md`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
        } catch (error) {
            console.error('Error downloading document:', error);
            // Handle error appropriately (e.g., show notification)
        }
    }

</script>

{#if doc}
    <div class="container">
        <div class="field mt-4">
            <input 
                class="input is-large"
                type="text" 
                bind:value={doc.title}
                bind:this={titleInput}
                placeholder="Document Title"
            >
        </div>
        
        <div id="editor" class="mt-4" bind:this={editorElement}></div>
        
        <div class="field mt-4 is-flex is-justify-content-space-between">
            <div class="buttons">
                <button class="button is-primary" on:click={updateDocument}>
                    Save Changes
                </button>
                <button 
                    class="button is-info" 
                    on:click={() => downloadDocument($page.params.slug)}
                >
                    Download as TXT
                </button>
            </div>
            
            <button class="button is-danger" on:click={deleteDocument}>
                Delete Document
            </button>
        </div>
    </div>
{:else if error}
    <p class="error">{error}</p>
{:else}
    <p>Loading...</p>
{/if}

<style>
    .error {
        color: red;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 1rem;
    }
    
    :global(.toastui-editor-defaultUI) {
        border: 1px solid #dbdbdb;
        border-radius: 4px;
    }
</style>