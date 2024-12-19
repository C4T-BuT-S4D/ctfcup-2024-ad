import requests
import json

def index_document(doc_id: str, title: str, content: str, org_id: str, host: str = "http://localhost:8080") -> bool:
    """
    Index a document in the search server.
    
    Args:
        doc_id: Unique identifier for the document
        title: Title of the document
        content: Content/body of the document 
        org_id: Organization ID the document belongs to
        host: Host URL of the search server
        
    Returns:
        bool: True if indexing was successful, False otherwise
        
    Raises:
        requests.exceptions.RequestException: If there is an error making the request
    """
    
    document = {
        "id": doc_id,
        "title": title, 
        "content": content,
        "org_id": org_id
    }
    
    try:
        response = requests.post(
            f"{host}/index",
            json=document
        )
        response.raise_for_status()
        return True
        
    except requests.exceptions.RequestException as e:
        print(f"Error indexing document: {e}")
        return False


def search(query: str, org_id: str, host: str = "http://localhost:8080"):

    try:
        response = requests.get(
            f"{host}/search?q={query}&org_id={org_id}"
        )
        response.raise_for_status()
        return response.json()
        
    except requests.exceptions.RequestException as e:
        print(f"Error indexing document: {e}")
        return False


def main():
    # print(index_document("1", "test kek", "test", "1"))
    # print(index_document("2", "test", "test", "1"))
    # print(index_document("3", "kektest", "test", "1"))
    # print(search("test", "1").get('hits'))
    # print(search("kek", "1").get('hits'))
    # print(search("lol", "1").get('hits'))
    # print(search("kek test", "1").get('hits'))
    # print(search("test", "2").get('hits'))
    # print(search("kek", "2").get('hits'))
    host = "http://localhost:8080"
    response = requests.get(
            f"{host}/search?q=&org_id=1&org_id=1"
    )
    print(response.json())

if __name__ == "__main__":
    main()
