import logging
import secrets

import fastapi
from fastapi import APIRouter, Query

from app import config, models, dto, auth, search
from beanie.operators import In
from beanie import BeanieObjectId

api = APIRouter()
logger = logging.getLogger(__name__)

def json_error(error):
    return {'error': error}

async def get_search_client():
    return search.SearchClient(config.settings.search_host)

async def get_current_user(data = fastapi.Depends(auth.jwt_bearer)) -> models.User | None:
    uid = data.get('uid')
    user = await models.User.get(uid)
    if not user:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail='invalid token'
        )
    return user


@api.get('/')
async def signup_handler(response: fastapi.Response):
    return {"hello": "world"}



@api.post('/organizations', response_model=dto.Organization)
async def create_organization(org: dto.OrganizationCreate):
    # Check if organization with same name exists
    existing_org = await models.Organization.find_one({"domain": org.domain})
    if existing_org:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_412_PRECONDITION_FAILED,
            detail=json_error('organization already exists')
        )

    token = secrets.token_hex(32)

    # Create new organization
    new_org = models.Organization(domain=org.domain, token=token)
    await new_org.insert()
    return dto.Organization(domain=new_org.domain, token=new_org.token, id=str(new_org.id))

@api.get('/organizations')
async def list_organizations():
    organizations = await models.Organization.find().to_list()
    return [dto.OrganizationList(id=str(org.id), domain=org.domain) for org in organizations]

@api.post('/users', response_model=dto.UserCreated)
async def create_user(user: dto.UserCreate):
    # Check if organization exists
    org = await models.Organization.find_one(models.Organization.token == user.token)
    if not org:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_412_PRECONDITION_FAILED,
            detail=json_error('organization not found')
        )

    new_username = f"{user.username}@{org.domain}"
    existing_user = await models.User.find_one({"username": new_username})
    if existing_user:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_412_PRECONDITION_FAILED,
            detail=json_error('user already exists')
        )

    # Create new user
    new_user = models.User(username=new_username, password=user.password, organization_id=str(org.id))
    await new_user.insert()
    return dto.UserCreated(email=new_user.username, password=new_user.password, organization_id=new_user.organization_id, id=str(new_user.id))

@api.post('/login')
async def login(req: dto.LoginRequest):
    user = await models.User.find_one({"username": req.email})
    if not user:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail=json_error('invalid username or password')
        )
    if user.password != req.password:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_401_UNAUTHORIZED,
            detail=json_error('invalid username or password')
        )

    token = auth.jwt_helper.gen_token({'uid': str(user.id)})
    return {'token': token}

@api.get('/users/me', response_model=dto.UserCreated)
async def get_me(user = fastapi.Depends(get_current_user)):
    return dto.UserCreated(email=user.username, password="", organization_id=user.organization_id, id=str(user.id))


@api.post('/documents')
async def create_document(doc: dto.CreateDocument, user = fastapi.Depends(get_current_user), search_client = fastapi.Depends(get_search_client)):
    new_doc = models.Doc(title=doc.title, author_id=str(user.id), content=doc.content, organization_id=user.organization_id)
    await new_doc.insert()
    doc_id = str(new_doc.id)
    await search_client.index(doc_id, new_doc.title, new_doc.content, new_doc.organization_id)
    return {'id': str(new_doc.id)}

async def must_get_doc(doc_id):
    doc = await models.Doc.get(doc_id)
    if not doc:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_404_NOT_FOUND,
            detail=json_error('document not found'))
    return doc

@api.get('/documents/{doc_id}', response_model=dto.Document)
async def get_document(doc_id: str, user = fastapi.Depends(get_current_user)):
    doc = await must_get_doc(doc_id)
    if doc.organization_id != user.organization_id:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_403_FORBIDDEN,
            detail=json_error('forbidden')
        )
    return dto.Document(id=str(doc.id), title=doc.title, content=doc.content, organization_id=doc.organization_id)

@api.patch('/documents/{doc_id}')
async def update_document(doc_id: str, update: dto.UpdateDocument, user = fastapi.Depends(get_current_user), search_client = fastapi.Depends(get_search_client)):
    doc = await must_get_doc(doc_id)
    if doc.organization_id != user.organization_id:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_403_FORBIDDEN,
            detail=json_error('forbidden')
        )
    if update.title:
        doc.title = update.title
    if update.content:
        doc.content = update.content
    await doc.save()
    await search_client.index(doc_id, update.title, update.content, doc.organization_id)
    return {'id': str(doc.id)}


@api.delete('/documents/{doc_id}')
async def delete_document(doc_id: str, user = fastapi.Depends(get_current_user), search_client = fastapi.Depends(get_search_client)):
    doc = await must_get_doc(doc_id)
    if doc.organization_id != user.organization_id:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_403_FORBIDDEN,
            detail=json_error('forbidden')
        )
    await doc.delete()
    return {}

@api.get('/documents/{doc_id}/text')
async def get_document_text(doc_id: str, user = fastapi.Depends(get_current_user)):
    doc = await must_get_doc(doc_id)
    if doc.organization_id != user.organization_id:
        raise fastapi.HTTPException(
            status_code=fastapi.status.HTTP_403_FORBIDDEN,
            detail=json_error('forbidden')
        )
    return fastapi.responses.FileResponse(path=doc.content, filename=f"{doc.title}.txt", media_type='text/plain')

# @api.get('/document/{doc_id}/pdf')
# async def get_document_pdf(doc_id: str, user = fastapi.Depends(get_current_user)):
#     doc = await must_get_doc(doc_id)
#     if doc.organization_id != user.organization_id:
#         raise fastapi.HTTPException(
#             status_code=fastapi.status.HTTP_403_FORBIDDEN,
#             detail=json_error('forbidden')
#         )




@api.get('/documents')
async def search_docs(
        query: str | None = Query(default=''),
                      user = fastapi.Depends(get_current_user),
                      search_client = fastapi.Depends(get_search_client)):
    org_id = user.organization_id
    not_allowed_chars = ['?', '*', '@' '#', '%', ';']
    for char in not_allowed_chars:
        if char in query:
            raise fastapi.HTTPException(
                status_code=fastapi.status.HTTP_400_BAD_REQUEST,
                detail=json_error('invalid query')
            )
    doc_ids =  await search_client.search(query, str(org_id))
    doc_ids = [BeanieObjectId(doc_id) for doc_id in doc_ids]
    docs = await models.Doc.find(In(models.Doc.id, doc_ids)).to_list()
    return [dto.Document(id=str(doc.id), title=doc.title, content=doc.content, organization_id=str(org_id)) for doc in docs]

