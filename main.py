# Importações.
import os
from decimal import Decimal

from pathlib import Path
from dotenv import load_dotenv
from fastapi import (
    FastAPI,
    HTTPException,
    UploadFile,
    File,
    Depends
)

from fastapi.security import (
    HTTPBearer,
    HTTPAuthorizationCredentials
)

from supabase import create_client
import cloudinary
import cloudinary.uploader

from io import BytesIO
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError


# Carregar as configurações do arquivo .env
caminho_env = Path(__file__).resolve().parent / ".env"

load_dotenv(
    dotenv_path=caminho_env,
    override=True
)

DATABASE_URL = os.getenv("DATABASE_URL")
# Configurações do Supabase Auth.
SUPABASE_URL = os.getenv("SUPABASE_URL")

SUPABASE_PUBLISHABLE_KEY = os.getenv(
    "SUPABASE_PUBLISHABLE_KEY"
)

print("\n========== CONFIGURAÇÃO SUPABASE ==========")
print("Arquivo .env:", caminho_env)
print("Arquivo existe:", caminho_env.is_file())
print("URL carregada:", repr(SUPABASE_URL))
print("============================================\n")

# Criar cliente de autenticação do Supabase.
def criar_cliente_auth():
    return create_client(
        SUPABASE_URL,
        SUPABASE_PUBLISHABLE_KEY
    )


# Verifica as configurações do Auth.
if not SUPABASE_URL or not SUPABASE_PUBLISHABLE_KEY:
    raise RuntimeError(
        "Configure SUPABASE_URL e SUPABASE_PUBLISHABLE_KEY no .env"
    )


CLOUDINARY_CLOUD_NAME = os.getenv("CLOUDINARY_CLOUD_NAME")
CLOUDINARY_API_KEY = os.getenv("CLOUDINARY_API_KEY")
CLOUDINARY_API_SECRET = os.getenv("CLOUDINARY_API_SECRET")


# Verifica se os dados foram configuradas.
if not all([
    CLOUDINARY_CLOUD_NAME,
    CLOUDINARY_API_KEY,
    CLOUDINARY_API_SECRET
]):
    raise RuntimeError(
        "Configure as credenciais do Cloudinary no arquivo .env"
    )


# Configura o SDK do Cloudinary.
cloudinary.config(
    cloud_name=CLOUDINARY_CLOUD_NAME,
    api_key=CLOUDINARY_API_KEY,
    api_secret=CLOUDINARY_API_SECRET,
    secure=True
)

if not DATABASE_URL:
    raise RuntimeError(
        "Configure DATABASE_URL no arquivo .env"
    )


# Preparar a conexão com o PostgreSQL.
engine = create_engine(
    DATABASE_URL,
    connect_args={"sslmode": "require"},
    pool_pre_ping=True
)


# Criar a aplicação FastAPI.
app = FastAPI(
    title="API Lista de Compras",
    version="0.1.0"
)

# Modelo para cadastro e login.
class CredenciaisAuth(BaseModel):

    email: str = Field(
        min_length=5,
        max_length=254
    )

    senha: str = Field(
        min_length=8,
        max_length=128
    )

class ListaCreate(BaseModel):
    nome: str = Field(min_length=1, max_length=150)

class ProdutoPersonalizadoCreate(BaseModel):
    nome: str = Field(min_length=1, max_length=150)
    imagem_url: str|None = Field(default=None, max_length=2048)
    cloudinary_public_id: str | None = Field(default=None, max_length=255)


class ProdutoAdicionarLista(BaseModel):
    produto_id: int = Field(gt=0)
    quantidade: int = Field(default=1, ge=1)
    preco_usuario: Decimal | None = Field(
        default=None,
        ge=0
    )


@app.post("/auth/register", status_code=201)
def cadastrar_usuario(dados: CredenciaisAuth):
    # Padroniza o e-mail: remove espaços e altera para letras minúsculas.
    email = dados.email.strip().lower()

    try:
        # Cria o cliente de conexão com o Supabase AUTH.
        cliente = criar_cliente_auth()

        # Envia o e-mail e senha para o Supabase realizar o cadastro.
        resposta = cliente.auth.sign_up({
            "email": email,
            "password": dados.senha
        })

        # Obtém os dados retornados pelo Supabase.
        usuario = resposta.user
        sessao = resposta.session

        # Verifica se o Supabase retornou o usuário.
        if usuario is None:
            raise HTTPException(
                status_code=400,
                detail="O Supabase não retornou os dados do usuário."
            )

        # resposta enviada ao android ou ao swagger.
        resultado = {
            "mensagem": "Cadastro realizado com sucesso.",
            "usuario": {
                "id": str(usuario.id),
                "email": usuario.email
            },
            "email_confirmacao_necessaria": sessao is None
        }

        # Se já criou uma sessão retorna os tokens (supabase).
        if sessao is not None:
            resultado.update({
                "access_token": sessao.access_token,
                "refresh_token": sessao.refresh_token,
                "token_type": sessao.token_type,
                "expires_in": sessao.expires_in
            })

        return resultado

    # Erros HTTP.
    except HTTPException:
        raise

    # Detalhes de erros do supabase.
    except Exception as erro:

        mensagem = (
            getattr(erro, "message", None)
            or str(erro)
        )

        codigo = getattr(erro, "code", None)

        status = getattr(erro, "status", None)

        status_code = getattr(erro, "status_code", None)

        print("\n========== ERRO SUPABASE AUTH ==========")
        print("Tipo:", type(erro).__name__)
        print("Status:", status)
        print("Status code:", status_code)
        print("Código:", codigo)
        print("Mensagem:", mensagem)
        print("Detalhes:", repr(erro))
        print("Causa:", repr(erro.__cause__))
        print("Contexto:", repr(erro.__context__))
        print("========================================\n")

        # Aproveita o código HTTP
        try:
            status_http = int(
                status_code if status_code is not None else status
            )
        except (TypeError, ValueError):
            status_http = 502

        # Códigos HTTP.
        if status_http < 400 or status_http > 599:
            status_http = 502

        raise HTTPException(
            status_code=status_http,
            detail=(
                "Não foi possível realizar o cadastro. "
                "Consulte o terminal da API para verificar o erro do Supabase."
            )
        ) from erro

@app.post("/auth/login")
def login_usuario(dados: CredenciaisAuth):

    email = dados.email.strip().lower()

    try:
        cliente =criar_cliente_auth()

        resposta = cliente.auth.sign_in_with_password({
            "email": email,
            "password": dados.senha
        })

        usuario = resposta.user
        sessao = resposta.session

        if usuario is None or sessao is None:
            raise HTTPException(
                status_code=401,
                detail="Não foi possível autenticar o usuário."
            )

        return {
            "mensagem": "Login realizado com sucesso.",
            "usuario": {
                "id": str(usuario.id),
                "email": usuario.email
            },
            "access_token": sessao.access_token,
            "refresh_token": sessao.refresh_token,
            "token_type": sessao.token_type,
            "expires_in": sessao.expires_in
        }

    except HTTPException:
        raise

    except Exception as erro:

        print(
            "Erro no login Supabase Auth:",
            type(erro).__name__
        )

        raise HTTPException(
            status_code=401,
            detail=(
                "E-mail ou senha inválidos, "
                "ou conta ainda não confirmada."
            )
        ) from erro

security = HTTPBearer(auto_error=False)
def obter_usuario_atual(
    credenciais: HTTPAuthorizationCredentials | None = Depends(security)
):

    if credenciais is None:
        raise HTTPException(
            status_code=401,
            detail="Autenticação necessária."
        )

    token =credenciais.credentials

    try:
        cliente = criar_cliente_auth()

        # O supabase verifica o JWT e retorna o usuário.
        resposta = cliente.auth.get_user(token)

        usuario = resposta.user

        if usuario is None:
            raise HTTPException(
                status_code=401,
                detail="Usuário não autenticado."
            )

        return {
            "id": str(usuario.id),
            "email": usuario.email
        }

    except HTTPException:
        raise

    except Exception as erro:

        print(
            "Erro ao validar token:",
            type(erro).__name__
        )

        raise HTTPException(
            status_code=401,
            detail="Token inválido ou expirado."
        ) from erro

@app.get("/auth/me")
def meu_usuario(
    usuario: dict = Depends(obter_usuario_atual)
):

    return {
        "mensagem": "Usuário autenticado.",
        "usuario": usuario
    }


@app.post("/listas", status_code=201)
def criar_lista(
    dados: ListaCreate,
    usuario: dict = Depends(obter_usuario_atual)
):

    # Remove espaços do nome.
    nome = dados.nome.strip()

    # Verifica nome vazio.
    if not nome:
        raise HTTPException(
            status_code=422,
            detail="O nome da lista não pode ficar vazio."
        )

    try:
        with engine.begin() as conexao:

            # Cria lista vinculada ao usuário.
            nova_lista = conexao.execute(
                text("""
                    INSERT INTO public.listas_compra (
                        nome,
                        usuario_id
                    )
                    VALUES (
                        :nome,
                        CAST(:usuario_id AS UUID)
                    )
                    RETURNING
                        id,
                        nome,
                        usuario_id,
                        criado_em
                """),
                {
                    "nome": nome,
                    "usuario_id": usuario["id"]
                }
            ).mappings().one()

            # Retorna os dados da lista criada.
            return dict(nova_lista)

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao criar a lista no PostgreSQL."
        ) from erro


# Endpoint inicial.
@app.get("/")
def inicio():
    return {
        "mensagem": "API da lista de compras funcionando!"
    }


# Verificar se a API responde.
@app.get("/health")
def verificar_api():
    return {
        "status": "ok"
    }


# Exemplo de endpoint.
@app.get("/exemplo/{item_id}")
def consultar_exemplo(item_id: int):
    return {
        "id": item_id
    }


# Validar os dados de um item.
class ItemTeste(BaseModel):
    nome: str = Field(
        min_length=1,
        max_length=150
    )

    imagem_url: str | None = None

    preco_usuario: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=10,
        decimal_places=2
    )

class ItemCreate(BaseModel):
    nome: str = Field(
        min_length=1,
        max_length=150
    )

    imagem_url: str | None = Field(
        default=None,
        max_length=2048
    )

    cloudinary_public_id: str | None = Field(
        default=None,
        max_length=255
    )
    imagem_enviada_pelo_usuario: bool = False

    preco_usuario: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=10,
        decimal_places=2
    )

    quantidade: int = Field(
        default=1,
        ge=1
    )

class CredenciaisAuth(BaseModel):

    email: str = Field(
        min_length=5,
        max_length=254
    )

    senha: str = Field(
        min_length=8,
        max_length=128
    )

class ItemUpdate(BaseModel):

    nome: str | None = Field(
        default=None,
        min_length=1,
        max_length=150
    )

    preco_usuario: Decimal | None = Field(
        default=None,
        ge=0,
        max_digits=10,
        decimal_places=2
    )

    quantidade: int | None = Field(
        default=None,
        ge=1
    )

    comprado: bool | None = None

# Receber dados de teste em json.
@app.post("/teste-item", status_code=201)
def testar_item(item: ItemTeste):
    return {
        "mensagem": "Dados recebidos. Ainda não foram salvos.",
        "item": item
    }


# tsetar a conexão com o postgreSQL.
@app.get("/health-db")
def verificar_banco():
    try:
        with engine.connect() as conexao:

            nome_banco = conexao.execute(
                text("SELECT current_database()")
            ).scalar_one()

        return {
            "api": "ok",
            "postgresql": "ok",
            "banco": nome_banco
        }

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Não foi possível conectar ao PostgreSQL."
        ) from erro


@app.post(
    "/listas/{lista_id}/itens",
    status_code=201
)
def criar_item(
    lista_id: int,
    item: ItemCreate,
    usuario: dict = Depends(obter_usuario_atual)
):

    nome = item.nome.strip()

    # Validação de nome.
    if not nome:
        raise HTTPException(
            status_code=422,
            detail="O nome do item não pode ficar vazio."
        )

    # Validação da imagem enviada pelo usuário.
    if item.imagem_enviada_pelo_usuario and not item.cloudinary_public_id:
        raise HTTPException(
            status_code=422,
            detail="Uma imagem enviada pelo usuário precisa ter um public_id."
        )

    # Ooperações com o banco.
    try:
        with engine.begin() as conexao:

            # Verifica se a lista pertence ao usuário autenticado
            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = CAST(:usuario_id AS UUID)
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

            # Impede inclusão de itens em listas de outras pessoas.
            if lista is None:
                raise HTTPException(
                    status_code=404,
                    detail="Lista não encontrada."
                )

            # Insere o novo produto no postgreSQL.
            novo_id = conexao.execute(
                text("""
                    INSERT INTO public.itens_lista (
                        lista_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario,
                        preco_usuario,
                        quantidade
                    )
                    VALUES (
                        :lista_id,
                        :nome,
                        :imagem_url,
                        :cloudinary_public_id,
                        :imagem_enviada_pelo_usuario,
                        :preco_usuario,
                        :quantidade
                    )
                    RETURNING id
                """),
                {
                    "lista_id": lista_id,
                    "nome": nome,
                    "imagem_url": item.imagem_url,
                    "cloudinary_public_id": item.cloudinary_public_id,
                    "imagem_enviada_pelo_usuario": item.imagem_enviada_pelo_usuario,
                    "preco_usuario": item.preco_usuario,
                    "quantidade": item.quantidade
                }
            ).scalar_one()

            # Busca o produto criado.
            item_criado = conexao.execute(
                text("""
                    SELECT
                        id,
                        lista_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        preco_usuario,
                        quantidade,
                        comprado
                    FROM public.itens_lista
                    WHERE id = :id
                """),
                {"id": novo_id}
            ).mappings().one()

            # Retorna os dados do produto criado.
            return dict(item_criado)

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao salvar o item no PostgreSQL."
        ) from erro


@app.post("/listas/{lista_id}/produtos", status_code=201)
def adicionar_produto_catalogo(
    lista_id: int,
    dados: ProdutoAdicionarLista,
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        with engine.begin() as conexao:

            # Verificar se a lista pertence ao usuario.
            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = CAST(:usuario_id AS UUID)
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

            if lista is None:
                raise HTTPException(
                    status_code=404,
                    detail="Lista não encontrada."
                )

            # Buscar o produto no catálogo.
            # Produtos compartilhados e personalizados do próprio
            # usuário podem ser utilizados.
            #1 e 2 top
            produto = conexao.execute(
                text("""
                    SELECT
                        id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario
                    FROM public.produtos
                    WHERE id = :produto_id
                      AND ativo = TRUE
                      AND (
                          usuario_id IS NULL
                          OR usuario_id = CAST(:usuario_id AS UUID)
                      )
                    FOR UPDATE
                """),
                {
                    "produto_id": dados.produto_id,
                    "usuario_id": usuario["id"]
                }
            ).mappings().first()

            if produto is None:
                raise HTTPException(
                    status_code=404,
                    detail="Produto não encontrado ou sem permissão de acesso."
                )

            # Inserir o produto na lista.
            # Se já existir nessa lista, aumentar a quantidade.
            item = conexao.execute(
                text("""
                    INSERT INTO public.itens_lista (
                        lista_id,
                        produto_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario,
                        preco_usuario,
                        quantidade,
                        comprado
                    )
                    VALUES (
                        :lista_id,
                        :produto_id,
                        :nome,
                        :imagem_url,
                        :cloudinary_public_id,
                        :imagem_enviada_pelo_usuario,
                        :preco_usuario,
                        :quantidade,
                        FALSE
                    )

                    ON CONFLICT (lista_id, produto_id)
                    WHERE produto_id IS NOT NULL

                    DO UPDATE SET
                        quantidade =
                            public.itens_lista.quantidade
                            + EXCLUDED.quantidade,

                        preco_usuario = COALESCE(
                            EXCLUDED.preco_usuario,
                            public.itens_lista.preco_usuario
                        ),

                        comprado = FALSE

                    RETURNING
                        id,
                        lista_id,
                        produto_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario,
                        preco_usuario,
                        quantidade,
                        comprado
                """),
                {
                    "lista_id": lista_id,
                    "produto_id": produto["id"],
                    "nome": produto["nome"],
                    "imagem_url": produto["imagem_url"],
                    "cloudinary_public_id": produto["cloudinary_public_id"],
                    "imagem_enviada_pelo_usuario": produto[
                        "imagem_enviada_pelo_usuario"
                    ],
                    "preco_usuario": dados.preco_usuario,
                    "quantidade": dados.quantidade
                }
            ).mappings().one()

            return dict(item)

    except HTTPException:
        raise

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao adicionar o produto à lista."
        ) from erro



@app.get("/listas/{lista_id}/itens")
def listar_itens(
    lista_id: int,
    usuario: dict = Depends(obter_usuario_atual)
):
    try:
        with engine.connect() as conexao:

            # 1. Verifica se a lista pertence ao usuário autenticado.
            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = :usuario_id
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

            # Se não encontrar então: a lista não existe ou pertence a outro usuário.
            if lista is None:
                raise HTTPException(
                    status_code=404,
                    detail="Lista não encontrada."
                )

            # Busca os produtos somente da lista autorizada.
            resultado = conexao.execute(
                text("""
                    SELECT
                        id,
                        lista_id,
                        produto_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        preco_usuario,
                        quantidade,
                        comprado
                    FROM public.itens_lista
                    WHERE lista_id = :lista_id
                    ORDER BY id DESC
                """),
                {
                    "lista_id": lista_id
                }
            )

            # Retorna os produtos encontrados (ver se devo apagar o(s) comentario(s) extremamente desnessesário(s) para ficar mais bonito).
            return [
                dict(item)
                for item in resultado.mappings().all()
            ]

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao consultar os itens."
        ) from erro



@app.patch("/listas/{lista_id}/itens/{item_id}")
def atualizar_item(
    lista_id: int,
    item_id: int,
    item: ItemUpdate,
    usuario: dict = Depends(obter_usuario_atual)
):

    # Obtém somente os campos enviados pelo android.
    dados = item.model_dump(exclude_unset=True)

    # Verifica se algum campo foi enviado.
    if not dados:
        raise HTTPException(
            status_code=400,
            detail="Nenhum dado foi enviado para atualização."
        )

    # Define os campos que podem ser atualizados.
    campos_permitidos = {
        "nome",
        "imagem_url",
        "cloudinary_public_id",
        "preco_usuario",
        "quantidade",
        "comprado"
    }

    # Valida os campos recebidos.
    if not set(dados.keys()).issubset(campos_permitidos):
        raise HTTPException(
            status_code=422,
            detail="Um ou mais campos não podem ser atualizados."
        )

    # Valida o nome, caso tenha sido enviado.
    if "nome" in dados:

        if dados["nome"] is None:
            raise HTTPException(
                status_code=422,
                detail="O nome não pode ser nulo."
            )

        dados["nome"] = dados["nome"].strip()

        if not dados["nome"]:
            raise HTTPException(
                status_code=422,
                detail="O nome não pode ficar vazio."
            )

    # Quantidade e status não podem ser null.
    for campo in ("quantidade", "comprado"):
        if campo in dados and dados[campo] is None:
            raise HTTPException(
                status_code=422,
                detail=f"O campo {campo} não pode ser nulo."
            )

    try:

        # Monta os campos que serão atualizados.
        campos= ", ".join(
            f"{campo} = :{campo}"
            for campo in dados
        )

        # Parâmetros SQL.
        parametros = {
            **dados,
            "lista_id": lista_id,
            "item_id": item_id,
            "usuario_id": usuario["id"]
        }

        with engine.begin() as conexao:

            # Verifica se a lista pertence ao usuário autenticado.
            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = CAST(:usuario_id AS UUID)
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

            if lista is None:
                raise HTTPException(
                    status_code=404,
                    detail="Lista não encontrada."
                )

            # Atualiza somente o item da lista autorizada.
            resultado = conexao.execute(
                text(f"""
                    UPDATE public.itens_lista
                    SET {campos}
                    WHERE id = :item_id
                      AND lista_id = :lista_id
                      AND lista_id IN (
                          SELECT id
                          FROM public.listas_compra
                          WHERE usuario_id = CAST(:usuario_id AS UUID)
                      )
                    RETURNING
                        id,
                        lista_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        preco_usuario,
                        quantidade,
                        comprado
                """),
                parametros
            )

            item_atualizado = resultado.mappings().first()

            if item_atualizado is None:
                raise HTTPException(
                    status_code=404,
                    detail="Item não encontrado nessa lista."
                )

            # Retorna os dados atualizados.
            return dict(item_atualizado)

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code = 503,
            detail="Falha ao atualizar o item."
        ) from erro



@app.delete("/listas/{lista_id}/itens/{item_id}")
def excluir_item(
    lista_id: int,
    item_id: int,
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        with engine.begin() as conexao:

            # Verificar se a lista pertence ao usuário autenticado.
            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = CAST(:usuario_id AS UUID)
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

            if lista is None:
                raise HTTPException(
                    status_code=404,
                    detail="Lista não encontrada."
                )

            # Localizar o item antes de excluí-lo.
            item = conexao.execute(
                text("""
                    SELECT
                        id,
                        produto_id,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario
                    FROM public.itens_lista
                    WHERE id = :item_id
                      AND lista_id = :lista_id
                    FOR UPDATE
                """),
                {
                    "item_id": item_id,
                    "lista_id": lista_id
                }
            ).mappings().first()

            if item is None:
                raise HTTPException(
                    status_code=404,
                    detail="Item não encontrado nesta lista."
                )

            public_id = item["cloudinary_public_id"]

            imagem_propria = (
                item["imagem_enviada_pelo_usuario"]
                and item["produto_id"] is None
            )

            # Excluir o registro do PostgreSQL.
            conexao.execute(
                text("""
                    DELETE FROM public.itens_lista
                    WHERE id = :item_id
                      AND lista_id = :lista_id
                """),
                {
                    "item_id": item_id,
                    "lista_id": lista_id
                }
            )

            # Verificar se outro item utiliza a mesma imagem.
            imagem_em_uso = False

            if imagem_propria and public_id:

                imagem_em_uso = conexao.execute(
                    text("""
                        SELECT EXISTS (
                            SELECT 1
                            FROM public.itens_lista
                            WHERE cloudinary_public_id = :public_id
                        )
                    """),
                    {"public_id": public_id}
                ).scalar_one()

    except SQLAlchemyError as erro:
        original = erro.orig
        diagnostico = getattr(original, "diag", None)

        print("\n========== ERRO AO EXCLUIR ITEM ==========")
        print("Tipo:", type(erro).__name__)
        print("Erro SQL original:", repr(original))
        print("SQLSTATE:", getattr(original, "sqlstate", None))
        print(
            "Mensagem PostgreSQL:",
            getattr(diagnostico, "message_primary", None)
        )
        print(
            "Detalhes PostgreSQL:",
            getattr(diagnostico, "message_detail", None)
        )
        print(
            "Restrição:",
            getattr(diagnostico, "constraint_name", None)
        )
        print("==========================================\n")

        raise HTTPException(
            status_code=503,
            detail="Falha ao excluir o item do PostgreSQL. Consulte o terminal."
        ) from erro


    # Excluir do Cloudinary se for seguro.
    imagem_excluida = False

    observacao = "Nenhuma imagem foi excluída do Cloudinary."

    if imagem_propria and public_id and not imagem_em_uso:

        try:
            resultado = cloudinary.uploader.destroy(
                public_id,
                resource_type="image",
                invalidate=True
            )

            if resultado.get("result") == "ok":
                imagem_excluida = True

                observacao = "Imagem removida do Cloudinary."

            else:
                observacao = (
                    "O produto foi removido, mas o Cloudinary "
                    "não confirmou a exclusão da imagem."
                )

        except Exception:
            observacao = (
                "O produto foi removido, mas ocorreu um erro "
                "ao excluir a imagem do Cloudinary."
            )

    elif imagem_em_uso:
        observacao = (
            "A imagem foi preservada porque outro produto "
            "também utiliza esse arquivo."
        )

    # Retornar o resultado da exclusão.
    return {
        "mensagem": "Item removido com sucesso.",
        "id": item_id,
        "imagem_excluida": imagem_excluida,
        "observacao": observacao
    }



@app.get("/listas/{lista_id}/resumo")
def calcular_resumo(
    lista_id: int,
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        with engine.connect() as conexao:

            # 1. Verificar se a lista pertence ao usuário autenticado.
            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = CAST(:usuario_id AS UUID)
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

            if lista is None:
                raise HTTPException(
                    status_code=404,
                    detail="Lista não encontrada."
                )

            # Calcular os totais e as quantidades.
            resultado = conexao.execute(
                text("""
                    SELECT

                        COUNT(*) AS total_itens,

                        COALESCE(
                            SUM(quantidade), 0
                        ) AS unidades_totais,

                        COUNT(*) FILTER (
                            WHERE comprado = TRUE
                        ) AS itens_comprados,

                        COUNT(*) FILTER (
                            WHERE comprado = FALSE
                        ) AS itens_pendentes,

                        COALESCE(
                            SUM(quantidade) FILTER (
                                WHERE comprado = TRUE
                            ), 0
                        ) AS unidades_compradas,

                        COALESCE(
                            SUM(quantidade) FILTER (
                                WHERE comprado = FALSE
                            ), 0
                        ) AS unidades_pendentes,

                        COUNT(*) FILTER (
                            WHERE preco_usuario IS NULL
                        ) AS itens_sem_preco,

                        COALESCE(
                            SUM(preco_usuario * quantidade)
                            FILTER (
                                WHERE preco_usuario IS NOT NULL
                            ), 0
                        ) AS total_estimado,

                        COALESCE(
                            SUM(preco_usuario * quantidade)
                            FILTER (
                                WHERE comprado = TRUE
                                AND preco_usuario IS NOT NULL
                            ), 0
                        ) AS total_comprado,

                        COALESCE(
                            SUM(preco_usuario * quantidade)
                            FILTER (
                                WHERE comprado = FALSE
                                AND preco_usuario IS NOT NULL
                            ), 0
                        ) AS total_pendente

                    FROM public.itens_lista

                    WHERE lista_id = :lista_id
                """),
                {
                    "lista_id": lista_id
                }
            ).mappings().one()

            # Organizar o resultado.
            resumo = dict(resultado)

            # Formatar os valores.
            campos_monetarios = [
                "total_estimado",
                "total_comprado",
                "total_pendente"
            ]

            for campo in campos_monetarios:
                resumo[campo] = f"{resumo[campo]:.2f}"

            # 5. Informar o ID da lista e se todos os produtos possuem preço cadastrado.
            resumo["lista_id"] = lista_id

            resumo["total_completo"] = (
                resumo["itens_sem_preco"] == 0
            )

            return resumo

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao calcular o resumo da lista."
        ) from erro


# Tamanho máximo permitido 5 MB.
MAX_IMAGE_SIZE = 5*1024*1024


# Formatos de imagem permitidos.
FORMATOS_PERMITIDOS = {
    "image/jpeg": "JPEG",
    "image/png": "PNG",
    "image/webp": "WEBP"
}


# Endpoint para enviar uma imagem ao Cloudinary.

@app.post("/listas/{lista_id}/imagens/upload")
def enviar_imagem(
    lista_id: int,
    arquivo: UploadFile = File(...),
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        # Verificar se a lista pertence ao usuário autenticado.
        with engine.connect() as conexao:

            lista = conexao.execute(
                text("""
                    SELECT id
                    FROM public.listas_compra
                    WHERE id = :lista_id
                      AND usuario_id = CAST(:usuario_id AS UUID)
                """),
                {
                    "lista_id": lista_id,
                    "usuario_id": usuario["id"]
                }
            ).first()

        if lista is None:
            raise HTTPException(
                status_code=404,
                detail="Lista não encontrada."
            )

        # Verificar o tipo informado pelo arquivo.
        if arquivo.content_type not in FORMATOS_PERMITIDOS:
            raise HTTPException(
                status_code=415,
                detail="Formato não permitido. Envie JPG, PNG ou WEBP."
            )

        # Ler o arquivo limitando o tamanho.
        conteudo = arquivo.file.read(MAX_IMAGE_SIZE + 1)

        if len(conteudo) > MAX_IMAGE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="A imagem deve ter no máximo 5 MB."
            )

        # Verificar se o arquivo realmente é uma imagem.
        try:
            with Image.open(BytesIO(conteudo)) as imagem:
                formato_real = imagem.format
                imagem.verify()

        except (
            UnidentifiedImageError,
            OSError,
            Image.DecompressionBombError
        ):
            raise HTTPException(
                status_code=415,
                detail="O arquivo enviado não é uma imagem válida."
            )

        # Vereficar se o conteúdo corresponde ao tipo informado.
        formato_esperado = FORMATOS_PERMITIDOS[
            arquivo.content_type
        ]

        if formato_real != formato_esperado:
            raise HTTPException(
                status_code=415,
                detail="O formato real da imagem não corresponde ao arquivo."
            )

        # Enviar a imagem ao Cloudinary.
        resultado = cloudinary.uploader.upload(
            conteudo,
            folder="lista_compras",
            resource_type="image",
            allowed_formats=["jpg", "jpeg", "png", "webp"]
        )

        # Devolver as informações da imagem.
        return {
            "mensagem": "Imagem enviada com sucesso!",
            "imagem_url": resultado["secure_url"],
            "cloudinary_public_id":resultado["public_id"],
            "formato": resultado.get("format"),
            "tamanho_bytes": resultado.get("bytes"),
            "largura": resultado.get("width"),
            "altura": resultado.get("height")
        }

    except HTTPException:
        raise

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao verificar a propriedade da lista."
        ) from erro

    except Exception as erro:
        raise HTTPException(
            status_code=502,
            detail="Não foi possível enviar a imagem ao Cloudinary."
        ) from erro

    finally:
        arquivo.file.close()


@app.post("/imagens/produtos/upload")
def enviar_imagem_produto(
    arquivo: UploadFile = File(...),
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        # Verificar o tipo informado pelo arquivo.
        if arquivo.content_type not in FORMATOS_PERMITIDOS:
            raise HTTPException(
                status_code=415,
                detail="Formato não permitido. Envie JPG, PNG ou WEBP."
            )

        # Ler o arquivo limitando o tamanho a 5 MB.
        conteudo = arquivo.file.read(MAX_IMAGE_SIZE + 1)

        if len(conteudo) > MAX_IMAGE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="A imagem deve ter no máximo 5 MB."
            )

        # Verificar se o arquivo realmente é uma imagem.
        try:
            with Image.open(BytesIO(conteudo)) as imagem:
                formato_real = imagem.format
                imagem.verify()

        except (
            UnidentifiedImageError,
            OSError,
            Image.DecompressionBombError
        ):
            raise HTTPException(
                status_code=415,
                detail="O arquivo enviado não é uma imagem valida."
            )

        # Conferir se o conteúdo corresponde ao tipo informado.
        formato_esperado = FORMATOS_PERMITIDOS[
            arquivo.content_type
        ]

        if formato_real != formato_esperado:
            raise HTTPException(
                status_code=415,
                detail="O formato real da imagem não corresponde ao arquivo."
            )

        # Criar uma pasta específica para as imagens dos produtos personalizados deste usuário.
        pasta_usuario = (
            f"lista_compras/produtos_personalizados/{usuario['id']}"
        )

        # Enviar a imagem ao Cloudinary.
        resultado = cloudinary.uploader.upload(
            conteudo,
            folder=pasta_usuario,
            resource_type="image",
            allowed_formats=["jpg", "jpeg", "png", "webp"]
        )

        # Retornar os dados necessários para cadastrar o produto.
        return {
            "mensagem": "Imagem enviada com sucesso!",
            "imagem_url": resultado["secure_url"],
            "cloudinary_public_id":resultado["public_id"],
            "formato": resultado.get("format"),
            "tamanho_bytes": resultado.get("bytes"),
            "largura": resultado.get("width"),
            "altura": resultado.get("height")
        }

    except HTTPException:
        raise

    except Exception as erro:
        print(
            "Erro no upload de imagem de produto:",
            type(erro).__name__,
            str(erro)
        )

        raise HTTPException(
            status_code = 502,
            detail="Não foi possível enviar a imagem ao Cloudinary."
        ) from erro

    finally:
        arquivo.file.close()




@app.get("/listas")
def listar_listas_usuario(
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        with engine.connect() as conexao:

            resultado = conexao.execute(
                text("""
                    SELECT
                        id,
                        nome,
                        criado_em
                    FROM public.listas_compra
                    WHERE usuario_id = CAST(:usuario_id AS UUID)
                    ORDER BY id DESC
                """),
                {
                    "usuario_id": usuario["id"]
                }
            )

            return [
                dict(lista)
                for lista in resultado.mappings().all()
            ]

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao consultar as listas do usuário."
        ) from erro


@app.get("/categorias")
def listar_categorias(
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        with engine.connect() as conexao:

            resultado = conexao.execute(
                text("""
                    SELECT
                        id,
                        nome,
                        slug,
                        ordem
                    FROM public.categorias
                    WHERE ativo = TRUE
                    ORDER BY ordem
                """)
            )

            return [
                dict(categoria)
                for categoria in resultado.mappings().all()
            ]

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao consultar as categorias."
        ) from erro


@app.get("/categorias/{categoria_id}/produtos")
def listar_produtos_categoria(
    categoria_id: int,
    usuario: dict = Depends(obter_usuario_atual)
):

    try:
        with engine.connect() as conexao:

            # Verificar se a categoria existe e está ativa.
            categoria = conexao.execute(
                text("""
                    SELECT id, nome, slug
                    FROM public.categorias
                    WHERE id = :categoria_id
                      AND ativo = TRUE
                """),
                {
                    "categoria_id": categoria_id
                }
            ).mappings().first()

            if categoria is None:
                raise HTTPException(
                    status_code=404,
                    detail="Categoria não encontrada."
                )

            # Buscar produtos disponíveis para o usuário.
            resultado = conexao.execute(
                text("""
                    SELECT
                        id,
                        categoria_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario,
                        criado_em
                    FROM public.produtos
                    WHERE categoria_id = :categoria_id
                      AND ativo = TRUE
                      AND (
                          usuario_id IS NULL
                          OR usuario_id = CAST(:usuario_id AS UUID)
                      )
                    ORDER BY nome ASC
                """),
                {
                    "categoria_id": categoria_id,
                    "usuario_id": usuario["id"]
                }
            )

            # Retornar os produtos.
            return [
                dict(produto)
                for produto in resultado.mappings().all()
            ]

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao consultar os produtos da categoria."
        ) from erro


@app.post("/produtos/personalizados", status_code=201)
def criar_produto_personalizado(
    dados: ProdutoPersonalizadoCreate,
    usuario: dict = Depends(obter_usuario_atual)
):

    # Validar o nome.
    nome = dados.nome.strip()

    if not nome:
        raise HTTPException(
            status_code=422,
            detail="O nome do produto não pode ficar vazio."
        )

    # Orgamizar os dados da imagem.
    imagem_url = (
        dados.imagem_url.strip()
        if dados.imagem_url
        else None
    )

    public_id = (
        dados.cloudinary_public_id.strip()
        if dados.cloudinary_public_id
        else None
    )

    # Verificar se URL e public_id foram enviados juntos.
    if (imagem_url is None) != (public_id is None):
        raise HTTPException(
            status_code=422,
            detail="A URL e o public_id da imagem devem ser enviados juntos."
        )

    try:
        with engine.begin() as conexao:

            # Localizar a categoria Personalizados.
            categoria = conexao.execute(
                text("""
                    SELECT id
                    FROM public.categorias
                    WHERE slug = 'personalizados'
                      AND ativo = TRUE
                """)
            ).mappings().first()

            if categoria is None:
                raise HTTPException(
                    status_code=500,
                    detail="A categoria Personalizados não foi encontrada."
                )

            # Inserir o produto vinculado ao usuário.
            resultado = conexao.execute(
                text("""
                    INSERT INTO public.produtos (
                        categoria_id,
                        usuario_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario
                    )
                    VALUES (
                        :categoria_id,
                        CAST(:usuario_id AS UUID),
                        :nome,
                        :imagem_url,
                        :cloudinary_public_id,
                        :imagem_enviada_pelo_usuario
                    )
                    RETURNING
                        id,
                        categoria_id,
                        usuario_id,
                        nome,
                        imagem_url,
                        cloudinary_public_id,
                        imagem_enviada_pelo_usuario,
                        ativo,
                        criado_em
                """),
                {
                    "categoria_id": categoria["id"],
                    "usuario_id": usuario["id"],
                    "nome": nome,
                    "imagem_url": imagem_url,
                    "cloudinary_public_id": public_id,
                    "imagem_enviada_pelo_usuario": public_id is not None
                }
            ).mappings().one()

            # Retornar o produto criado.
            return dict(resultado)

    except HTTPException:
        raise

    except SQLAlchemyError as erro:
        raise HTTPException(
            status_code=503,
            detail="Falha ao salvar o produto personalizado."
        ) from erro


