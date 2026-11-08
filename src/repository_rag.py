from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer
from langchain_text_splitters import RecursiveCharacterTextSplitter


DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


INDEX_EXTENSIONS = {
    ".py",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".ini",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".sql",
}


EXCLUDED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".idea",
    ".vscode",
}


CHUNK_SIZE = 6400
CHUNK_OVERLAP = 1200


def _clean_text(text: str) -> str:
    text = text.replace("\x00", " ")
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _chunks(text: str) -> list[dict[str, Any]]:
    if not text:
        return []

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
        length_function=len,
        add_start_index=True,
        strip_whitespace=True,
    )

    documents = splitter.create_documents([text])
    result = []

    for document in documents:
        content = document.page_content
        start_index = document.metadata.get("start_index", 0)

        if not content:
            continue

        start_line = text[:start_index].count("\n") + 1
        end_line = start_line + content.count("\n")

        result.append({
            "start_line": start_line,
            "end_line": end_line,
            "text": content,
        })

    return result


class RepositoryRAG:
    """Local repository RAG using SentenceTransformers + persistent Chroma."""

    def __init__(
        self,
        persist_dir: str | Path,
        embedding_model: str = DEFAULT_EMBEDDING_MODEL,
    ):
        self.persist_dir = Path(persist_dir)

        self.persist_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self.embedding_model_name = embedding_model

        self.embedder = SentenceTransformer(
            embedding_model
        )

        self.client = chromadb.PersistentClient(
            path=str(self.persist_dir)
        )

        self.collection = self.client.get_or_create_collection(
            name="securepatch_repository",
            metadata={
                "hnsw:space": "cosine"
            },
        )

    @staticmethod
    def _repo_id(repo: Path) -> str:
        return str(
            repo.resolve()
        ).lower()

    @staticmethod
    def _files(repo: Path) -> list[Path]:
        repo = repo.resolve()

        if not repo.exists() or not repo.is_dir():
            return []

        files = []

        for path in repo.rglob("*"):

            if not path.is_file():
                continue

            if any(
                part in EXCLUDED_DIRS
                for part in path.parts
            ):
                continue

            if (
                path.suffix.lower()
                not in INDEX_EXTENSIONS
            ):
                continue

            files.append(path)

        return sorted(files)

    def index(
        self,
        repo: str | Path,
    ) -> dict[str, Any]:

        repo = Path(repo).resolve()

        if not repo.exists():
            raise FileNotFoundError(
                f"Repository does not exist: {repo}"
            )

        if not repo.is_dir():
            raise NotADirectoryError(
                f"Repository is not a directory: {repo}"
            )

        repo_id = self._repo_id(repo)

        files = self._files(repo)

        # Remove old chunks belonging to this repository
        try:
            self.collection.delete(
                where={
                    "repo_id": repo_id
                }
            )
        except Exception:
            pass

        documents = []
        metadatas = []
        ids = []

        for file_path in files:

            try:
                raw = file_path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )

            except OSError:
                continue

            text = _clean_text(raw)

            if not text:
                continue

            relative = file_path.relative_to(
                repo
            ).as_posix()

            for chunk_index, chunk in enumerate(
                _chunks(text)
            ):

                content = chunk["text"]

                chunk_id = hashlib.sha1(
                    f"{repo_id}:{relative}:{chunk_index}".encode(
                        "utf-8"
                    )
                ).hexdigest()

                ids.append(chunk_id)

                documents.append(content)

                metadatas.append(
                    {
                        "repo_id": repo_id,
                        "file": relative,
                        "start_line": int(
                            chunk["start_line"]
                        ),
                        "end_line": int(
                            chunk["end_line"]
                        ),
                        "chunk": int(
                            chunk_index
                        ),
                    }
                )

        # Generate embeddings and store in Chroma
        if documents:

            embeddings = self.embedder.encode(
                documents,
                normalize_embeddings=True,
                show_progress_bar=False,
                batch_size=32,
            ).tolist()

            batch_size = 128

            for start in range(
                0,
                len(documents),
                batch_size,
            ):

                end = start + batch_size

                self.collection.add(
                    ids=ids[start:end],
                    documents=documents[start:end],
                    metadatas=metadatas[start:end],
                    embeddings=embeddings[start:end],
                )

        return {
            "files_indexed": len(
                {
                    item["file"]
                    for item in metadatas
                }
            ),
            "chunks_indexed": len(documents),
            "embedding_model": self.embedding_model_name,
            "repo_path": str(repo),
        }

    def query(
        self,
        query: str,
        k: int = 6,
        repo: str | Path | None = None,
    ) -> list[dict[str, Any]]:

        query = (query or "").strip()

        if not query or repo is None:
            return []

        repo_id = self._repo_id(
            Path(repo)
        )

        total = self.collection.count()

        if total == 0:
            return []

        query_embedding = self.embedder.encode(
            [query],
            normalize_embeddings=True,
            show_progress_bar=False,
        )[0].tolist()

        result = self.collection.query(
            query_embeddings=[
                query_embedding
            ],
            n_results=min(
                max(int(k), 1),
                total,
            ),
            where={
                "repo_id": repo_id
            },
            include=[
                "documents",
                "metadatas",
                "distances",
            ],
        )

        documents = (
            result.get("documents")
            or [[]]
        )[0]

        metadatas = (
            result.get("metadatas")
            or [[]]
        )[0]

        distances = (
            result.get("distances")
            or [[]]
        )[0]

        retrieved = []

        for (
            document,
            metadata,
            distance,
        ) in zip(
            documents,
            metadatas,
            distances,
        ):

            score = 1.0 - float(distance)

            retrieved.append(
                {
                    "file": metadata.get(
                        "file",
                        "",
                    ),
                    "start_line": int(
                        metadata.get(
                            "start_line",
                            0,
                        )
                    ),
                    "end_line": int(
                        metadata.get(
                            "end_line",
                            0,
                        )
                    ),
                    "score": round(
                        score,
                        4,
                    ),
                    "text": document,
                    "distance": round(
                        float(distance),
                        4,
                    ),
                }
            )

        return retrieved


def format_context(
    retrieved: list[dict[str, Any]],
) -> str:

    parts = []

    for index, item in enumerate(
        retrieved,
        start=1,
    ):

        parts.append(
            f"""[REPOSITORY EVIDENCE {index}]
File: {item.get("file", "")}
Lines: {item.get("start_line", "")}-{item.get("end_line", "")}
Similarity: {item.get("score", 0)}

{item.get("text", "")}""".strip()
        )

    return "\n\n".join(parts)