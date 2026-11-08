from routes.documents import DocumentController

def test_document_listing():
    controller = DocumentController()
    documents = controller.list_documents(2)
    assert len(documents) >= 1
    assert documents[0]["owner_id"] == 2

def test_archive_document():
    controller = DocumentController()
    result = controller.archive(2, 1)
    assert result["success"] is True
    assert result["status"] == "archived"

def test_restore_document():
    controller = DocumentController()
    result = controller.restore(2, 1)
    assert result["success"] is True
    assert result["status"] == "uploaded"
