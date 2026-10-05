from flask import Blueprint, request, g
from backend.app.common.utils import api_response
from backend.app.common.security import token_required
from backend.app.common.validators import FileValidationError
from backend.app.documents.service import (
    process_document_upload,
    get_user_documents,
    get_document_by_id,
    get_document_findings,
    delete_document,
    get_document_risk
)

documents_bp = Blueprint("documents", __name__, url_prefix="/api/documents")


@documents_bp.route("/scan", methods=["POST"])
@token_required
def scan_document():
    """
    POST /api/documents/scan
    Authenticated endpoint to upload, extract text, and run PII detection.
    Returns document metadata, text preview, masked PII findings, and deterministic risk score.
    """
    if "file" not in request.files:
        return api_response(
            error={"code": "NO_FILE_PART", "message": "Multipart request must include a 'file' field."},
            status_code=400
        )

    file = request.files["file"]
    if not file or not file.filename:
        return api_response(
            error={"code": "NO_FILE_SELECTED", "message": "No file was selected for upload."},
            status_code=400
        )

    # Process extraction, deterministic PII detection, and privacy risk scoring
    doc_dict = process_document_upload(file, user_id=str(g.current_user.id))
    findings = doc_dict.pop("findings", [])
    risk = {
        "score": doc_dict.get("risk_score", 0.0),
        "risk_level": doc_dict.get("risk_level", "LOW"),
        "scoring_version": doc_dict.get("scoring_version", "1.0"),
        "explanation": doc_dict.get("score_explanation", {}),
    }

    return api_response(
        data={
            "document": doc_dict,
            "findings": findings,
            "risk": risk
        },
        message="Document uploaded, text extracted, and PII analyzed successfully.",
        status_code=201
    )


@documents_bp.route("", methods=["GET"])
@token_required
def list_documents():
    """
    GET /api/documents
    Retrieves paginated history of documents scanned by the authenticated user.
    """
    page = request.args.get("page", 1, type=int)
    limit = min(request.args.get("limit", 10, type=int), 50)
    offset = (page - 1) * limit

    docs, total = get_user_documents(str(g.current_user.id), limit=limit, offset=offset)

    return api_response(
        data={
            "documents": docs,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit if limit > 0 else 1
        },
        status_code=200
    )


@documents_bp.route("/<uuid:document_id>", methods=["GET"])
@token_required
def get_document(document_id):
    """
    GET /api/documents/<id>
    Retrieves document extraction details with strict user data isolation.
    """
    doc_dict = get_document_by_id(str(document_id), str(g.current_user.id))
    return api_response(
        data={"document": doc_dict},
        status_code=200
    )


@documents_bp.route("/<uuid:document_id>/findings", methods=["GET"])
@token_required
def get_document_findings_route(document_id):
    """
    GET /api/documents/<id>/findings
    Retrieves isolated PII findings for a document. Always returns masked values.
    """
    doc_info, findings = get_document_findings(str(document_id), str(g.current_user.id))
    return api_response(
        data={
            "document_id": str(document_id),
            "original_filename": doc_info["original_filename"],
            "total_findings": len(findings),
            "findings": findings
        },
        status_code=200
    )


@documents_bp.route("/<uuid:document_id>", methods=["DELETE"])
@token_required
def remove_document(document_id):
    """
    DELETE /api/documents/<id>
    Deletes document record.
    """
    delete_document(str(document_id), str(g.current_user.id))
    return api_response(
        data={"deleted": True},
        message="Document record removed successfully.",
        status_code=200
    )


@documents_bp.route("/<uuid:document_id>/risk", methods=["GET"])
@token_required
def get_document_risk_route(document_id):
    """
    GET /api/documents/<id>/risk
    Retrieves deterministic privacy risk scoring breakdown for a document.
    """
    risk_data = get_document_risk(str(document_id), str(g.current_user.id))
    return api_response(
        data=risk_data,
        status_code=200
    )

