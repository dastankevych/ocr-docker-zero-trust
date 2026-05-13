# -*- coding: utf-8 -*-
import base64
import os
import subprocess
import time
import uuid

from flask import Flask, jsonify, render_template, request, send_from_directory
from flask_restful import Api
from loguru import logger
import pytesseract

from zt_integration import decrypt_payload, get_manifest, landing_manifest_json

try:
    from PIL import Image
except ImportError:
    import Image


def allowed_file(image_file):
    logger.info("Validating file extension")
    return "." in image_file and image_file.rsplit(".", 1)[1].lower() in "png,jpg,pdf,tiff"


def convert_to_tiff(image_file):
    logger.info("Converting pdf to tiff")
    converted_file_name = image_file.replace("pdf", "tiff")
    process = subprocess.Popen(
        "convert -density 300 "
        + image_file
        + " -background white -alpha Off "
        + converted_file_name,
        stderr=subprocess.STDOUT,
        shell=True,
    )
    process.wait()
    time.sleep(5)
    if os.path.exists(image_file):
        os.remove(image_file)
    return converted_file_name


app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = os.environ.get("UPLOAD_FOLDER", "/opt/ocr/tmp")
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
api = Api(app)


def current_origin():
    host = request.headers.get("Host", "").strip()
    if not host:
        return ""
    scheme = request.headers.get("X-Forwarded-Proto", request.scheme or "http").strip() or "http"
    return f"{scheme}://{host}"


def run_ocr_file(file_path, language):
    if file_path.endswith(".pdf"):
        file_path = convert_to_tiff(file_path)
    if file_path.endswith(".tiff"):
        image = Image.open(file_path)
        text = ""
        for frame in range(image.n_frames):
            image.seek(frame)
            text += pytesseract.image_to_string(image, config="--psm 6", lang=language) + "\n"
        return text
    return pytesseract.image_to_string(Image.open(file_path), lang=language)


@app.route("/zt-manifest", methods=["GET"])
def zt_manifest():
    return jsonify(get_manifest(current_origin()))


@app.route("/v1/submit", methods=["POST"])
def zt_submit():
    try:
        fields = decrypt_payload(request.get_json())
    except Exception as error:
        return jsonify({"ok": False, "error": str(error)}), 400

    doc = fields.get("document") or {}
    language = fields.get("language") or "eng"
    file_b64 = doc.get("file_data_b64") if isinstance(doc, dict) else None

    if not file_b64:
        return jsonify({"ok": False, "error": "no document"}), 400

    file_name = doc.get("file_name", "upload.png").lower()
    tmp_path = os.path.join(app.config["UPLOAD_FOLDER"], f"zt_{uuid.uuid4().hex}_{file_name}")
    try:
        file_bytes = base64.b64decode(file_b64)
        with open(tmp_path, "wb") as handle:
            handle.write(file_bytes)
        text = run_ocr_file(tmp_path, language)
        return jsonify({"ok": True, "text": text})
    except Exception as error:
        return jsonify({"ok": False, "error": str(error)}), 500
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


@app.route("/ocr", methods=["POST"])
def ocr():
    language = str(request.form["languages"])
    if "file" not in request.files:
        return "Data posted does not contains files"
    file = request.files["file"]
    if not allowed_file(file.filename):
        return "The file type you uploaded is not supported"
    if not language:
        return "Please select OCR Language"
    if file and allowed_file(file.filename):
        filename = file.filename.lower()
        image_file = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(image_file)
        return run_ocr_file(image_file, language)


@app.route("/")
def devices():
    return render_template("index.html", manifest_json=landing_manifest_json(current_origin()))


@app.route("/languages")
def languages():
    return jsonify(pytesseract.get_languages())


@app.route("/js/<path:path>")
def send_js(path):
    return send_from_directory("js", path)


@app.route("/css/<path:path>")
def send_css(path):
    return send_from_directory("css", path)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8080)
