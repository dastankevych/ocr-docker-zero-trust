# -*- coding: utf-8 -*-
from flask import Flask, request, make_response, render_template, url_for, g, send_from_directory, jsonify, send_file
from flask_restful import Resource, Api
from json import dumps
from loguru import logger
import yaml, uuid, base64, os, io
import pytesseract
import subprocess
from subprocess import Popen
import time
from zt_integration import get_manifest, decrypt_payload

try:
    from PIL import Image
except ImportError:
    import Image


# Validating file extension
def allowed_file(image_file):
    logger.info("Validating file extension")
    return '.' in image_file and \
           image_file.rsplit('.', 1)[1].lower() in "png,jpg,pdf,tiff"

# Getting file extension
def getExtention(image_file):
    logger.info("Getting file extension")
    filename, file_extension = os.path.splitext(image_file)
    return filename, file_extension

def convert_to_tiff(image_file):
    logger.info("Converting pdf to tiff")
    converted_file_name = image_file.replace('pdf','tiff')
    p = subprocess.Popen('convert -density 300 '+ image_file +' -background white -alpha Off '+ converted_file_name , stderr=subprocess.STDOUT, shell=True)
    p_status = p.wait()
    time.sleep(5)
    if os.path.exists(image_file):
        os.remove(image_file)
    return converted_file_name


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "/opt/ocr/tmp"
api = Api(app)


@app.route('/zt-manifest', methods=['GET'])
def zt_manifest():
    origin = request.headers.get('Host', '')
    if origin:
        origin = f"https://{origin}"
    return jsonify(get_manifest(origin))

@app.route('/v1/submit', methods=['POST'])
def zt_submit():
    try:
        fields = decrypt_payload(request.get_json())
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 400

    doc = fields.get('document') or {}
    language = fields.get('language') or 'eng'
    file_b64 = doc.get('file_data_b64') if isinstance(doc, dict) else None

    if not file_b64:
        return jsonify({'ok': False, 'error': 'no document'}), 400

    try:
        file_bytes = base64.b64decode(file_b64)
        file_name  = doc.get('file_name', 'upload.png').lower()
        tmp_path   = os.path.join(app.config['UPLOAD_FOLDER'], f'zt_{uuid.uuid4().hex}_{file_name}')
        with open(tmp_path, 'wb') as f:
            f.write(file_bytes)
        if tmp_path.endswith('.pdf'):
            tmp_path = convert_to_tiff(tmp_path)
        if tmp_path.endswith('.tiff'):
            img = Image.open(tmp_path)
            txt = ''
            for frame in range(img.n_frames):
                img.seek(frame)
                txt += pytesseract.image_to_string(img, config='--psm 6', lang=language) + '\n'
        else:
            txt = pytesseract.image_to_string(Image.open(tmp_path), lang=language)
        os.remove(tmp_path)
        return jsonify({'ok': True, 'text': txt})
    except Exception as e:
        return jsonify({'ok': False, 'error': str(e)}), 500


@app.route('/ocr', methods=['POST'])
def ocr():
    if request.method == 'POST':
        # check if the post request has the file part
        language = str(request.form['languages'])
        if 'file' not in request.files:
            return "Data posted does not contains files"
        file = request.files['file']
        if not allowed_file(file.filename):
            return "The file type you uploaded is not supported"
        if not language:
            return "Please select OCR Language"
        if file and allowed_file(file.filename):
            filename = file.filename.lower()
            image_file = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(image_file)
            if ".pdf" in image_file:
                image_file = convert_to_tiff(image_file)
            if ".tiff" in image_file:
                image = Image.open(image_file)
                config = ("--psm 6")
                txt = ''
                for frame in range(image.n_frames):
                    image.seek(frame)
                    txt += pytesseract.image_to_string(image, config = config, lang=language) + '\n'
                return txt
            else:
                return pytesseract.image_to_string(Image.open(image_file), lang=language)



@app.route('/')
def devices():
    return render_template('index.html')


@app.route('/languages')
def languages():
    return jsonify(pytesseract.get_languages())

# Serve Javascript
@app.route('/js/<path:path>')
def send_js(path):
    return send_from_directory('js', path)

@app.route('/css/<path:path>')
def send_css(path):
    return send_from_directory('css', path)




# Start Application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
