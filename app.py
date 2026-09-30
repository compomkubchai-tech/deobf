import io, os
from flask import Flask, render_template, request, jsonify, send_file
from decompiler import deobfuscate

app = Flask(__name__)
MAX_BYTES = 8 * 1024 * 1024

@app.get("/")
def index():
    return render_template("index.html")

@app.post("/api/deobfuscate")
def api_deobfuscate():
    f = request.files.get("file")
    src = request.form.get("source", "")
    name = "input.lua"
    if f and f.filename:
        raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return jsonify(error="File too large (8 MB max)."), 413
        src = raw.decode("utf-8", "replace")
        name = os.path.basename(f.filename)
    if not src.strip():
        return jsonify(error="No source supplied."), 400
    try:
        result, stats = deobfuscate(src)
    except Exception as e:
        return jsonify(error=str(e)), 400
    return jsonify(
        output=result,
        filename="deobf_" + name.rsplit(".", 1)[0] + ".lua",
        stats=stats,
    )

@app.post("/deobfuscate")
def deobfuscate_download():
    f = request.files.get("file")
    src = request.form.get("source", "")
    name = "input.lua"
    if f and f.filename:
        raw = f.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            return "File too large (8 MB max).", 413
        src = raw.decode("utf-8", "replace")
        name = os.path.basename(f.filename)
    if not src.strip():
        return "No source supplied.", 400
    try:
        result, _ = deobfuscate(src)
    except Exception as e:
        return f"Deobfuscation failed: {e}", 400
    return send_file(
        io.BytesIO(result.encode("utf-8")),
        mimetype="text/plain; charset=utf-8",
        as_attachment=True,
        download_name="deobf_" + name.rsplit(".", 1)[0] + ".lua",
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "10000")))
