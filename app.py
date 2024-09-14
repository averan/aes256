from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = ''
    key_default = 'E45CAEC8F1F2DEC1DD1E9BE1C9CB548C636BEED4C32AD48B39E7E105AA061759'
    iv_default = '63520F9035ED12DC5FBAAD1DB0ECD6D1'
    data_default = '1234567890123456'

    if request.method == 'POST':
        action = request.form.get('action')
        key = request.form.get('key')
        iv = request.form.get('iv')
        data = request.form.get('data')
        data_type = request.form.get('data_type')
        padding = request.form.get('padding')

        try:
            # Convertir key y iv de hexadecimal a bytes
            key_bytes = binascii.unhexlify(key)
            iv_bytes = binascii.unhexlify(iv)

            # Asegurarse de que key y iv tengan la longitud correcta
            if len(key_bytes) != 32:
                return render_template('index.html', result='La llave debe tener 32 bytes (256 bits).', key=key, iv=iv, data=data, current_year=datetime.now().year)
            if len(iv_bytes) != 16:
                return render_template('index.html', result='El IV debe tener 16 bytes (128 bits).', key=key, iv=iv, data=data, current_year=datetime.now().year)

            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

            if action == 'encrypt':
                if data_type == 'text':
                    data_bytes = data.encode('utf-8')
                else:
                    data_bytes = binascii.unhexlify(data)

                if padding == 'yes':
                    data_bytes = pad(data_bytes, AES.block_size)

                encrypted_bytes = cipher.encrypt(data_bytes)
                result = binascii.hexlify(encrypted_bytes).decode('utf-8')

            elif action == 'decrypt':
                encrypted_bytes = binascii.unhexlify(data)
                decrypted_bytes = cipher.decrypt(encrypted_bytes)

                if padding == 'yes':
                    decrypted_bytes = unpad(decrypted_bytes, AES.block_size)

                if data_type == 'text':
                    result = decrypted_bytes.decode('utf-8', errors='ignore')
                else:
                    result = binascii.hexlify(decrypted_bytes).decode('utf-8')

        except Exception as e:
            result = f'Error: {str(e)}'

        return render_template('index.html', result=result, key=key, iv=iv, data=data, current_year=datetime.now().year)

    else:
        # Prellenar valores por defecto
        return render_template('index.html', key=key_default, iv=iv_default, data=data_default, current_year=datetime.now().year)

@app.route('/reset_iv', methods=['POST'])
def reset_iv():
    new_iv = binascii.hexlify(os.urandom(16)).decode('utf-8')
    return jsonify({'iv': new_iv})

if __name__ == '__main__':
    app.run(debug=True)