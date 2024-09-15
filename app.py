from flask import Flask, render_template, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import base64
import os
from datetime import datetime

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    # Inicializar variables de resultado
    result_hex = result_text = result_base64 = ''
    error = ''
    key_default = ('E45CAEC8F1F2DEC1DD1E9BE1C9CB548C'
                   '636BEED4C32AD48B39E7E105AA061759')
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
            key_bytes = binascii.unhexlify(key)
            iv_bytes = binascii.unhexlify(iv)

            if len(key_bytes) != 32:
                error = 'La llave debe tener 32 bytes (256 bits).'
            elif len(iv_bytes) != 16:
                error = 'El IV debe tener 16 bytes (128 bits).'
            else:
                cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)

                if action == 'encrypt':
                    if data_type == 'text':
                        data_bytes = data.encode('utf-8')
                    else:
                        data_bytes = binascii.unhexlify(data)

                    if padding == 'yes':
                        data_bytes = pad(data_bytes, AES.block_size)
                    elif len(data_bytes) % AES.block_size != 0:
                        error = 'El texto debe ser múltiplo de 16 bytes cuando no se usa padding.'

                    if not error:
                        encrypted_bytes = cipher.encrypt(data_bytes)
                        result_hex = binascii.hexlify(encrypted_bytes).decode('utf-8')
                        result_base64 = base64.b64encode(encrypted_bytes).decode('utf-8')
                        result_text = ''  # El texto cifrado no es legible como ASCII
                elif action == 'decrypt':
                    if data_type == 'text':
                        encrypted_bytes = data.encode('utf-8')
                    else:
                        encrypted_bytes = binascii.unhexlify(data)

                    if len(encrypted_bytes) % AES.block_size != 0:
                        error = 'El texto cifrado debe ser múltiplo de 16 bytes.'
                    else:
                        decrypted_bytes = cipher.decrypt(encrypted_bytes)

                        if padding == 'yes':
                            decrypted_bytes = unpad(decrypted_bytes, AES.block_size)
                        result_hex = binascii.hexlify(decrypted_bytes).decode('utf-8')
                        result_base64 = base64.b64encode(decrypted_bytes).decode('utf-8')
                        result_text = decrypted_bytes.decode('utf-8', errors='replace')
        except Exception as e:
            error = f'Error: {str(e)}'

        # Renderizar el template con todas las variables necesarias
        return render_template('index.html', error=error,
                               result_hex=result_hex,
                               result_text=result_text,
                               result_base64=result_base64,
                               key=key, iv=iv, data=data,
                               action=action, data_type=data_type, padding=padding,
                               current_year=datetime.now().year)
    else:
        # Renderizar el template con valores por defecto y variables de resultado vacías
        return render_template('index.html', error=error,
                               result_hex=result_hex,
                               result_text=result_text,
                               result_base64=result_base64,
                               key=key_default, iv=iv_default,
                               data=data_default,
                               action='encrypt', data_type='text', padding='yes',
                               current_year=datetime.now().year)

@app.route('/reset_iv', methods=['POST'])
def reset_iv():
    new_iv = binascii.hexlify(os.urandom(16)).decode('utf-8')
    return jsonify({'iv': new_iv})

if __name__ == '__main__':
    app.run(debug=True)