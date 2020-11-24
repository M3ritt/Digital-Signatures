from flask import Flask, request, render_template, jsonify
import signatures

app = Flask(__name__)


@app.route('/')
def homepage():
    return render_template("homepage.html")


@app.route('/about_us')
def about_us():
    return render_template("about_us.html")


@app.route('/digital_signature')
def digital_signature():
    return render_template("digital_signature.html")


@app.route('/example')
def example():
    return render_template('demo.html')


@app.route('/process', methods=['POST'])
def process():
    """
        Behind the scenes of the demonstration page. This updates the page using AJAX.

        This process calls from signatures.py and gets;
            - public key
            - private key
            - original hash of data
            - new hash of data
            - whether the signatures are matching or not

        One can view the code/comments in signatures.py if one wants to know the more about the listed variables.
    """
    try:
        original_input = request.form['original_input']
        new_input = request.form['new_input']
        bit_size = request.form['first_bit_size']
    except KeyError:
        return jsonify({'error': '[Error] Incorrect Key.'})

    if new_input and original_input:
        if bit_size == '':
            bit_size = 1024

        elif not signatures.bit_size_checking(bit_size):
            return jsonify({'error': '[Error] Incorrect type. Try an integer that is a multiple of 1024.'})

        public_key, private_key, original_hash, hashed, valid, signature = signatures.demonstration(original_input,
                                                                                                    new_input,
                                                                                                    int(bit_size))

        return jsonify(
            {'first_bit_size': bit_size, 'publicKey': public_key, 'privateKey': private_key,
             'originalSignature': str(original_hash), 'newSignature': str(hashed),
             'name': str(signature) + " and is: " + str(valid)}
        )

    else:
        return jsonify({'error': '[Error] Missing data.'})


@app.route('/time_difference')
def time_difference():
    return render_template("time_difference.html")


@app.route('/time_process', methods=['POST'])
def time_process():
    """
        Behind the scenes of the time difference page. This updates the page using AJAX.

        This process calls from signatures.py and gets;
            - times it took for each bit size
            - time difference
            - whether the signatures are matching or not
    """
    try:
        first_bit_size = request.form['first_bit_size']
        second_bit_size = request.form['second_bit_size']
        original_input = request.form['original_input']
        new_input = request.form['new_input']
    except KeyError:
        return jsonify({'error': '[Error] Incorrect Key.'})

    if not signatures.bit_size_checking(first_bit_size) or not signatures.bit_size_checking(second_bit_size):
        return jsonify({'error': '[Error] Incorrect type. Try an integer that is a multiple of 1024.'})

    elif first_bit_size and second_bit_size and new_input and original_input:
        difference_in_time, valid, first_run_time, second_run_time = signatures.time_difference(int(first_bit_size),
                                                                                                int(second_bit_size),
                                                                                                original_input,
                                                                                                new_input)

        first_run_time = float(first_run_time)
        first_run_time = str(first_run_time)

        second_run_time = float(second_run_time)
        second_run_time = str(second_run_time)

        first_run = first_bit_size + " with a time of: " + first_run_time
        second_run = second_bit_size + " with a time of: " + second_run_time

        return jsonify(
            {'first_bit_size': str(first_run), 'second_bit_size': str(second_run),
             'difference': str(difference_in_time) + " seconds", 'name': str(valid), }
        )

    else:
        return jsonify({'error': '[Error] Missing data.'})


if __name__ == '__main__':
    app.run(debug=True)
