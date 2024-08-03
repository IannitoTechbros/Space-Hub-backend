from config import *
from flask_cors import CORS
from models import User, Space, Booking
from config import bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename
from flask import send_from_directory, request, jsonify, make_response
import os
import requests
from requests.auth import HTTPBasicAuth
import base64
from datetime import datetime

CORS(app, resources={r"/*": {"origins": ["http://localhost:3000"]}})

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    new_user = User(
        name=data['name'], 
        email=data['email'], 
        password=hashed_password,
    )
    db.session.add(new_user)
    db.session.commit()
    return make_response(jsonify({'message': 'User created successfully'}), 201)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return make_response(jsonify({'message': 'Email and password are required'}))

    user = User.query.filter_by(email=data['email']).first()
    if not user or not bcrypt.check_password_hash(user.password, data['password']):
        return make_response(jsonify({'message': 'Invalid email or password'}), 401)

    access_token = create_access_token(identity={'id': user.id, 'role': user.role}) 
    return make_response(jsonify(access_token=access_token, user=user.to_dict()), 200)

@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/users/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_user(id):
    user = User.query.get(id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    return jsonify({'message': 'User not found'}), 404

@app.route('/spaces', methods=['GET'])
# @jwt_required()
def get_spaces():
    spaces = Space.query.all()
    return jsonify([{
        'id': space.id,
        'name': space.name,
        'location': space.location,
        'capacity': space.capacity,
        'amenities': space.amenities,
        'ratecard': space.ratecard,
        'image': space.image,
        'isBooked': space.booked
    } for space in spaces])

@app.route('/spaces/<int:id>', methods=['GET'])
@jwt_required()
def get_space(id):
    space = db.session.get(Space, id)
    if space:
        return jsonify({
            'id': space.id,
            'name': space.name,
            'location': space.location,
            'capacity': space.capacity,
            'amenities': space.amenities,
            'ratecard': space.ratecard,
            'image': space.image,
            'isBooked': space.booked
        })
    return jsonify({'message': 'Space not found'}), 404

@app.route('/spaces', methods=['POST'])
@jwt_required()
def create_space():
    if 'image' not in request.files:
        return jsonify({'message': 'No image file part'}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({'message': 'No selected file'}), 400
    
    if not (request.form.get('name') and request.form.get('location')):
        return jsonify({'message': 'Missing required fields'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    file.save(file_path)

    data = request.form
    new_space = Space(
        name=data.get('name'),
        location=data.get('location'),
        capacity=data.get('capacity'),
        amenities=data.get('amenities'),
        ratecard=data.get('ratecard'),
        image=f"/uploads/{filename}"  
    )
    db.session.add(new_space)
    db.session.commit()

    return jsonify({'message': 'Space created successfully'}), 201

@app.route('/spaces/<int:id>', methods=['PUT'])
@jwt_required()
def update_space(id):
    data = request.get_json()
    space = db.session.get(Space, id)
    if space:
        space.name = data.get('name', space.name)
        space.location = data.get('location', space.location)
        space.capacity = data.get('capacity', space.capacity)
        space.amenities = data.get('amenities', space.amenities)
        space.ratecard = data.get('ratecard', space.ratecard)
        space.image = data.get('image', space.image)
        space.booked = data.get('booked', space.booked)  
        db.session.commit()
        return jsonify({'message': 'Space updated successfully'})
    return jsonify({'message': 'Space not found'}), 404

@app.route('/spaces/<int:id>', methods=['DELETE'])
@jwt_required()
def delete_space(id):
    space = db.session.get(Space, id)
    if space:
        db.session.delete(space)
        db.session.commit()
        return jsonify({'message': 'Space deleted successfully'})
    return jsonify({'message': 'Space not found'}), 404

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

def get_access_token():
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(url, auth=HTTPBasicAuth(app.config['MPESA_CONSUMER_KEY'], app.config['MPESA_CONSUMER_SECRET']))
    
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        print(f"Failed to get access token: {response.status_code}, {response.text}")
        return None

def get_password():
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    data_to_encode = app.config['MPESA_BUSINESS_SHORT_CODE'] + app.config['MPESA_PASS_KEY'] + timestamp
    return base64.b64encode(data_to_encode.encode()).decode('utf-8')

def format_phone_number(number):
    if number.startswith('0'):
        return f'254{number[1:]}'
    elif number.startswith('254'):
        return number
    else:
        raise ValueError("Invalid phone number format")

@app.route('/spaces/<int:id>/book', methods=['POST'])
@jwt_required()
def book_space(id):
    data = request.get_json()
    space = db.session.get(Space, id)
    if not space:
        return jsonify({'message': 'Space not found'}), 404

    if space.booked:
        return jsonify({'message': 'Space is already booked'}), 400

    user_id = get_jwt_identity()['id']
    hours = float(data.get('hours'))
    total_amount = hours * space.ratecard
    phone_number = data.get('phone_number')
    
    try:
        formatted_phone_number = format_phone_number(phone_number)
    except ValueError:
        return jsonify({'message': 'Invalid phone number format'}), 400

    # Initiate M-Pesa payment
    access_token = get_access_token()
    if access_token:
        print(f"Retrieved access token: {access_token}")
    else:
        return jsonify({'message': 'Failed to get access token for payment. Please try again.'}), 500

    password = get_password()
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')

    payload = {
        "BusinessShortCode": app.config['MPESA_BUSINESS_SHORT_CODE'],
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": app.config['MPESA_TRANSACTION_TYPE'],
        "Amount": int(total_amount),  # Ensure this is a valid integer
        "PartyA": formatted_phone_number,
        "PartyB": app.config['MPESA_BUSINESS_SHORT_CODE'],
        "PhoneNumber": formatted_phone_number,
        "CallBackURL": app.config['MPESA_CALLBACK_URL'],
        "AccountReference": f"Space Booking {id}",
        "TransactionDesc": f"Payment for Space {id}"
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    print("Payload:", payload)  # Debug: Print the payload

    response = requests.post(
        "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
        json=payload,
        headers=headers
    )

    if response.status_code == 200:
        # Save booking details
        booking = Booking(user_id=user_id, space_id=id, hours=hours, total_amount=total_amount)
        db.session.add(booking)
        db.session.commit()
        print(f"Formatted Phone Number for Payment: {formatted_phone_number}")
        return jsonify({'message': 'Payment initiated. Please check your phone to complete the transaction.', 'bookingId': booking.id}), 200
    else:
        print(f"Formatted Phone Number for Payment: {formatted_phone_number}")
        print(f"Failed to initiate payment: {response.status_code}, {response.text}")
        return jsonify({'message': 'Failed to initiate payment. Please try again.'}), 400

@app.route('/mpesa-callback', methods=['POST'])
def mpesa_callback():
    data = request.get_json()
    app.logger.info(f"Callback data received: {data}")

    result_code = data['Body']['stkCallback']['ResultCode']
    merchant_request_id = data['Body']['stkCallback']['MerchantRequestID']
    checkout_request_id = data['Body']['stkCallback']['CheckoutRequestID']
    
    if result_code == 0:  # Successful payment
        mpesa_receipt_number = data['Body']['stkCallback']['CallbackMetadata']['Item'][1]['Value']
        
        # Update the booking status
        booking = Booking.query.filter_by(id=merchant_request_id).first()
        if booking:
            booking.payment_status = 'completed'
            booking.mpesa_receipt_number = mpesa_receipt_number
            db.session.commit()
            app.logger.info(f"Payment successful for booking ID {merchant_request_id}")
    
    return jsonify({'message': 'Callback received'}), 200


@app.route('/booking/<int:booking_id>/status', methods=['GET'])
@jwt_required()
def check_booking_status(booking_id):
    booking = Booking.query.get(booking_id)
    if not booking:
        return jsonify({'message': 'Booking not found'}), 404
    
    return jsonify({'status': booking.payment_status}), 200

if __name__ == '__main__':
    app.run(debug=True)
