from flask import Flask, request, jsonify, render_template, send_file
import json
import hashlib
import time
import os
from web3 import Web3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Initialize Flask app
app = Flask(__name__)

# Create a directory to store certificates locally
os.makedirs('certificates', exist_ok=True)
# Also create a directory for PDF certificates
os.makedirs('certificate_pdfs', exist_ok=True)

# Connect to Ganache with error handling
try:
    w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
    if not w3.is_connected():
        print("WARNING: Failed to connect to Ganache. Is it running?")
except Exception as e:
    print(f"Error connecting to Ganache: {e}")
    w3 = None

# Replace IPFS functions with local file storage
def store_certificate(certificate_data, certificate_hash):
    """Store certificate data in a local JSON file"""
    try:
        file_path = os.path.join('certificates', f"{certificate_hash}.json")
        with open(file_path, 'w') as f:
            json.dump(certificate_data, f, indent=4)
        return f"local-storage:{certificate_hash}"
    except Exception as e:
        print(f"Error storing certificate: {e}")
        raise

def retrieve_certificate(storage_id):
    """Retrieve certificate data from local storage"""
    if not storage_id or not isinstance(storage_id, str) or not storage_id.startswith("local-storage:"):
        return None
    
    certificate_hash = storage_id.replace("local-storage:", "")
    file_path = os.path.join('certificates', f"{certificate_hash}.json")
    
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"Certificate not found: {certificate_hash}")
        return None
    except json.JSONDecodeError:
        print(f"Invalid JSON in certificate file: {certificate_hash}")
        return None
    except Exception as e:
        print(f"Error retrieving certificate: {e}")
        return None

# Helper function to generate a PDF certificate
def generate_certificate_pdf(certificate_data, certificate_hash):
    """Generate a PDF version of the certificate"""
    try:
        from fpdf import FPDF
        
        # Extract certificate details
        cert_data = certificate_data.get('certificateData', {})
        student_id = certificate_data.get('studentId', 'Unknown')
        name = cert_data.get('name', 'Unknown')
        course = cert_data.get('course', 'Unknown')
        grade = cert_data.get('grade', 'Unknown')
        institution = cert_data.get('institution', 'Unknown')
        issue_date = cert_data.get('issueDate', 0)
        
        # Convert timestamp to readable date
        from datetime import datetime
        date_str = datetime.fromtimestamp(issue_date).strftime('%B %d, %Y')
        
        # Create PDF
        pdf = FPDF()
        pdf.add_page()
        
        # Add certificate border
        pdf.set_draw_color(0, 0, 0)
        pdf.set_line_width(1)
        pdf.rect(10, 10, 190, 277)
        
        # Add title
        pdf.set_font('Arial', 'B', 24)
        pdf.cell(0, 30, 'Certificate of Completion', 0, 1, 'C')
        
        # Add logo or institution name
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 20, institution, 0, 1, 'C')
        
        # Add content
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 20, f'This is to certify that', 0, 1, 'C')
        
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 15, name, 0, 1, 'C')
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 15, f'Student ID: {student_id}', 0, 1, 'C')
        pdf.cell(0, 15, f'has successfully completed the course', 0, 1, 'C')
        
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 15, course, 0, 1, 'C')
        
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 15, f'with a grade of {grade}', 0, 1, 'C')
        
        # Add date
        pdf.cell(0, 20, f'Issued on: {date_str}', 0, 1, 'C')
        
        # Add certificate hash for verification
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 15, f'Certificate Hash: {certificate_hash}', 0, 1, 'C')
        pdf.cell(0, 10, 'Verify at: https://your-verification-url.com', 0, 1, 'C')
        
        # Save PDF
        pdf_path = os.path.join('certificate_pdfs', f"{certificate_hash}.pdf")
        pdf.output(pdf_path)
        
        return pdf_path
    except ImportError:
        print("FPDF library not installed. Cannot generate PDF certificate.")
        return None
    except Exception as e:
        print(f"Error generating PDF certificate: {e}")
        return None

# Define contract ABI manually to avoid dependency on build artifacts
CONTRACT_ABI = [
    {
        "inputs": [],
        "stateMutability": "nonpayable",
        "type": "constructor"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "bytes32",
                "name": "certificateHash",
                "type": "bytes32"
            },
            {
                "indexed": False,
                "internalType": "string",
                "name": "ipfsHash",
                "type": "string"
            },
            {
                "indexed": False,
                "internalType": "address",
                "name": "issuer",
                "type": "address"
            }
        ],
        "name": "CertificateIssued",
        "type": "event"
    },
    {
        "anonymous": False,
        "inputs": [
            {
                "indexed": True,
                "internalType": "bytes32",
                "name": "certificateHash",
                "type": "bytes32"
            }
        ],
        "name": "CertificateRevoked",
        "type": "event"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "name": "authorizedIssuers",
        "outputs": [
            {
                "internalType": "bool",
                "name": "",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "",
                "type": "bytes32"
            }
        ],
        "name": "certificates",
        "outputs": [
            {
                "internalType": "string",
                "name": "ipfsHash",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "issueDate",
                "type": "uint256"
            },
            {
                "internalType": "address",
                "name": "issuer",
                "type": "address"
            },
            {
                "internalType": "bool",
                "name": "isRevoked",
                "type": "bool"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "certificateHash",
                "type": "bytes32"
            },
            {
                "internalType": "string",
                "name": "ipfsHash",
                "type": "string"
            }
        ],
        "name": "issueCertificate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "owner",
        "outputs": [
            {
                "internalType": "address",
                "name": "",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "certificateHash",
                "type": "bytes32"
            }
        ],
        "name": "revokeCertificate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "address",
                "name": "issuer",
                "type": "address"
            },
            {
                "internalType": "bool",
                "name": "status",
                "type": "bool"
            }
        ],
        "name": "setIssuerStatus",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {
                "internalType": "bytes32",
                "name": "certificateHash",
                "type": "bytes32"
            }
        ],
        "name": "verifyCertificate",
        "outputs": [
            {
                "internalType": "bool",
                "name": "exists",
                "type": "bool"
            },
            {
                "internalType": "bool",
                "name": "isValid",
                "type": "bool"
            },
            {
                "internalType": "string",
                "name": "ipfsHash",
                "type": "string"
            },
            {
                "internalType": "uint256",
                "name": "issueDate",
                "type": "uint256"
            },
            {
                "internalType": "address",
                "name": "issuer",
                "type": "address"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# Set contract address with better error handling
CONTRACT_ADDRESS = os.environ.get('CONTRACT_ADDRESS')
if not CONTRACT_ADDRESS:
    CONTRACT_ADDRESS = '0x3A8f5207368d4732DEF941c4d51B70D05c6E7d23'  # Default address
    print(f"Using default contract address: {CONTRACT_ADDRESS}")

# Initialize contract with error handling
try:
    if w3 and w3.is_connected():
        # Check if the address is valid
        if Web3.is_address(CONTRACT_ADDRESS):
            contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
            print("Contract successfully initialized")
        else:
            print(f"Invalid contract address format: {CONTRACT_ADDRESS}")
            contract = None
    else:
        contract = None
        print("Web3 not connected, contract initialization skipped")
except Exception as e:
    print(f"Error initializing contract: {e}")
    contract = None

# ZKP Implementation - For demonstration purposes, we're using a simplified approach
# In a production system, you would use zkSNARKs or zkSTARKs libraries
class ZKProof:
    def __init__(self):
        try:
            # Generate keys for the institution
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
        except Exception as e:
            print(f"Error initializing ZKProof: {e}")
            raise
    
    def generate_certificate_hash(self, student_id, certificate_data):
        """Generate a hash of student ID and certificate data"""
        if not student_id or not certificate_data:
            raise ValueError("Student ID and certificate data are required")
            
        try:
            combined_data = f"{student_id}:{json.dumps(certificate_data, sort_keys=True)}"
            return Web3.keccak(text=combined_data).hex()
        except Exception as e:
            print(f"Error generating certificate hash: {e}")
            raise
    
    def sign_certificate(self, certificate_hash):
        """Sign the certificate hash with the institution's private key"""
        if not certificate_hash:
            raise ValueError("Certificate hash is required")
            
        try:
            signature = self.private_key.sign(
                certificate_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return signature.hex()
        except Exception as e:
            print(f"Error signing certificate: {e}")
            raise
    
    def verify_signature(self, certificate_hash, signature):
        """Verify the signature without revealing the certificate data"""
        if not certificate_hash or not signature:
            return False
            
        try:
            self.public_key.verify(
                bytes.fromhex(signature),
                certificate_hash.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            print(f"Signature verification failed: {e}")
            return False
    
    def get_public_key_pem(self):
        """Export public key in PEM format"""
        try:
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        except Exception as e:
            print(f"Error exporting public key: {e}")
            raise

# Initialize ZKP system
try:
    zkp = ZKProof()
    print("ZKProof system initialized successfully")
except Exception as e:
    print(f"Failed to initialize ZKProof system: {e}")
    zkp = None

@app.route('/')
def index():
    """Render the main page"""
    return render_template('index.html')

@app.route('/generate_certificate', methods=['POST'])
def generate_certificate():
    """Generate a new certificate and store it locally and on blockchain"""
    # Check if required services are initialized
    if not w3 or not w3.is_connected():
        return jsonify({
            'success': False,
            'message': 'Blockchain connection not available. Check if Ganache is running.'
        }), 503
        
    if not contract:
        return jsonify({
            'success': False,
            'message': 'Smart contract not properly initialized'
        }), 503
        
    if not zkp:
        return jsonify({
            'success': False,
            'message': 'ZKP system not properly initialized'
        }), 503
    
    try:
        data = request.json
        if not data:
            return jsonify({
                'success': False,
                'message': 'No data provided'
            }), 400
            
        # Validate required fields
        required_fields = ['student_id', 'name', 'course', 'grade', 'institution']
        missing_fields = [field for field in required_fields if field not in data or not data.get(field)]
        
        if missing_fields:
            return jsonify({
                'success': False,
                'message': f'Missing required fields: {", ".join(missing_fields)}'
            }), 400
        
        student_id = data.get('student_id')
        certificate_data = {
            'name': data.get('name'),
            'course': data.get('course'),
            'grade': data.get('grade'),
            'issueDate': int(time.time()),
            'institution': data.get('institution')
        }
        
        # Generate certificate hash using ZKP
        certificate_hash = zkp.generate_certificate_hash(student_id, certificate_data)
        
        # Sign the certificate
        signature = zkp.sign_certificate(certificate_hash)
        
        # Prepare complete certificate
        complete_certificate = {
            'studentId': student_id,
            'certificateData': certificate_data,
            'certificateHash': certificate_hash,
            'signature': signature,
            'publicKey': zkp.get_public_key_pem()
        }
        
        # Store locally instead of IPFS
        storage_id = store_certificate(complete_certificate, certificate_hash)
        
        # Generate PDF certificate
        pdf_path = generate_certificate_pdf(complete_certificate, certificate_hash)
        
        # Check if we have accounts available
        accounts = w3.eth.accounts
        if not accounts:
            return jsonify({
                'success': False,
                'message': 'No blockchain accounts available. Check Ganache configuration.'
            }), 503
            
        issuer_account = accounts[0]  # Using the first account for simplicity
        
        # Build and send transaction with error handling
        try:
            # Ensure the certificate hash is properly formatted for the blockchain
            cert_hash_bytes = Web3.to_bytes(hexstr=certificate_hash)
            
            # Check gas estimation first (this will fail early if there are issues)
            gas_estimate = contract.functions.issueCertificate(
                cert_hash_bytes,
                storage_id
            ).estimate_gas({'from': issuer_account})
            
            # Add a buffer to gas estimate
            gas_with_buffer = int(gas_estimate * 1.2)
            
            # Now send the transaction
            tx_hash = contract.functions.issueCertificate(
                cert_hash_bytes,
                storage_id
            ).transact({'from': issuer_account, 'gas': gas_with_buffer})
            
            # Wait for transaction receipt with timeout
            tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            
            return jsonify({
                'success': True,
                'certificateHash': certificate_hash,
                'storageId': storage_id,
                'txHash': tx_receipt.transactionHash.hex(),
                'downloadUrl': f'/download_certificate/{certificate_hash}',
                'downloadPdfUrl': f'/download_certificate_pdf/{certificate_hash}',
                'message': 'Certificate issued successfully. You can download it using the provided links.'
            })
        except Exception as e:
            print(f"Blockchain transaction error: {e}")
            # Try to clean up the locally stored certificate if blockchain transaction fails
            try:
                os.remove(os.path.join('certificates', f"{certificate_hash}.json"))
                if pdf_path:
                    os.remove(pdf_path)
            except:
                pass
                
            return jsonify({
                'success': False,
                'message': f'Error during blockchain transaction: {str(e)}'
            }), 500
    
    except Exception as e:
        print(f"Certificate generation error: {e}")
        return jsonify({
            'success': False,
            'message': f'Error generating certificate: {str(e)}'
        }), 500

@app.route('/download_certificate/<certificate_hash>', methods=['GET'])
def download_certificate(certificate_hash):
    """Download the certificate in JSON format"""
    try:
        # Construct the storage ID
        storage_id = f"local-storage:{certificate_hash}"
        
        # Retrieve certificate
        certificate = retrieve_certificate(storage_id)
        
        if not certificate:
            return jsonify({
                'success': False,
                'message': 'Certificate not found'
            }), 404
        
        # Create a temporary file to download
        temp_file_path = os.path.join('certificates', f"{certificate_hash}.json")
        
        # Check if the file exists
        if not os.path.exists(temp_file_path):
            return jsonify({
                'success': False,
                'message': 'Certificate file not found'
            }), 404
        
        # Return the file for download
        return send_file(
            temp_file_path,
            as_attachment=True,
            download_name=f"certificate_{certificate_hash[:8]}.json",
            mimetype='application/json'
        )
    
    except Exception as e:
        print(f"Certificate download error: {e}")
        return jsonify({
            'success': False,
            'message': f'Error downloading certificate: {str(e)}'
        }), 500

@app.route('/download_certificate_pdf/<certificate_hash>', methods=['GET'])
def download_certificate_pdf(certificate_hash):
    """Download the certificate in PDF format"""
    try:
        # Check if PDF exists
        pdf_path = os.path.join('certificate_pdfs', f"{certificate_hash}.pdf")
        
        if not os.path.exists(pdf_path):
            # Construct the storage ID
            storage_id = f"local-storage:{certificate_hash}"
            
            # Retrieve certificate
            certificate = retrieve_certificate(storage_id)
            
            if not certificate:
                return jsonify({
                    'success': False,
                    'message': 'Certificate not found'
                }), 404
            
            # Generate PDF on-the-fly if it doesn't exist
            pdf_path = generate_certificate_pdf(certificate, certificate_hash)
            
            if not pdf_path or not os.path.exists(pdf_path):
                return jsonify({
                    'success': False,
                    'message': 'Failed to generate PDF certificate'
                }), 500
        
        # Return the PDF file for download
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=f"certificate_{certificate_hash[:8]}.pdf",
            mimetype='application/pdf'
        )
    
    except Exception as e:
        print(f"PDF certificate download error: {e}")
        return jsonify({
            'success': False,
            'message': f'Error downloading PDF certificate: {str(e)}'
        }), 500

@app.route('/verify_certificate', methods=['POST'])
def verify_certificate():
    """Verify a certificate using its hash without revealing student data"""
    # Check if required services are initialized
    if not w3 or not w3.is_connected() or not contract:
        return jsonify({
            'success': False,
            'message': 'Blockchain connection or contract not available'
        }), 503
    
    try:
        data = request.json
        if not data or 'certificateHash' not in data:
            return jsonify({
                'success': False,
                'message': 'Certificate hash is required'
            }), 400
            
        certificate_hash = data.get('certificateHash')
        if not certificate_hash:
            return jsonify({
                'success': False,
                'message': 'Invalid certificate hash'
            }), 400
        
        # Convert hex string to bytes for blockchain query
        try:
            cert_hash_bytes = Web3.to_bytes(hexstr=certificate_hash)
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Invalid certificate hash format: {str(e)}'
            }), 400
        
        # Check blockchain for certificate existence
        try:
            exists, is_valid, storage_id, issue_date, issuer = contract.functions.verifyCertificate(
                cert_hash_bytes
            ).call()
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Blockchain verification error: {str(e)}'
            }), 500
        
        if not exists:
            return jsonify({
                'success': False,
                'message': 'Certificate does not exist on the blockchain'
            })
        
        if not is_valid:
            return jsonify({
                'success': False,
                'message': 'Certificate has been revoked'
            })
        
        # Retrieve from local storage instead of IPFS
        certificate = retrieve_certificate(storage_id)
        
        if not certificate:
            return jsonify({
                'success': False,
                'message': 'Certificate data not found in storage'
            })
        
        # Verify signature
        try:
            signature_valid = zkp.verify_signature(certificate_hash, certificate.get('signature', ''))
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Error verifying signature: {str(e)}'
            }), 500
        
        if not signature_valid:
            return jsonify({
                'success': False,
                'message': 'Certificate signature is invalid'
            })
        
        # Return minimal information for verification (ZKP principles)
        cert_data = certificate.get('certificateData', {})
        return jsonify({
            'success': True,
            'isValid': True,
            'issueDate': issue_date,
            'institution': cert_data.get('institution', 'Unknown'),
            'course': cert_data.get('course', 'Unknown'),
            'downloadUrl': f'/download_certificate/{certificate_hash}',
            'downloadPdfUrl': f'/download_certificate_pdf/{certificate_hash}'
            # Note: We're not returning student's personal data
        })
    
    except Exception as e:
        print(f"Certificate verification error: {e}")
        return jsonify({
            'success': False,
            'message': f'Error verifying certificate: {str(e)}'
        }), 500

@app.route('/verify_by_student_id', methods=['POST'])
def verify_by_student_id():
    """Verify certificate by student ID (ZKP implementation)"""
    try:
        data = request.json
        if not data or 'student_id' not in data or 'course' not in data:
            return jsonify({
                'success': False,
                'message': 'Student ID and course are required'
            }), 400
            
        student_id = data.get('student_id')
        course = data.get('course')
        
        if not student_id or not course:
            return jsonify({
                'success': False,
                'message': 'Invalid student ID or course'
            }), 400
        
        # The verifier creates a ZKP request
        # In a real system, this would involve more complex ZKP protocols
        verification_request = {
            'studentId': student_id,
            'course': course,
            'timestamp': int(time.time())
        }
        
        verification_id = hashlib.sha256(json.dumps(verification_request).encode()).hexdigest()
        
        return jsonify({
            'success': True,
            'message': 'Verification request created successfully',
            'verificationId': verification_id
        })
    
    except Exception as e:
        print(f"Student verification error: {e}")
        return jsonify({
            'success': False,
            'message': f'Error processing verification: {str(e)}'
        }), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for the application"""
    status = {
        'service': 'Certificate Service',
        'status': 'up',
        'timestamp': int(time.time()),
        'blockchain_connected': False,
        'contract_initialized': contract is not None,
        'zkp_initialized': zkp is not None
    }
    
    if w3:
        try:
            status['blockchain_connected'] = w3.is_connected()
            if status['blockchain_connected']:
                status['blockchain_node'] = 'Ganache'
                status['latest_block'] = w3.eth.block_number
        except:
            status['blockchain_connected'] = False
    
    return jsonify(status)

if __name__ == '__main__':
    # Print startup information
    print(f"Starting Certificate Service...")
    print(f"Blockchain connection: {'OK' if w3 and w3.is_connected() else 'FAILED'}")
    print(f"Contract initialized: {'OK' if contract else 'FAILED'}")
    print(f"ZKP system: {'OK' if zkp else 'FAILED'}")
    print(f"Certificate storage directory: {os.path.abspath('certificates')}")
    print(f"PDF certificate storage directory: {os.path.abspath('certificate_pdfs')}")
    
    app.run(debug=True)